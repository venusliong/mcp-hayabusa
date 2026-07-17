#!/usr/bin/env python3
"""MCP server that wraps Hayabusa for EVTX analysis (low-level API)."""

import asyncio
import json
import re
import subprocess
import tempfile
from pathlib import Path

import mcp.server.stdio
import mcp.types as types
import yaml
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.models import InitializationOptions
from pydantic import AnyUrl

try:
    from yaml import CSafeLoader as YamlLoader
except ImportError:
    from yaml import SafeLoader as YamlLoader

server = Server("hayabusa")

REPO_ROOT = Path(__file__).resolve().parent
HAYABUSA_DIR = REPO_ROOT / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"
DETECTION_RULES_DIR = REPO_ROOT / "rules"

ATTACK_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
SCAN_TIMEOUT_SECONDS = 600

OUTPUT_FORMATS = ["summary", "full"]

SCAN_EVTX_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "minLength": 1,
            "description": "Path to an EVTX file or a directory of EVTX files.",
        },
        "min_severity": {
            "type": ["string", "null"],
            "enum": [*SEVERITY_LEVELS, None],
            "description": (
                "Optional minimum severity to include "
                "(e.g. \"critical\", \"high\", \"medium\", \"low\", \"informational\")."
            ),
        },
        "rule_filter": {
            "type": ["string", "null"],
            "description": (
                "Only include findings whose rule title contains this string "
                "(case-insensitive substring match, e.g. \"lateral\" or \"mimikatz\")."
            ),
        },
        "output_format": {
            "type": "string",
            "enum": OUTPUT_FORMATS,
            "default": "summary",
            "description": (
                "\"summary\" (default) returns condensed fields per finding "
                "(timestamp, rule, level, computer, event ID). "
                "\"full\" returns the complete Hayabusa finding, including Details/ExtraFieldInfo."
            ),
        },
        "max_results": {
            "type": ["integer", "null"],
            "minimum": 1,
            "description": "Optional limit on the number of findings returned.",
        },
    },
    "required": ["path"],
}

GET_HAYABUSA_RULES_SCHEMA = {
    "type": "object",
    "properties": {
        "keyword": {
            "type": ["string", "null"],
            "description": (
                "Only include rules whose title, description, tags, or ID contain this string "
                "(case-insensitive substring match, e.g. \"lateral\" or \"mimikatz\")."
            ),
        },
        "min_severity": {
            "type": ["string", "null"],
            "enum": [*SEVERITY_LEVELS, None],
            "description": (
                "Optional minimum severity to include "
                "(e.g. \"critical\", \"high\", \"medium\", \"low\", \"informational\")."
            ),
        },
        "max_results": {
            "type": ["integer", "null"],
            "minimum": 1,
            "description": "Optional limit on the number of rules returned.",
        },
    },
    "required": [],
}


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_evtx",
            description="Scan EVTX file(s) with Hayabusa and return structured results.",
            inputSchema=SCAN_EVTX_SCHEMA,
        ),
        types.Tool(
            name="get_hayabusa_rules",
            description=(
                "List Hayabusa detection rules (title, ID, severity, description, tags), "
                "optionally filtered by keyword and/or minimum severity. "
                "Useful for discovering what rules exist before running scan_evtx."
            ),
            inputSchema=GET_HAYABUSA_RULES_SCHEMA,
        ),
    ]


def _severity_rank(level: str) -> int:
    try:
        return SEVERITY_LEVELS.index(level.lower())
    except ValueError:
        return -1


def _summarize_finding(finding: dict) -> dict:
    return {
        "Timestamp": finding.get("Timestamp"),
        "RuleTitle": finding.get("RuleTitle"),
        "Level": finding.get("Level"),
        "Computer": finding.get("Computer"),
        "Channel": finding.get("Channel"),
        "EventID": finding.get("EventID"),
        "RecordID": finding.get("RecordID"),
        "RuleID": finding.get("RuleID"),
    }


def scan_evtx(
    path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Run Hayabusa against an EVTX file/directory and return structured findings."""
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"EVTX path not found: {path}")

    if not HAYABUSA_BIN.is_file():
        raise FileNotFoundError(
            f"Hayabusa binary not found at {HAYABUSA_BIN}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    if min_severity is not None:
        min_severity = min_severity.lower()
        if min_severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid min_severity {min_severity!r}. Must be one of: {', '.join(SEVERITY_LEVELS)}"
            )

    if output_format not in OUTPUT_FORMATS:
        raise ValueError(
            f"Invalid output_format {output_format!r}. Must be one of: {', '.join(OUTPUT_FORMATS)}"
        )

    if max_results is not None and max_results < 1:
        raise ValueError(f"max_results must be a positive integer, got {max_results!r}")

    with tempfile.TemporaryDirectory(prefix="hayabusa-scan-") as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        input_flag = "-d" if target.is_dir() else "-f"

        cmd = [
            str(HAYABUSA_BIN), "json-timeline",
            input_flag, str(target),
            "-o", str(output_path),
            "-w",  # no-wizard: never block waiting on interactive prompts
            "-q",  # quiet: suppress the launch banner
            "-K",  # no-color: keep captured stdout/stderr clean
            "-C",  # clobber: overwrite the output file if it exists
            "-b",  # disable-abbreviations: full severity words (e.g. "medium" not "med")
            "-L",  # JSONL output: one finding per line, easy to stream-parse
            "-m", min_severity or "informational",
        ]

        try:
            proc = subprocess.run(
                cmd,
                cwd=HAYABUSA_DIR,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Could not execute Hayabusa binary at {HAYABUSA_BIN}: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise TimeoutError(f"Hayabusa scan timed out after {e.timeout}s") from e

        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "no output captured"
            raise RuntimeError(f"Hayabusa exited with code {proc.returncode}: {detail}")

        if not output_path.exists():
            detail = proc.stderr.strip() or proc.stdout.strip() or "no output captured"
            raise RuntimeError(f"Hayabusa did not produce an output file: {detail}")

        findings = []
        for line in output_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if min_severity:
        min_rank = _severity_rank(min_severity)
        findings = [f for f in findings if _severity_rank(str(f.get("Level", ""))) >= min_rank]

    if rule_filter:
        needle = rule_filter.lower()
        findings = [f for f in findings if needle in str(f.get("RuleTitle", "")).lower()]

    total_findings = len(findings)
    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [_summarize_finding(f) for f in findings]

    return {
        "path": str(target),
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "total_findings": total_findings,
        "returned_findings": len(findings),
        "findings": findings,
    }


_rules_cache: list[dict] | None = None


def _load_all_rules() -> list[dict]:
    """Parse every Hayabusa/Sigma rule YAML under RULES_DIR, caching the result."""
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    if not RULES_DIR.is_dir():
        raise FileNotFoundError(
            f"Hayabusa rules directory not found at {RULES_DIR}. "
            "Run scripts/download_hayabusa.py to install rules."
        )

    rules = []
    for rule_path in RULES_DIR.rglob("*.yml"):
        if ".git" in rule_path.parts or "config" in rule_path.relative_to(RULES_DIR).parts[:-1]:
            continue
        try:
            with rule_path.open() as f:
                data = yaml.load(f, Loader=YamlLoader)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or not data.get("title") or not data.get("id"):
            continue

        logsource = data.get("logsource") or {}
        rules.append({
            "id": data.get("id"),
            "title": data.get("title"),
            "level": str(data.get("level") or "").lower() or None,
            "status": data.get("status"),
            "description": data.get("description"),
            "tags": data.get("tags") or [],
            "ruletype": data.get("ruletype"),
            "logsource_product": logsource.get("product"),
            "logsource_service": logsource.get("service"),
            "logsource_category": logsource.get("category"),
        })

    _rules_cache = rules
    return rules


def get_hayabusa_rules(
    keyword: str | None = None,
    min_severity: str | None = None,
    max_results: int | None = None,
) -> dict:
    """List Hayabusa detection rules, optionally filtered by keyword and/or severity."""
    if min_severity is not None:
        min_severity = min_severity.lower()
        if min_severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid min_severity {min_severity!r}. Must be one of: {', '.join(SEVERITY_LEVELS)}"
            )

    if max_results is not None and max_results < 1:
        raise ValueError(f"max_results must be a positive integer, got {max_results!r}")

    rules = _load_all_rules()

    if min_severity:
        min_rank = _severity_rank(min_severity)
        rules = [r for r in rules if _severity_rank(str(r.get("level") or "")) >= min_rank]

    if keyword:
        needle = keyword.lower()
        rules = [
            r for r in rules
            if needle in str(r.get("title") or "").lower()
            or needle in str(r.get("description") or "").lower()
            or needle in str(r.get("id") or "").lower()
            or any(needle in str(tag).lower() for tag in r.get("tags") or [])
        ]

    rules = sorted(rules, key=lambda r: str(r.get("title") or "").lower())

    total_rules = len(rules)
    if max_results is not None:
        rules = rules[:max_results]

    return {
        "keyword": keyword,
        "min_severity": min_severity,
        "total_rules": total_rules,
        "returned_rules": len(rules),
        "rules": rules,
    }


_detection_rules_cache: list[dict] | None = None


def _load_detection_rules() -> list[dict]:
    """Parse every Sigma rule YAML under DETECTION_RULES_DIR, caching the result."""
    global _detection_rules_cache
    if _detection_rules_cache is not None:
        return _detection_rules_cache

    if not DETECTION_RULES_DIR.is_dir():
        raise FileNotFoundError(
            f"Sigma rules directory not found at {DETECTION_RULES_DIR}."
        )

    rules = []
    for rule_path in sorted(DETECTION_RULES_DIR.glob("*.yml")):
        raw_text = rule_path.read_text()
        try:
            data = yaml.load(raw_text, Loader=YamlLoader)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or not data.get("title") or not data.get("id"):
            continue

        rules.append({
            "rule_name": rule_path.stem,
            "id": data.get("id"),
            "title": data.get("title"),
            "level": str(data.get("level") or "").lower() or None,
            "status": data.get("status"),
            "description": data.get("description"),
            "tags": data.get("tags") or [],
            "logsource": data.get("logsource") or {},
            "raw": raw_text,
        })

    _detection_rules_cache = rules
    return rules


def _technique_ids_from_tags(tags: list) -> set[str]:
    """Extract ATT&CK technique IDs (e.g. 'attack.t1003.001' -> 'T1003.001') from Sigma tags."""
    ids = set()
    for tag in tags:
        match = ATTACK_TECHNIQUE_TAG_RE.match(str(tag))
        if match:
            ids.add(match.group(1).upper())
    return ids


def _rule_summary(rule: dict) -> dict:
    return {
        "rule_name": rule["rule_name"],
        "id": rule["id"],
        "title": rule["title"],
        "level": rule["level"],
        "status": rule["status"],
        "tags": rule["tags"],
        "techniques": sorted(_technique_ids_from_tags(rule["tags"])),
    }


DETECTION_RULES_LIST_URI = "detection://rules"
DETECTION_RULE_URI_PREFIX = "detection://rules/"
DETECTION_RULES_BY_TECHNIQUE_PREFIX = "detection://rules/by-technique/"


def _rule_resource_uri(rule_name: str) -> str:
    return f"{DETECTION_RULE_URI_PREFIX}{rule_name}"


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    resources = [
        types.Resource(
            uri=AnyUrl(DETECTION_RULES_LIST_URI),
            name="All Sigma detection rules",
            description="Summary listing of every Sigma rule under rules/.",
            mimeType="application/json",
        ),
    ]
    for rule in _load_detection_rules():
        resources.append(
            types.Resource(
                uri=AnyUrl(_rule_resource_uri(rule["rule_name"])),
                name=rule["title"],
                description=rule.get("description") or "",
                mimeType="application/yaml",
            )
        )
    return resources


@server.list_resource_templates()
async def list_resource_templates() -> list[types.ResourceTemplate]:
    return [
        types.ResourceTemplate(
            uriTemplate=f"{DETECTION_RULE_URI_PREFIX}{{rule_name}}",
            name="Sigma rule by name",
            description=(
                "Fetch a single Sigma rule's raw YAML content by its filename stem "
                "(rule_name), e.g. detection://rules/proc_creation_win_lsass_dump_procdump."
            ),
            mimeType="application/yaml",
        ),
        types.ResourceTemplate(
            uriTemplate=f"{DETECTION_RULES_BY_TECHNIQUE_PREFIX}{{technique_id}}",
            name="Sigma rules by ATT&CK technique",
            description=(
                "List Sigma rules tagged with the given ATT&CK technique ID, "
                "e.g. detection://rules/by-technique/T1003.001."
            ),
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
    uri_str = str(uri)

    if uri_str == DETECTION_RULES_LIST_URI:
        rules = [_rule_summary(r) for r in _load_detection_rules()]
        payload = {"total_rules": len(rules), "rules": rules}
        return [ReadResourceContents(content=json.dumps(payload, indent=2), mime_type="application/json")]

    if uri_str.startswith(DETECTION_RULES_BY_TECHNIQUE_PREFIX):
        technique_id = uri_str[len(DETECTION_RULES_BY_TECHNIQUE_PREFIX):].strip().upper()
        if not technique_id:
            raise ValueError("Missing technique_id in URI")
        matches = [
            _rule_summary(r)
            for r in _load_detection_rules()
            if technique_id in _technique_ids_from_tags(r["tags"])
        ]
        payload = {"technique_id": technique_id, "total_rules": len(matches), "rules": matches}
        return [ReadResourceContents(content=json.dumps(payload, indent=2), mime_type="application/json")]

    if uri_str.startswith(DETECTION_RULE_URI_PREFIX):
        rule_name = uri_str[len(DETECTION_RULE_URI_PREFIX):].strip()
        if not rule_name:
            raise ValueError("Missing rule_name in URI")
        for rule in _load_detection_rules():
            if rule["rule_name"] == rule_name:
                return [ReadResourceContents(content=rule["raw"], mime_type="application/yaml")]
        raise FileNotFoundError(f"No Sigma rule named {rule_name!r} found under {DETECTION_RULES_DIR}")

    raise ValueError(f"Unknown resource URI: {uri_str}")


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> dict:
    if name == "scan_evtx":
        path = arguments.get("path")
        if not path:
            raise ValueError("Missing required argument: path")
        min_severity = arguments.get("min_severity")
        rule_filter = arguments.get("rule_filter")
        output_format = arguments.get("output_format") or "summary"
        max_results = arguments.get("max_results")

        # Hayabusa is a blocking subprocess call; run it off the event loop thread
        # so the server can keep handling other requests while a scan is in progress.
        return await asyncio.to_thread(
            scan_evtx, path, min_severity, rule_filter, output_format, max_results
        )

    if name == "get_hayabusa_rules":
        keyword = arguments.get("keyword")
        min_severity = arguments.get("min_severity")
        max_results = arguments.get("max_results")
        return await asyncio.to_thread(get_hayabusa_rules, keyword, min_severity, max_results)

    raise ValueError(f"Unknown tool: {name}")


async def run() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="hayabusa",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
