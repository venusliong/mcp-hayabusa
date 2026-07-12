#!/usr/bin/env python3
"""MCP server that wraps Hayabusa for EVTX analysis."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")


@mcp.tool()
def scan_evtx(
    path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan EVTX file(s) with Hayabusa and return structured results.

    Args:
        path: Path to an EVTX file or a directory of EVTX files.
        min_severity: Optional minimum severity to include
            (e.g. "critical", "high", "medium", "low", "informational").
        rule_filter: Only include findings whose rule title contains this
            string (case-insensitive substring match, e.g. "lateral" or "mimikatz").
        output_format: "summary" (default) for condensed fields, or "full"
            for the complete Hayabusa finding.
        max_results: Optional limit on the number of findings returned.
    """
    raise NotImplementedError("scan_evtx is not implemented yet")


@mcp.tool()
def get_hayabusa_rules(
    keyword: str | None = None,
    min_severity: str | None = None,
    max_results: int | None = None,
) -> dict:
    """List Hayabusa detection rules, optionally filtered by keyword and/or severity.

    Args:
        keyword: Only include rules whose title, description, tags, or ID
            contain this string (case-insensitive substring match).
        min_severity: Optional minimum severity to include
            (e.g. "critical", "high", "medium", "low", "informational").
        max_results: Optional limit on the number of rules returned.
    """
    raise NotImplementedError("get_hayabusa_rules is not implemented yet")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
