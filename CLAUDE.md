# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository is currently empty (pre-implementation). This file documents the intended purpose and design so that work can start consistently. Update this file as real structure, commands, and conventions are established.

## Purpose

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) — a Windows event log (EVTX) analysis tool — to expose EVTX scanning as a tool callable by MCP clients (e.g. Claude Code, Claude Desktop).

## Goals

- Expose a `scan_evtx` MCP tool that runs the Hayabusa CLI against EVTX file(s) or a directory of EVTX files.
- Return Hayabusa's results as structured JSON (not raw CLI/CSV/table output) to the MCP client.
- Support filtering results by severity level (e.g. critical/high/medium/low/informational), likely by passing Hayabusa's own severity flags and/or post-filtering the JSON output.
- Handle errors gracefully — e.g. missing/invalid EVTX paths, Hayabusa binary not found or not on PATH, non-zero exit codes, and malformed output — and surface them as clear MCP tool errors rather than crashing the server.

## Stack

- **Language**: Python
- **MCP framework**: the `mcp` Python library (official MCP SDK) for defining the server and tools
- **Hayabusa**: invoked as an external CLI binary that must be installed locally (not bundled) — the server shells out to it (e.g. via `subprocess`) rather than reimplementing EVTX parsing

## Architecture notes for implementation

- Hayabusa is invoked as a subprocess; prefer its JSON/JSONL output modes (e.g. `-J`/`--JSON-timeline` or similar, check `hayabusa --help` for the installed version) over parsing human-readable table output.
- Severity filtering should map to Hayabusa's own `--min-level`/severity flags where possible rather than fetching everything and filtering client-side, to keep scans efficient on large EVTX sets.
- Since Hayabusa is an external dependency installed locally, validate its presence/version at startup or on first tool call, and return an actionable MCP error if it's missing.
- Treat EVTX file paths as untrusted input from the MCP client — validate/sanitize paths before passing them to the subprocess call to avoid command injection.
