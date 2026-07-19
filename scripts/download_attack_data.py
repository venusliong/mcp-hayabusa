#!/usr/bin/env python3
"""Download the MITRE ATT&CK Enterprise STIX bundle to ./attack/enterprise-attack.json."""

import os
import sys
import urllib.error
import urllib.request

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
DEST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attack")
DEST_PATH = os.path.join(DEST_DIR, "enterprise-attack.json")


def main():
    print(f"Downloading {URL} ...")
    req = urllib.request.Request(URL, headers={"User-Agent": "mcp-hayabusa-installer"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        print(f"Download failed: {e.code} {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Could not reach {URL}: {e.reason}", file=sys.stderr)
        return 1

    os.makedirs(DEST_DIR, exist_ok=True)
    with open(DEST_PATH, "wb") as f:
        f.write(data)

    print(f"Done. ATT&CK Enterprise data ({len(data) / 1_000_000:.1f} MB) is at: {DEST_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
