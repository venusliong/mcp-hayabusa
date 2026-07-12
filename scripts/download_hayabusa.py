#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/."""

import io
import json
import os
import platform
import stat
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile

REPO = "Yamato-Security/hayabusa"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
DEST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hayabusa")


def detect_platform_keywords():
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        os_keys = ["lin"]
    elif system == "darwin":
        os_keys = ["mac", "darwin"]
    elif system == "windows":
        os_keys = ["win"]
    else:
        raise RuntimeError(f"Unsupported OS: {platform.system()}")

    if machine in ("x86_64", "amd64"):
        arch_keys = ["x64", "amd64", "x86_64", "intel"]
    elif machine in ("aarch64", "arm64"):
        arch_keys = ["aarch64", "arm64"]
    else:
        raise RuntimeError(f"Unsupported architecture: {platform.machine()}")

    return os_keys, arch_keys


def fetch_latest_release():
    req = urllib.request.Request(
        API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mcp-hayabusa-installer",
        },
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub API request failed: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach GitHub API: {e.reason}") from e


def pick_asset(assets, os_keys, arch_keys):
    def matches(name, keys):
        return any(k in name for k in keys)

    candidates = [a for a in assets if matches(a["name"].lower(), os_keys)]
    exact = [a for a in candidates if matches(a["name"].lower(), arch_keys)]
    if exact:
        # Prefer musl builds: they're statically linked, so they run on any
        # glibc version instead of requiring a glibc >= the build host's.
        musl = [a for a in exact if "musl" in a["name"].lower()]
        return (musl or exact)[0]

    fallback = [a for a in assets if "all-platform" in a["name"].lower()]
    if fallback:
        return fallback[0]

    return None


def download(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "mcp-hayabusa-installer"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def extract(data, asset_name, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(dest_dir)
    elif asset_name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(dest_dir)
    else:
        raise RuntimeError(f"Don't know how to extract asset: {asset_name}")


def find_binary(dest_dir):
    for root, _dirs, files in os.walk(dest_dir):
        for name in files:
            lower = name.lower()
            if lower == "hayabusa" or lower == "hayabusa.exe" or lower.startswith("hayabusa-"):
                return os.path.join(root, name)
    return None


def main():
    os_keys, arch_keys = detect_platform_keywords()
    print(f"Detected platform keywords: os={os_keys} arch={arch_keys}")

    print(f"Fetching latest release info from {API_URL} ...")
    release = fetch_latest_release()
    tag = release.get("tag_name", "unknown")
    assets = release.get("assets", [])
    if not assets:
        print("Latest release has no downloadable assets.", file=sys.stderr)
        return 1

    asset = pick_asset(assets, os_keys, arch_keys)
    if asset is None:
        print("Could not find a matching asset for this platform. Available assets:", file=sys.stderr)
        for a in assets:
            print(f"  - {a['name']}", file=sys.stderr)
        return 1

    print(f"Selected asset: {asset['name']} (release {tag})")
    print("Downloading ...")
    data = download(asset["browser_download_url"])

    print(f"Extracting to {DEST_DIR} ...")
    extract(data, asset["name"], DEST_DIR)

    binary = find_binary(DEST_DIR)
    if binary is None:
        print(f"Extraction complete, but no hayabusa binary was found under {DEST_DIR}.", file=sys.stderr)
        return 1

    if not binary.endswith(".exe"):
        st = os.stat(binary)
        os.chmod(binary, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Done. Hayabusa {tag} binary is at: {binary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
