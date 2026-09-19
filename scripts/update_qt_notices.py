"""Refresh the checked-in Qt notices when updating the pinned Qt version.

Fetch attribution and licence texts from the exact upstream tag. Builds themselves
remain offline with respect to notices; they consume docs/licenses/Qt-NOTICES.txt.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path, PurePosixPath
import posixpath

import requests

VERSION = "6.11.2"


def fetch(url):
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.text


def main():
    sections = [f"Qt {VERSION} third-party attributions\n\n"
                "This inventory includes optional components from Qt Base and Qt SVG.\n"
                "Not every component is used on every platform. Original upstream texts follow.\n"]
    for module in ("qtbase", "qtsvg"):
        base = f"https://raw.githubusercontent.com/qt/{module}/v{VERSION}/"
        tree = json.loads(fetch(f"https://api.github.com/repos/qt/{module}/git/trees/v{VERSION}?recursive=1"))
        paths = sorted(p["path"] for p in tree["tree"] if p["path"].startswith("src/") and p["path"].endswith("qt_attribution.json"))
        with ThreadPoolExecutor(max_workers=8) as executor:
            records = list(executor.map(lambda p: fetch(base + p), paths))
        licences = set()
        for path, content in zip(paths, records):
            # A few upstream descriptions contain literal newlines inside strings.
            entries = json.loads(content, strict=False)
            entries = entries if isinstance(entries, list) else [entries]
            sections.append(f"\n--- {module}/{path} ---\n{content}\n")
            for entry in entries:
                names = entry.get("LicenseFile", [])
                for name in ([names] if isinstance(names, str) else names):
                    licences.add(posixpath.normpath(str(PurePosixPath(path).parent / name)))
                if not names and entry.get("LicenseId"):
                    candidate = f"LICENSES/{entry['LicenseId']}.txt"
                    if any(p["path"] == candidate for p in tree["tree"]):
                        licences.add(candidate)
        with ThreadPoolExecutor(max_workers=8) as executor:
            texts = list(executor.map(lambda p: fetch(base + p), sorted(licences)))
        for path, content in zip(sorted(licences), texts):
            sections.append(f"\n--- {base}{path} ---\n{content}\n")
    output = Path(__file__).resolve().parents[1] / "docs/licenses/Qt-NOTICES.txt"
    output.write_text("\n".join(sections), encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
