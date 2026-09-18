"""Collect licence texts from the exact installed distributions used for a build."""
from importlib.metadata import distribution
from pathlib import Path
import re
import sys


def collect_notices(root):
    root = Path(root)
    packages = re.findall(r"^([a-zA-Z0-9_.-]+)==", (root / "requirements.lock").read_text(), re.M)
    sections = ["Discovr third-party notices\n\n"
                "These components retain their respective licences. Package release pages below\n"
                "link to upstream source distributions and project repositories.\n"]
    for name in sorted(set(packages + ["pyinstaller"])):
        dist = distribution(name)
        heading = f"{dist.metadata['Name']} {dist.version}"
        sections.append(f"\n{'=' * 72}\n{heading}\nhttps://pypi.org/project/{name}/{dist.version}/\n")
        for path in dist.files or []:
            if re.match(r"(?i)(licen[cs]e|copying|notice)(\.|$)", path.name):
                resolved = Path(dist.locate_file(path))
                if resolved.is_file():
                    sections.append(f"\n--- {path.name} ---\n{resolved.read_text(encoding='utf-8', errors='replace')}\n")
        sections.append(f"Licence metadata: {dist.metadata.get('License-Expression') or dist.metadata.get('License') or 'See upstream release'}\n")
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if python_license.is_file():
        sections.append("\nPython runtime\n" + python_license.read_text(encoding="utf-8", errors="replace"))
    output = root / "build" / "THIRD_PARTY_NOTICES.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(sections), encoding="utf-8")
    return output


if __name__ == "__main__":
    print(collect_notices(Path(__file__).resolve().parents[1]))
