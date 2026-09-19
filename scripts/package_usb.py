"""Archive USB apps with regular files so FAT/exFAT do not need symlink support."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        with tempfile.TemporaryDirectory(prefix="discovr-usb-") as temporary:
            folder = Path(temporary) / "Discovr"
            folder.mkdir()
            app = folder / "Discovr.app"
            # The single-executable app bundle has no framework/resource symlinks,
            # so it can be copied onto common flash-drive filesystems unchanged.
            shutil.copytree("dist/Discovr.app", app, symlinks=False)
            shutil.copy2("docs/USB-START.txt", folder / "START HERE.txt")
            shutil.copy2("build/THIRD_PARTY_NOTICES.txt", folder / "THIRD_PARTY_NOTICES.txt")
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", str(app)], check=True)
            subprocess.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                            str(folder), str(output)], check=True)
    else:
        folder = Path("dist/Discovr").resolve()
        shutil.copy2("docs/USB-START.txt", folder / "START HERE.txt")
        shutil.copy2("build/THIRD_PARTY_NOTICES.txt", folder / "THIRD_PARTY_NOTICES.txt")
        if sys.platform.startswith("linux"):
            with tarfile.open(output, "w:gz", dereference=True) as archive:
                archive.add(folder, arcname="Discovr")
        else:
            shutil.make_archive(str(output.with_suffix("")), "zip", folder.parent, folder.name)
    print(output)


if __name__ == "__main__":
    main()
