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
            app = Path(temporary) / "Discovr.app"
            shutil.copytree("dist/Discovr.app", app, symlinks=False)
            # Replacing symlinks changes bundle resources. Rebuild the ad-hoc seal;
            # this is integrity signing, not a trusted Developer ID or notarisation.
            subprocess.run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", str(app)], check=True)
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", str(app)], check=True)
            subprocess.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                            str(app), str(output)], check=True)
    else:
        folder = Path("dist/Discovr").resolve()
        shutil.copy2("docs/USB-START.txt", folder / "START HERE.txt")
        shutil.copy2("build/THIRD_PARTY_NOTICES.txt", folder / "THIRD_PARTY_NOTICES.txt")
        if sys.platform.startswith("linux"):
            launcher = folder / "Discovr.desktop"
            # %k supplies this desktop file's relocated path as a separate argument.
            # Escape both desktop-entry string parsing and Exec argument quoting.
            command = 'exec "$(/usr/bin/dirname -- "$1")/Discovr"'
            quoted = ''.join('\\' + c if c in '\\"$`' else c for c in command).replace('\\', '\\\\')
            launcher.write_text('[Desktop Entry]\nType=Application\nName=Discovr\n'
                                f'Comment=Portable asset discovery\nExec=/bin/sh -c "{quoted}" discovr %k\n'
                                'Terminal=false\nCategories=Utility;Network;\n', encoding="utf-8")
            launcher.chmod(0o755)
            with tarfile.open(output, "w:gz", dereference=True) as archive:
                archive.add(folder, arcname="Discovr")
        else:
            shutil.make_archive(str(output.with_suffix("")), "zip", folder.parent, folder.name)
    print(output)


if __name__ == "__main__":
    main()
