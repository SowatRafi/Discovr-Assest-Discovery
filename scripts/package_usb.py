"""Archive USB apps with regular files so FAT/exFAT do not need symlink support."""
import argparse
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
import tarfile
import tempfile


def copy_guides(folder):
    """Keep first-use help beside the launcher, so reading it needs no internet."""
    for name in ("USER_GUIDE.md", "REQUIREMENTS.md", "API.md"):
        shutil.copy2(Path("docs") / name, folder / name)
    samples = folder / "demo"
    samples.mkdir(exist_ok=True)
    for name in ("demo.png", "demo.csv", "demo.json"):
        shutil.copy2(Path("docs/demo") / name, samples / name)


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
            contents = app / "Contents"
            macos = contents / "MacOS"
            macos.mkdir(parents=True)
            # Keep the ordinary frozen folder under Resources. Frameworks requires
            # symbolic links and rejects distribution metadata as nested code bundles.
            shutil.copytree("dist/Discovr", contents / "Resources/runtime", symlinks=False)
            with (contents / "Info.plist").open("wb") as output_plist:
                plistlib.dump({"CFBundleName": "Discovr", "CFBundleExecutable": "Discovr",
                               "CFBundleIdentifier": "org.discovr.desktop", "CFBundlePackageType": "APPL",
                               "CFBundleShortVersionString": "2.1.0", "CFBundleVersion": "2.1.0",
                               "LSUIElement": False, "NSHighResolutionCapable": True,
                               "LSMinimumSystemVersion": "14.0" if platform.machine() == "arm64" else "15.0"},
                              output_plist)
            subprocess.run(["/usr/bin/clang", "-fobjc-arc", "-framework", "Cocoa",
                            "scripts/macos_launcher.m", "-o", str(macos / "Discovr")], check=True)
            # Runtime Mach-O files already carry PyInstaller's ad-hoc signatures.
            # Seal the native launcher and its resources without re-signing nested data.
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(app)], check=True)
            shutil.copy2("docs/USB-START.txt", folder / "START HERE.txt")
            copy_guides(folder)
            shutil.copy2("build/THIRD_PARTY_NOTICES.txt", folder / "THIRD_PARTY_NOTICES.txt")
            subprocess.run(["/usr/bin/codesign", "--verify", str(app)], check=True)
            subprocess.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                            str(folder), str(output)], check=True)
    else:
        folder = Path("dist/Discovr").resolve()
        shutil.copy2("docs/USB-START.txt", folder / "START HERE.txt")
        copy_guides(folder)
        shutil.copy2("build/THIRD_PARTY_NOTICES.txt", folder / "THIRD_PARTY_NOTICES.txt")
        if sys.platform.startswith("linux"):
            with tarfile.open(output, "w:gz", dereference=True) as archive:
                archive.add(folder, arcname="Discovr")
        else:
            shutil.make_archive(str(output.with_suffix("")), "zip", folder.parent, folder.name)
    print(output)


if __name__ == "__main__":
    main()
