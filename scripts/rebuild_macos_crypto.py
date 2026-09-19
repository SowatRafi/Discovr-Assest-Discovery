"""Build cryptography with static OpenSSL before packaging on Intel macOS.

The Intel runner builds cryptography from source. Its Homebrew OpenSSL and Python's
OpenSSL have the same dylib names but different symbols; PyInstaller otherwise
collapses them into one incompatible library. Static linkage avoids that collision.
"""
import importlib.util
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


def main():
    if sys.platform != "darwin" or platform.machine() != "x86_64":
        return
    root = Path(__file__).resolve().parents[1]
    lock = (root / "requirements.lock").read_text(encoding="utf-8")
    requirement = re.search(r"(?m)^cryptography==[^\n]*(?:\n[ \t]+[^\n]*)*", lock)
    if not requirement or "--hash=sha256:" not in requirement[0]:
        raise RuntimeError("No hash-locked cryptography requirement found")
    openssl = subprocess.check_output(["brew", "--prefix", "openssl@3"], text=True).strip()
    environment = dict(os.environ, OPENSSL_DIR=openssl, OPENSSL_STATIC="1")
    with tempfile.TemporaryDirectory(prefix="discovr-crypto-") as temporary:
        path = Path(temporary) / "cryptography.txt"
        path.write_text(requirement[0] + "\n", encoding="utf-8")
        # Bypass cached dynamically linked wheels; preserve the lock's source hash.
        subprocess.run([sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps",
                        "--no-cache-dir", "--no-binary=cryptography", "--require-hashes", "-r", str(path)],
                       env=environment, check=True)
    native = importlib.util.find_spec("cryptography.hazmat.bindings._rust").origin
    links = subprocess.check_output(["otool", "-L", native], text=True)
    if "libssl" in links or "libcrypto" in links:
        raise RuntimeError(f"cryptography still links dynamic OpenSSL:\n{links}")
    print("Verified static OpenSSL linkage for Intel macOS cryptography")


if __name__ == "__main__":
    main()
