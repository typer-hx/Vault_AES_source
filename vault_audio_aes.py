#!/usr/bin/env python3
###############################################################################
# QUICK SETUP ON A NEW COMPUTER
#   1) Check Python ≥3.8  →  python --version
#   2) First-time install →  python -m pip install -r requirements.txt
#      (or let the script auto-install when prompted)
#   3) Run a command      →  python vault_audio_aes.py  unlock  file.vault  out
#
# Tested OK with cryptography 40-45.  Script uses only stable primitives
# (AESGCM + PBKDF2HMAC), so newer versions should keep working.
###############################################################################

"""
vault_audio_aes.py – lock / unlock *any* file with AES-256-GCM.
"""

import base64, json, os, sys, time, getpass, argparse
from hashlib import sha256

# ───────────────────────────────────────────────────────────────────────────────
# Ensure the external dependency “cryptography” is present.
# Offers an optional interactive auto-installer if it’s missing.
# ───────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError:
    import subprocess

    print("\n[!] Required package 'cryptography' is not installed.")
    print("    You have two choices:")
    print("      1  →  Let this script install it for you now.")
    print("      2  →  Quit; I’ll show the pip command so you can run it later.\n")

    choice = input("Enter 1 or 2 and press <Enter>: ").strip()

    if choice == "1":
        cmd = [sys.executable, "-m", "pip", "install",
               "cryptography>=42.0,<100.0"]
        print("\n▶ Running:", " ".join(cmd), "\n")
        try:
            subprocess.check_call(cmd)
            print("\n✓ cryptography installed successfully.")
            print("⟳ Restarting the script...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)  # type: ignore[arg-type]
        except Exception as err:
            sys.exit(f"\nInstallation failed: {err}\n"
                     "Please run the command manually:\n"
                     "  python -m pip install 'cryptography>=42.0,<100.0'\n")
    else:
        sys.exit("\nOkay, exiting. Manually install with:\n"
                 "  python -m pip install 'cryptography>=42.0,<100.0'\n")

# ───────────────────────────────────────────────────────────────────────────────
MAGIC  = b"VAESv1"
ROUNDS = 200_000

# ---------- low-level ----------------------------------------------------------
def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm   = hashes.SHA256(),
        length      = 32,
        salt        = salt,
        iterations  = ROUNDS,
    )
    return kdf.derive(passphrase.encode())

def _aes_encrypt(raw: bytes, pwd: str) -> bytes:
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    key   = _derive_key(pwd, salt)
    ct    = AESGCM(key).encrypt(nonce, raw, None)
    return salt + nonce + ct                     # 16-byte salt + 12-byte nonce

def _aes_decrypt(blob: bytes, pwd: str) -> bytes:
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = _derive_key(pwd, salt)
    return AESGCM(key).decrypt(nonce, ct, None)

# ---------- header helpers -----------------------------------------------------
def _header(name: str) -> bytes:
    meta = {"orig": name, "ts": time.time(), "alg": "AES-256-GCM"}
    b    = json.dumps(meta).encode()
    return MAGIC + len(b).to_bytes(4, "big") + b

def _split(full: bytes):
    if not full.startswith(MAGIC):
        raise ValueError("Not a vault file")
    l    = int.from_bytes(full[6:10], "big")
    meta = json.loads(full[10:10+l])
    return meta, full[10+l:]

# ---------- user-facing ops ----------------------------------------------------
def lock(src: str, dst: str, pwd: str) -> None:
    with open(src, "rb") as f:
        raw = f.read()
    blob = (
        _header(os.path.basename(src))
        + sha256(raw).digest()
        + _aes_encrypt(raw, pwd)
    )
    with open(dst, "wb") as f:
        f.write(blob)
    print("🔒  Locked  →", dst)

def unlock(src: str, dst: str, pwd: str) -> None:
    meta, rest = _split(open(src, "rb").read())
    h, enc = rest[:32], rest[32:]
    try:
        raw = _aes_decrypt(enc, pwd)
    except Exception:
        print("❌  Wrong password")
        return
    if sha256(raw).digest() != h:
        print("❌  File damaged or corrupted")
        return
    with open(dst, "wb") as f:
        f.write(raw)
    print("🔓  Unlocked →", dst)

def repass(path: str) -> None:
    old = getpass.getpass("Old pass: ")
    tmp = path + ".tmp"
    unlock(path, tmp, old)
    if not os.path.exists(tmp):
        return
    new = getpass.getpass("New pass: ")
    lock(tmp, path, new)
    os.remove(tmp)
    print("🔑  Password changed")

# ---------- CLI wrapper --------------------------------------------------------
def cli() -> None:
    P   = argparse.ArgumentParser(prog="vault", description="AES-256 file vault")
    sub = P.add_subparsers(dest="cmd", required=True)

    L = sub.add_parser("lock",   help="Encrypt a file into a .vault")
    L.add_argument("src")
    L.add_argument("dst")
    L.add_argument("--wipe", action="store_true",
                   help="delete original after locking")

    U = sub.add_parser("unlock", help="Decrypt a .vault file")
    U.add_argument("src")
    U.add_argument("dst")

    R = sub.add_parser("repass", help="Change password of a .vault")
    R.add_argument("src")

    args = P.parse_args()

    if args.cmd == "lock":
        pwd = getpass.getpass("Pass: ")
        lock(args.src, args.dst, pwd)
        if args.wipe and input("Delete original file? (y/N) ").lower() == "y":
            os.remove(args.src)
            print("🗑️  Original file deleted.")
    elif args.cmd == "unlock":
        pwd = getpass.getpass("Pass: ")
        unlock(args.src, args.dst, pwd)
    elif args.cmd == "repass":
        repass(args.src)

# ---------- main guard ---------------------------------------------------------
if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            argparse.ArgumentParser(description=__doc__).print_help()
        else:
            cli()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
