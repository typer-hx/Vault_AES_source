# Vault_AES_source

Vault_AES_source is a student-friendly file locker combining a simple GUI with AES-256-GCM encryption for quick, secure file and folder protection.

## Features

- Encrypt and decrypt single files or entire folders  
- AES-256-GCM with SHA-256 and PBKDF2HMAC key derivation  
- Change password support for existing `.vault` files  
- Auto-installer for the `cryptography` package  

## Prerequisites

- Python 3.8 or newer  
- (Optional) `requirements.txt` listing `cryptography`; the script can auto-install missing packages on first run  

## Installation

1. Clone or download this repository.  
2. Install dependencies (once):
    ```bash
    python -m pip install -r requirements.txt
    ```
    ## Usage

### GUI Mode

```bash
python vault_gui.py
```
1. Choose Lock, Unlock, or Change Password

2. Browse to your file or folder

3. Enter password (and new password if changing)

4. Click Go and watch the status message

### CLI Mode

```bash
python vault_audio_aes.py lock   <src> <dst> [--wipe]
python vault_audio_aes.py unlock <src> <dst>
python vault_audio_aes.py repass <src>

-Use --wipe to delete the original file after locking
-Passwords entered securely at the prompt
```

## Repository Structure

```plaintext
Vault_AES_source/
├─ vault_gui.py         # GUI front-end
└─ vault_audio_aes.py   # AES-256-GCM logic and CLI

```
## License

Released under the Student-First Non-Commercial License (SF-NC) v1.0.  
- Students: free to use, modify, and share  
- Non-commercial use: attribution required  
- Commercial use: strictly prohibited  

See [LICENSE](LICENSE) for full terms.

## Contributing & Support

Questions, bug reports, or feature ideas? Open an issue or pull request.  
Let’s make Vault_AES_source even better for students everywhere!
