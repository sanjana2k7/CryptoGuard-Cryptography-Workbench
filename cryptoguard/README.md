# CryptoGuard — Cryptography Workbench

A Flask-based student project demonstrating AES-256-GCM, RSA-2048 OAEP, SHA-256 hashing, Caesar cipher, and password-based file encryption/decryption. Includes a responsive dark cybersecurity dashboard.

## Features
- **AES-256-GCM:** password-derived key using PBKDF2-HMAC-SHA256 (600,000 iterations), random salt and nonce, authenticated encryption.
- **RSA-2048:** generate PEM keys, encrypt using a public key, decrypt using the private key with OAEP/SHA-256. RSA is for short messages, not large files.
- **SHA-256:** generate a 256-bit digest for integrity demonstrations. Hashes are one-way.
- **Caesar cipher:** shift letters forward/backward; educational only.
- **File Vault:** encrypt/decrypt files up to 25 MB using AES-256-GCM and a password.
- Responsive interface and clear educational warnings.

## Requirements
- Python 3.10 or newer (Python 3.11+ recommended)
- pip

## Run on Windows
1. Extract the ZIP file.
2. Open the extracted `cryptoguard` folder in VS Code, or open Command Prompt in that folder.
3. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
4. Install packages:
   ```bat
   python -m pip install -r requirements.txt
   ```
5. Start the application:
   ```bat
   python app.py
   ```
6. Open **http://127.0.0.1:5000** in your browser.

## Suggested demo sequence
1. Encrypt a message with AES, then decrypt it with the same password.
2. Generate an RSA key pair, encrypt using the public key, then decrypt using the private key.
3. Hash a sentence, change one character, and hash again to compare digests.
4. Encrypt a sample file, then decrypt the downloaded `.cg` file using the same password.
5. Demonstrate Caesar encryption and decryption with shift 3.

## GitHub upload
Upload `app.py`, `templates/`, `static/`, `requirements.txt`, and `README.md`. Do **not** upload real private keys, secrets, virtual environments, or sensitive files. A `.gitignore` is included.

## Important limitations
This is an educational prototype, not a security-audited product. Do not use it as the only copy of important files. Keep backups and test decryption before removing originals. The demo-generated RSA private key is unencrypted; store it securely. For a production application, add authentication, CSRF protection, HTTPS, stronger operational controls, and a reviewed file format.
