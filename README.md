# CryptoGuard — Cryptography Workbench

**A Flask-based web application for cryptographic algorithm demonstrations and secure file encryption.**

## Overview

CryptoGuard is an educational cybersecurity project that brings multiple cryptographic algorithms together in a single web dashboard. It allows users to explore encryption, decryption, hashing, and file protection through a simple interface.

## Features

- **AES-256-GCM:** Authenticated message encryption and decryption.
- **RSA-2048:** Public-key and private-key generation with OAEP-based encryption and decryption for short messages.
- **SHA-256:** Generate cryptographic hashes to demonstrate data integrity.
- **Caesar Cipher:** Explore classical text encryption and decryption.
- **File Vault:** Encrypt and decrypt files using password-based AES-GCM encryption.
- **Web Dashboard:** A dark cybersecurity-themed interface built with Flask.

## Technologies Used

- Python
- Flask
- Python `cryptography` library
- HTML5 and CSS3
- JavaScript
- Git and GitHub

## Installation and Setup

1. Clone or download this repository.
2. Open the project folder in a terminal.
3. Create and activate a virtual environment.

```bash
python -m venv .venv
```

On Windows:

```powershell
.venv\Scripts\activate
```

4. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

5. Start the application:

```bash
python app.py
```

6. Open `http://127.0.0.1:5000` in your browser.

## Project Modules

| Module | Purpose |
|---|---|
| AES-256-GCM | Authenticated symmetric encryption |
| RSA-2048 | Public-key encryption for short messages |
| SHA-256 | One-way hashing and integrity comparison |
| Caesar Cipher | Classical cipher demonstration |
| File Vault | Password-based file encryption and decryption |

## Educational Purpose

This project demonstrates cryptographic concepts and their practical use in a web application. SHA-256 is a hashing algorithm, not an encryption algorithm, and Caesar Cipher is not suitable for protecting sensitive information.

## Security Notice

CryptoGuard is an educational prototype and has not been independently security-audited. Do not use it as the sole protection for sensitive files. Keep passwords and private keys out of public repositories.

## Author

**D. Sanjana**  
Roll Number: 25R15A6203

B.Tech — Cyber Security

## License

This project is intended for academic and educational purposes.
