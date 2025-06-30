# aes256

Encryption and decryption related codes

# 🔐 AES-256 Encryption API with FastAPI

This project provides a simple REST API for AES-256 encryption and decryption using the `cryptography` and `FastAPI` libraries.

The encryption is performed in **AES-256 CBC mode** with PKCS7 padding, and the ciphertext is returned as a base64-encoded string (with the IV prepended for decryption).

---

## 📦 Features

- AES-256 encryption (256-bit key, 32 bytes)
- AES CBC mode with PKCS7 padding
- FastAPI endpoints for encrypting and decrypting messages
- Base64 output for easy transport over HTTP

---

## 🛠️ Requirements

- Python 3.10+
- `fastapi`
- `uvicorn`
- `cryptography`

![Graph](https://github.com/DavitGadyan/encryption/blob/main/aes256/aes256_encryption.png)

Install dependencies:

```bash
pip install fastapi uvicorn cryptography
```
