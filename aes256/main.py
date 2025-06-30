from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os

app = FastAPI()

# Generate a persistent AES-256 key for demo (store securely in real apps)
KEY = os.urandom(32)  # 32 bytes = 256-bit
IV = os.urandom(16)   # 16 bytes for AES block size

class Message(BaseModel):
    data: str

def encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()  # prepend IV for decoding

def decrypt(encoded_ciphertext: str, key: bytes) -> str:
    try:
        data = base64.b64decode(encoded_ciphertext)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid data or key.")

@app.post("/encrypt")
def encrypt_message(message: Message):
    ciphertext = encrypt(message.data, KEY, IV)
    return {"encrypted": ciphertext}

@app.post("/decrypt")
def decrypt_message(message: Message):
    decrypted = decrypt(message.data, KEY)
    return {"decrypted": decrypted}
