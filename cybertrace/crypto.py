import hashlib
from cryptography.fernet import Fernet
from flask import current_app

def _fernet():
    return Fernet(current_app.config["FERNET_KEY"].encode())

def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)

def decrypt_bytes(data: bytes) -> bytes:
    return _fernet().decrypt(data)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()