import os
import re
from typing import List
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

AES_KEY_FILE="aes_key.bin"
AES_SALT_FILE="aes_salt.bin"
AES_PWD="VERY_SECURE_PASSWORD"

def init_bytes_file(file_name: str) -> bytes: 
    if os.path.exists(file_name):
        with open(file_name, 'rb') as f:
            return f.read()
    iv = os.urandom(16)
    with open(file_name, 'wb') as f:
        f.write(iv)
    return iv

def bytes_to_ansi_quoted_string(b: bytes) -> str:
    return ''.join([
        f'\\x{byte:02x}'
        for byte in b
    ])

def ansi_quoted_string_to_bytes(s: str) -> bytes:
    matches = re.findall(r'\\x[0-9a-fA-F]{2}', s)
    return bytes([int(match[2:], 16) for match in matches])

def generate_aes_key():
    if os.path.exists(AES_KEY_FILE):
        return
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=init_bytes_file(AES_SALT_FILE),
        iterations=100000,
        backend=default_backend()
    ).derive(AES_PWD.encode())
    key_s = bytes_to_ansi_quoted_string(key)
    with open(AES_KEY_FILE, 'w') as f:
        f.write(key_s)

