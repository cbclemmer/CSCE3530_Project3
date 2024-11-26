import os
import re
from typing import List
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from lib import init_bytes_file, bytes_to_ansi_quoted_string

AES_KEY_FILE="aes_key.bin"
AES_SALT_FILE="aes_salt.bin"
AES_PWD="VERY_SECURE_PASSWORD"

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

generate_aes_key()