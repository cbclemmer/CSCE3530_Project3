import os
import sqlite3
import datetime
from argon2 import PasswordHasher
from uuid import uuid4
from typing import List, Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from lib import init_bytes_file, ansi_quoted_string_to_bytes

AES_IV_FILE="aes_iv.bin"
AES_ENV_VAR="NOT_MY_KEY"

KEY_TABLE_DECLARATION = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

USER_TABLE_DECLARATION = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)
"""

AUTH_LOG_TABLE_DECLARATION = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""

def get_iv_data():
    return init_bytes_file(AES_IV_FILE)

def get_aes_key() -> bytes: 
    key = os.environ.get(AES_ENV_VAR)
    if key is None:
        raise Exception(f"environment variable {AES_ENV_VAR} not set")
    return ansi_quoted_string_to_bytes(key)

def get_cipher() -> Cipher:
    key = get_aes_key()
    iv = get_iv_data()
    return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

def aes_decrypt(ciphertext: bytes) -> bytes:
    decryptor = get_cipher().decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(decrypted_text) + unpadder.finalize()

def aes_encrypt(data: bytes) -> bytes:
    encryptor = get_cipher().encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

password_hasher = PasswordHasher()
connection = sqlite3.connect('totally_not_my_privateKeys.db')

def create_key():
    return generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def create_tables():
    cursor = connection.cursor()
    cursor.execute(KEY_TABLE_DECLARATION)
    cursor.execute(USER_TABLE_DECLARATION)
    cursor.execute(AUTH_LOG_TABLE_DECLARATION)

# Converts a private key object to a PEM encoded string
def make_pem(key: RSAPrivateKey):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def get_padding():
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

def save_user(username: str, email: str) -> str:
    cursor = connection.cursor()
    password = str(uuid4())
    hashed_password = password_hasher.hash(password)
    cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashed_password, email))
    connection.commit()
    return password

def authenticate_user(username: str, password: str) -> int | None:
    cursor = connection.cursor()
    q = cursor.execute(f"SELECT id, password_hash FROM users WHERE username='{username}'")
    user = q.fetchone()
    if user is None:
        return None
    
    try:
        password_hasher.verify(user[1], password)
    except:
        return None

    return user[0]

def encrypt_key(key: RSAPrivateKey) -> bytes:
    pem = make_pem(key)
    return aes_encrypt(pem)

# Save the private key to the database
def save_private_key(key: RSAPrivateKey, expiration: datetime.datetime):
    date_int = int(expiration.timestamp())
    encrypted_pem = encrypt_key(key)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, date_int));
    connection.commit()

# Get all keys and filter based on whether they are expired or not
def get_keys(expired: bool) -> List[Tuple[int, datetime.datetime, RSAPrivateKey]]:
    cursor = connection.cursor()
    # Get all keys and do filtering later
    cursor.execute("SELECT * FROM keys")
    rows = cursor.fetchall()
    # Get the current ticks from epoch
    now = int(datetime.datetime.utcnow().timestamp())
    ret_data = []
    for row in rows:
        key_expiration = row[2]
        id = row[0]
        key_data = aes_decrypt(row[1])
        # Add the key to the return data if it is expired when that's what we're looking for and vise-versa
        if expired == (key_expiration < now):
            ret_data.append((
                id,
                # Reconvert to datetime
                datetime.datetime.utcfromtimestamp(key_expiration),
                # load pem blob into an RSAPrivateKey object for easier use
                serialization.load_pem_private_key(key_data, backend=default_backend(), password=None)
            ))
    return ret_data
