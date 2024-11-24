import os
import sqlite3
import datetime
from argon2 import PasswordHasher
from uuid import uuid4
from typing import List, Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

ENV_PEM_KEY_FILE="rsa_key.pem"

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

password_hasher = PasswordHasher()


connection = sqlite3.connect('totally_not_my_privateKeys.db')

def read_key_environment_var():
    key = os.environ.get('NOT_MY_KEY')
    if key is None:
        raise Exception("Could not find NOT_MY_KEY environment var")
    return key

def create_key():
    return generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def create_key_table():
    cursor = connection.cursor()
    cursor.execute(KEY_TABLE_DECLARATION)

def create_user_table():
    cursor = connection.cursor()
    cursor.execute(USER_TABLE_DECLARATION)

def create_auth_logs_table():
    cursor = connection.cursor()
    cursor.execute(AUTH_LOG_TABLE_DECLARATION)

# Converts a private key object to a PEM encoded string
def make_pem(key: RSAPrivateKey):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def get_private_key() -> RSAPrivateKey:
    return load_pem_private_key(read_key_environment_var().encode(), password=None)

def get_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

def save_user(username: str, email: str):
    cursor = connection.cursor()
    password = str(uuid4())
    hashed_password = password_hasher.hash(password)
    cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed_password, email))
    return password

def authenticate_user(username: str, password: str, ip: str):
    cursor = connection.cursor()
    timestamp = datetime.datetime.utcnow()
    q = cursor.execute("SELECT * FROM users WHERE username=?", username)
    user = q.fetchone()
    if user is None:
        return False

    if not password_hasher.verify(user["password"], password):
        return False

    cursor.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", (ip, timestamp, user["id"]))
    return True

def encrypt_key(key: RSAPrivateKey):
    pem = make_pem(key)
    private_key = get_private_key()
    # TODO: could not encrypt because pem is too long
    return private_key.public_key().encrypt(pem, padding=get_padding())

# Save the private key to the database
def save_private_key(key: RSAPrivateKey, expiration: datetime.datetime):
    date_int = int(expiration.timestamp())
    encrypted_pem = encrypt_key(key)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, date_int));

def decrypt_key(encrypted_pem: bytes):
    private_key = get_private_key()
    return private_key.decrypt(encrypted_pem, padding=get_padding())

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
        key_data = decrypt_key(row[1])
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
