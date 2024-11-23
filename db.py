import os
import sqlite3
import datetime
from typing import List, Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key


ENV_PUB_KEY_FILE="rsa_key.pub"
ENV_PRV_KEY_FILE="rsa_key"

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


connection = sqlite3.connect('totally_not_my_privateKeys.db')

def read_key_environment_var():
    return os.environ.get('NOT_MY_KEY')


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

# Converts a private key object to a PEM encoded string
def make_pem(key: RSAPrivateKey):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def encrypt_key(key: RSAPrivateKey):
    pem = make_pem(key)
    with open(ENV_PRV_KEY_FILE, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key.public_key(). pt(pem, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

# Save the private key to the database
def save_private_key(key: RSAPrivateKey, expiration: datetime.datetime):
    date_int = int(expiration.timestamp())
    pem = make_pem(key)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, date_int));

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
        key_data = row[1]
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
