import os

def init_bytes_file(file_name: str) -> bytes: 
    if os.path.exists(file_name):
        with open(file_name, 'rb') as f:
            return f.read()
    iv = os.urandom(16)
    with open(file_name, 'wb') as f:
        f.write(iv)
    return iv
