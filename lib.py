import os
import re

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

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')
