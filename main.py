from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

import db

# Create the key table if it does not exist
db.create_key_table()

hostName = "localhost"
serverPort = 8080

def create_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Create a current key and an expired key
current_key = create_key()
expired_key = create_key()

now = datetime.datetime.utcnow()
later = now + datetime.timedelta(hours=1)

# Save both keys to database
db.save_private_key(current_key, later)
db.save_private_key(expired_key, now)

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Get the first key that will be expired if the 'expired' param is present
            kid, key_expiration, db_key = db.get_keys('expired' in params)[0]

            headers = {
                "kid": str(kid)
            }
            token_payload = {
                "user": "username",
                "exp": key_expiration 
            }
            db_pem = db.make_pem(db_key)
            encoded_jwt = jwt.encode(token_payload, db_pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            good_keys = db.get_keys(False)
            key_list = []
            # Get all non-expired keys
            for kid, _, db_key in good_keys:
                db_numbers = db_key.private_numbers().public_numbers
                key_list.append({
                    "alg": "RSA256",
                    "ktty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "n": int_to_base64(db_numbers.n),
                    "e": int_to_base64(db_numbers.e)
                })
            keys = {
                "keys": key_list
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
