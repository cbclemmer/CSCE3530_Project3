from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

import db

# Create the tables if they do not exist
db.create_tables()

hostName = "localhost"
serverPort = 8080

# Create a current key and an expired key
current_key = db.create_key()
expired_key = db.create_key()

now = datetime.datetime.utcnow()
later = now + datetime.timedelta(hours=1)

# Save both keys to database
db.save_private_key(current_key, later)
db.save_private_key(expired_key, now)

def auth_endpoint(server: BaseHTTPRequestHandler, params: dict, ip: str):
    if not "username" in params or not "password" in params:
        server.send_response(400)
        server.end_headers()
        return

    if not db.authenticate_user(params["username"], params["password"], ip):
        server.send_response(401)
        server.end_headers()
        return

    # Get the first key that will be expired if the 'expired' param is present
    kid, key_expiration, db_key = db.get_keys('expired' in params)[0]

    headers = {
        "kid": str(kid)
    }
    token_payload = {
        "user": params["username"],
        "exp": key_expiration 
    }
    db_pem = db.make_pem(db_key)
    encoded_jwt = jwt.encode(token_payload, db_pem, algorithm="RS256", headers=headers)
    server.send_response(200)
    server.end_headers()
    server.wfile.write(bytes(encoded_jwt, "utf-8"))

def register_endpoint(server: BaseHTTPRequestHandler, params: dict):
    if not "username" in params or "email" not in params:
        server.send_response(400)
        server.end_headers()
        return
    password = db.save_user(params["username"], params["email"])
    server.send_response(200)
    server.end_headers()
    server.wfile.write(json.dumps({
        "password": password
    }).encode())


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
            auth_endpoint(self, params, self.client_address[0])
            return
        if parsed_path.path == "/register":
            register_endpoint(self, params)
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
