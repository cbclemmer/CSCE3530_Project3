from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import base64
import json
import time
import datetime

import db
from limiter import Limiter

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

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def auth_endpoint(server: BaseHTTPRequestHandler, params: dict, ip: str):
    if not "username" in params or not "password" in params:
        server.send_response(400)
        server.end_headers()
        return

    user_id = db.authenticate_user(params["username"], params["password"])
    if user_id is None:
        server.send_response(401)
        server.end_headers()
        return

    server.send_response(200)
    server.end_headers()

    # log auth request after response to improve response time
    cursor = db.connection.cursor()
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip, user_id))
    db.connection.commit()

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

def get_post_data(server: BaseHTTPRequestHandler) -> dict:
    content_length = int(server.headers['Content-Length'])
    return json.loads(server.rfile.read(content_length).decode('utf-8'))

def forward_auth(packet):
    auth_endpoint(packet["server"], packet["params"], packet["ip"])

def drop_auth(packet):
    server: BaseHTTPRequestHandler = packet["server"]
    server.send_response(429)
    server.end_headers()

# because gradebot waits for each packet to be returned before sending the next one
# we need to adjust the rate limit to account for response time of the server
lim = Limiter(10, 1, forward_auth, drop_auth) 

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
        start = time.time()
        parsed_path = urlparse(self.path)
        params = get_post_data(self)
        if parsed_path.path == "/auth":
            lim.handle({
                "server": self,
                "params": params,
                "ip": self.client_address[0]
            })
            #print(f'elapsed: {time.time() - start:.4f}')
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
