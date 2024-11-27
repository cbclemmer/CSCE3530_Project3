from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import json
from typing import Tuple

import db
from limiter import Limiter

# Create the tables if they do not exist
def init():
    db.create_tables()

def auth_endpoint(params: dict, ip: str) -> int:
    if not "username" in params or not "password" in params:
        return 400

    user_id = db.authenticate_user(params["username"], params["password"])
    if user_id is None:
        return 401

    cursor = db.connection.cursor()
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip, user_id))
    db.connection.commit()
    return 200

def register_endpoint(params: dict) -> Tuple[int, dict | None]:
    if not "username" in params or "email" not in params:
        return 400, None
    password = db.save_user(params["username"], params["email"])

    return 200, {
        "password": password
    }

def auth_wrapper(server: BaseHTTPRequestHandler, params: dict, ip: str):
    status_code = auth_endpoint(params, ip)
    server.send_response(status_code)
    server.end_headers()

def register_wrapper(server: BaseHTTPRequestHandler, params: dict):
    status_code, body = register_endpoint(params)
    server.send_response(status_code)
    server.end_headers()
    if status_code == 200:
        server.wfile.write(json.dumps(body).encode())

def get_post_data(server: BaseHTTPRequestHandler) -> dict:
    content_length = int(server.headers['Content-Length'])
    return json.loads(server.rfile.read(content_length).decode('utf-8'))

def forward_auth(packet):
    auth_wrapper(packet["server"], packet["params"], packet["ip"])

def drop_auth(packet):
    server: BaseHTTPRequestHandler = packet["server"]
    server.send_response(429)
    server.end_headers()

# because gradebot waits for each packet to be returned before sending the next one
# we need to adjust the rate limit to account for response time of the server
lim = Limiter(10, 1, forward_auth, drop_auth) 

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        try:
            params = get_post_data(self)
        except:
            self.send_response(400)
            self.end_headers()
            return
        if parsed_path.path == "/auth":
            lim.handle({
                "server": self,
                "params": params,
                "ip": self.client_address[0]
            })
            return
        if parsed_path.path == "/register":
            register_wrapper(self, params)
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    init()
    hostName = "localhost"
    serverPort = 8080
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Web server started at port {serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
