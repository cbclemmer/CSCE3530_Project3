from http.server import HTTPServer

import os
from time import sleep
from uuid import UUID, uuid4
import requests
import unittest
import main
import multiprocessing

# https://stackoverflow.com/questions/53847404/how-to-check-uuid-validity-in-python
def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test

def start_server():
    webServer = HTTPServer(("localhost", 8080), main.MyServer)
    webServer.serve_forever()

def remove_db():
    DB_FILE = "totally_not_my_privateKeys.db"
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)


proc = multiprocessing.Process(target=start_server, args=())
proc.start()
sleep(1) # give time for the server to start

AUTH_ENDPOINT = 'http://localhost:8080/auth'
REGISTER_ENDPOINT = 'http://localhost:8080/register' 

def register(un: str, email: str):
    return requests.post(REGISTER_ENDPOINT, json={
        "username": un,
        "email": email
    })

class ServerTests(unittest.TestCase):
    def test_register(self):
        # should not work if no params supplied
        res = requests.post(REGISTER_ENDPOINT)
        self.assertEqual(400, res.status_code)

        un = str(uuid4())
        email = un + "@domain.com"
        # should not work if only supplied username
        res = requests.post(REGISTER_ENDPOINT, json={
            "username": un
        })
        self.assertEqual(400, res.status_code)

        # should work if supplied both username and email
        res = register(un, email)
        self.assertEqual(200, res.status_code)
        data: dict = res.json()
        self.assertTrue("password" in data)
        # should recieve a valid uuid as a password back
        self.assertTrue(is_valid_uuid(data["password"]))

    def test_auth(self):
        # Setup
        un = str(uuid4())
        email = un + "@domain.com"
        res = register(un, email)
        self.assertEqual(200, res.status_code)
        pwd = res.json()["password"]
        
        # should not work if no body data is sent
        res = requests.post(AUTH_ENDPOINT)
        self.assertEqual(400, res.status_code)

        # should not work if no password is sent
        res = requests.post(AUTH_ENDPOINT, json={
            "username": un
        })
        self.assertEqual(400, res.status_code)

        # should not authenticate if incorrect password is supplied
        res = requests.post(AUTH_ENDPOINT, json={
            "username": un,
            "password": "bad_password"
        })

        self.assertEqual(401, res.status_code)

        # should work with valid data
        res = requests.post(AUTH_ENDPOINT, json={
            "username": un,
            "password": pwd
        })
        self.assertEqual(200, res.status_code)
    @classmethod
    def tearDownClass(cls):
        proc.terminate()

if __name__ == '__main__':
    unittest.main()