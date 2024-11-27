from http.server import HTTPServer

import os
from time import sleep
from uuid import UUID, uuid4
import requests
import unittest
import main
import db
import datetime
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


AUTH_ENDPOINT = 'http://localhost:8080/auth'
REGISTER_ENDPOINT = 'http://localhost:8080/register' 

def register(un: str, email: str):
    return requests.post(REGISTER_ENDPOINT, json={
        "username": un,
        "email": email
    })

proc: multiprocessing.Process = multiprocessing.Process(target=lambda x: x, args=())

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global proc
        main.init()
        proc = multiprocessing.Process(target=start_server, args=())
        proc.start()
        sleep(1)

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


class MainTests(unittest.TestCase):
    @classmethod
    def setupClass(cls):
        main.init()

    def test_register(self):
        un = str(uuid4())
        status_code, body = main.register_endpoint({})
        self.assertEqual(None, body)
        self.assertEqual(400, status_code)

        status_code, body = main.register_endpoint({ "username": un })
        self.assertEqual(None, body)
        self.assertEqual(400, status_code)
        
        email = un + "@domain.com"
        status_code, body = main.register_endpoint({
            "username": un,
            "email": email
        })
        self.assertEqual(200, status_code)
        self.assertEqual(type({}), type(body))
        self.assertTrue(is_valid_uuid(body["password"]))

    def test_auth(self):
        un = str(uuid4())
        email = un + "@domain.com"
        status_code, body = main.register_endpoint({
            "username": un,
            "email": email
        })
        pwd = body["password"]
        
        status_code = main.auth_endpoint({}, "")
        self.assertEqual(400, status_code)
        
        status_code = main.auth_endpoint({ "username": un }, "")
        self.assertEqual(400, status_code)

        status_code = main.auth_endpoint({
            "username": un,
            "password": "bad_password"
        }, "")
        self.assertEqual(401, status_code)

        status_code = main.auth_endpoint({
            "username": un,
            "password": pwd
        }, "")
        self.assertEqual(200, status_code)

class DBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.init()

    def test_aes_encryption(self):
        test_string = "This is only a test".encode()
        ciphertext = db.aes_encrypt(test_string)
        self.assertEqual(test_string, db.aes_decrypt(ciphertext))

        aes_key = os.environ.get(db.AES_ENV_VAR)
        self.assertIsNotNone(aes_key)
        del os.environ[db.AES_ENV_VAR]
        try:
            db.get_aes_key()
            self.fail()
        except:
            pass

        os.environ[db.AES_ENV_VAR] = aes_key

    def test_pem(self):
        key = db.create_key()
        pem = db.make_pem(key)
        self.assertIsNotNone(pem)
        self.assertEqual(type(bytes([])), type(pem))

        encrypted_key = db.encrypt_key(key)
        self.assertEqual(type(bytes([])), type(encrypted_key))
        

    def test_authenticate_user(self):
        user_id = db.authenticate_user("", "")
        self.assertIsNone(user_id)

    def test_save_private_key(self):
        key = db.create_key()
        db.save_private_key(key, datetime.datetime.utcnow())

if __name__ == '__main__':
    unittest.main()
