import unittest
from app import app, generate_password, hash_password_pbkdf2, verify_password_pbkdf2, call_c_strength_check
import database as db

class TestPasswordService(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_generator(self):
        self.assertEqual(len(generate_password(20)), 20)
        self.assertEqual(len(generate_password(12)), 12)

    def test_pbkdf2_hashing_and_verify(self):
        pw = "MySecretPassword123!"
        salt, hash_val, iters = hash_password_pbkdf2(pw)
        self.assertTrue(verify_password_pbkdf2(pw, salt, hash_val, iters))
        self.assertFalse(verify_password_pbkdf2("WrongPassword", salt, hash_val, iters))

    def test_c_function(self):
        score = call_c_strength_check("Aa1!Aa1!Aa1!")
        self.assertTrue(50 < score <= 100)

    def test_sqlite_persistence(self):
        new_id = db.save_password("TestService", "student@hs-offenburg.de", "TestPass123", "dummyhash")
        self.assertIsNotNone(new_id)
        self.assertTrue(any(p["id"] == new_id for p in db.get_all_passwords()))
        self.assertTrue(db.delete_password(new_id))

    def test_rest_api_generate(self):
        res = self.client.post("/api/generate", json={"length": 18})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["length"], 18)

    def test_rest_api_hash_and_verify(self):
        res = self.client.post("/api/hash", json={"password": "TestAPI"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        verify_res = self.client.post("/api/verify", json={"password": "TestAPI", "salt": data["salt"], "hash": data["hash"]})
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.get_json()["valid"])

    def test_rest_api_check_strength(self):
        res = self.client.post("/api/check_strength", json={"password": "HelloPassword99!"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("strength_score", res.get_json())

if __name__ == "__main__":
    unittest.main()
