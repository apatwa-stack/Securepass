"""
test_app.py: Clean, simple unit tests for Password Service.
"""
import unittest
from app import app, generate_password, hash_password_pbkdf2, verify_password_pbkdf2, call_c_strength_check, C_LIB
import database as db

class TestPasswordService(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_generator(self):
        # Test length 20
        pw = generate_password(length=20)
        self.assertEqual(len(pw), 20)

        # Test length 12
        pw12 = generate_password(length=12)
        self.assertEqual(len(pw12), 12)

    def test_pbkdf2_hashing_and_verify(self):
        pw = "MySecretPassword123!"
        salt, hash_val, iterations = hash_password_pbkdf2(pw)
        
        # Verify valid password
        self.assertTrue(verify_password_pbkdf2(pw, salt, hash_val, iterations))
        
        # Verify incorrect password fails
        self.assertFalse(verify_password_pbkdf2("WrongPassword", salt, hash_val, iterations))

    def test_c_function(self):
        self.assertIsNotNone(C_LIB, "C shared library should be loaded")
        score = call_c_strength_check("Aa1!Aa1!Aa1!")
        self.assertGreater(score, 50)
        self.assertLessEqual(score, 100)

    def test_sqlite_persistence(self):
        # Save password
        new_id = db.save_password("TestService", "student@hs-offenburg.de", "TestPass123", "dummyhash")
        self.assertIsNotNone(new_id)

        # Fetch passwords
        passwords = db.get_all_passwords()
        self.assertTrue(any(p['id'] == new_id for p in passwords))

        # Delete password
        self.assertTrue(db.delete_password(new_id))

    def test_rest_api_generate(self):
        res = self.client.post("/api/generate", json={"length": 18})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("password", data)
        self.assertEqual(data["length"], 18)
        self.assertIn("strength_score", data)

    def test_rest_api_hash_and_verify(self):
        res = self.client.post("/api/hash", json={"password": "TestAPI"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("salt", data)
        self.assertIn("hash", data)

        # Verify
        verify_res = self.client.post("/api/verify", json={
            "password": "TestAPI",
            "salt": data["salt"],
            "hash": data["hash"]
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.get_json()["valid"])

    def test_rest_api_check_strength(self):
        res = self.client.post("/api/check_strength", json={"password": "HelloPassword99!"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("strength_score", data)

if __name__ == "__main__":
    unittest.main()
