import unittest
from core.hasher import (
    hash_password,
    verify_password,
    verify_encoded,
    PasswordHashingError
)

class TestPasswordHasher(unittest.TestCase):

    def test_salt_uniqueness(self):
        pw = "SuperSecretPassword123!"
        h1 = hash_password(pw, iterations=50000)
        h2 = hash_password(pw, iterations=50000)

        # Unique salts generated via CSPRNG
        self.assertNotEqual(h1['salt_hex'], h2['salt_hex'])
        self.assertNotEqual(h1['hash_hex'], h2['hash_hex'])

    def test_deterministic_with_same_salt(self):
        pw = "DeterministicTest#99"
        fixed_salt = b"0123456789abcdef0123456789abcdef"
        h1 = hash_password(pw, salt=fixed_salt, iterations=10000)
        h2 = hash_password(pw, salt=fixed_salt, iterations=10000)

        self.assertEqual(h1['hash_hex'], h2['hash_hex'])

    def test_verification_success(self):
        pw = "CorrectPassword2026!"
        h = hash_password(pw, iterations=20000)

        valid = verify_password(
            password=pw,
            stored_hash_hex=h['hash_hex'],
            stored_salt_hex=h['salt_hex'],
            iterations=h['iterations'],
            algorithm=h['algorithm']
        )
        self.assertTrue(valid)

    def test_verification_failure(self):
        pw = "CorrectPassword2026!"
        h = hash_password(pw, iterations=20000)

        valid = verify_password(
            password="WrongPasswordAttempt",
            stored_hash_hex=h['hash_hex'],
            stored_salt_hex=h['salt_hex'],
            iterations=h['iterations'],
            algorithm=h['algorithm']
        )
        self.assertFalse(valid)

    def test_verify_encoded_format(self):
        pw = "ModularStringTest!"
        h = hash_password(pw, iterations=15000)

        # Verify using formatted string
        self.assertTrue(verify_encoded(pw, h['encoded']))
        self.assertFalse(verify_encoded("WrongPw", h['encoded']))

    def test_empty_password_raises(self):
        with self.assertRaises(PasswordHashingError):
            hash_password("")

if __name__ == '__main__':
    unittest.main()
