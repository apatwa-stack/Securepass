import unittest
import string
from core.generator import (
    generate_password,
    generate_multiple_passwords,
    generate_passphrase,
    PasswordGenerationError,
    AMBIGUOUS_CHARS
)

class TestPasswordGenerator(unittest.TestCase):

    def test_default_password_length(self):
        pw = generate_password()
        self.assertEqual(len(pw), 16)

    def test_custom_length(self):
        for l in [8, 12, 24, 48, 64]:
            pw = generate_password(length=l)
            self.assertEqual(len(pw), l)

    def test_length_boundaries(self):
        with self.assertRaises(PasswordGenerationError):
            generate_password(length=3)
        with self.assertRaises(PasswordGenerationError):
            generate_password(length=300)

    def test_character_inclusion(self):
        # Letters only
        pw_letters = generate_password(length=20, include_digits=False, include_symbols=False)
        self.assertTrue(all(c.isalpha() for c in pw_letters))

        # Digits only
        pw_digits = generate_password(
            length=10,
            include_uppercase=False,
            include_lowercase=False,
            include_digits=True,
            include_symbols=False
        )
        self.assertTrue(all(c.isdigit() for c in pw_digits))

    def test_ambiguous_exclusion(self):
        # Generate 20 passwords with exclude_ambiguous=True
        for _ in range(20):
            pw = generate_password(length=30, exclude_ambiguous=True)
            for c in pw:
                self.assertNotIn(c, AMBIGUOUS_CHARS)

    def test_custom_exclusion(self):
        exclude_set = "XYZ012!@"
        for _ in range(10):
            pw = generate_password(length=25, custom_exclude=exclude_set)
            for c in pw:
                self.assertNotIn(c, exclude_set)

    def test_guarantee_each_type(self):
        pw = generate_password(
            length=16,
            include_uppercase=True,
            include_lowercase=True,
            include_digits=True,
            include_symbols=True,
            guarantee_each_type=True
        )
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw))

    def test_batch_generation(self):
        passwords = generate_multiple_passwords(count=5, length=12)
        self.assertEqual(len(passwords), 5)
        self.assertEqual(len(set(passwords)), 5)  # All distinct

    def test_passphrase_generation(self):
        phrase = generate_passphrase(word_count=4, separator="-")
        parts = phrase.split("-")
        # 4 words + 1 appended 2-digit number = 5 tokens
        self.assertEqual(len(parts), 5)
        self.assertTrue(parts[-1].isdigit())

if __name__ == '__main__':
    unittest.main()
