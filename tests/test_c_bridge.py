import unittest
from core.c_bridge import bridge

class TestCBridge(unittest.TestCase):

    def test_c_library_loaded(self):
        # Check that the C module is found and loaded
        self.assertTrue(bridge.is_c_loaded, "Native C shared library (libentropy.dll/.so) must be loaded.")

    def test_c_entropy_calculation(self):
        result = bridge.analyze("Aa1!Aa1!Aa1!")
        self.assertEqual(result['length'], 12)
        self.assertEqual(result['uppercase_count'], 3)
        self.assertEqual(result['lowercase_count'], 3)
        self.assertEqual(result['digit_count'], 3)
        self.assertEqual(result['symbol_count'], 3)
        self.assertGreater(result['shannon_entropy_bits'], 0.0)
        self.assertGreater(result['pool_entropy_bits'], 0.0)
        self.assertIn("Native C", result['engine'])

    def test_c_weak_password_scoring(self):
        weak_res = bridge.analyze("123456")
        self.assertLess(weak_res['strength_score'], 50)
        self.assertIn(weak_res['strength_label'], ["Very Weak", "Weak"])

    def test_c_strong_password_scoring(self):
        strong_res = bridge.analyze("K9#vL2$pQ8*mZ!9xR5@t")
        self.assertGreaterEqual(strong_res['strength_score'], 80)
        self.assertIn(strong_res['strength_label'], ["Strong", "Very Strong"])

    def test_empty_password(self):
        res = bridge.analyze("")
        self.assertEqual(res['length'], 0)
        self.assertEqual(res['strength_score'], 0)

if __name__ == '__main__':
    unittest.main()
