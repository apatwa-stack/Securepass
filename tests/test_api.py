import unittest
import json
from app import app
import database.db as db

class TestSecurePassAPI(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_health_check(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('c_engine_loaded', data)

    def test_generate_password_endpoint(self):
        payload = {
            "mode": "password",
            "length": 22,
            "include_uppercase": True,
            "include_lowercase": True,
            "include_digits": True,
            "include_symbols": True
        }
        res = self.client.post('/api/generate', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('password', data)
        self.assertEqual(len(data['password']), 22)
        self.assertIn('analysis', data)
        self.assertIn('shannon_entropy_bits', data['analysis'])

    def test_generate_passphrase_endpoint(self):
        payload = {
            "mode": "passphrase",
            "word_count": 4,
            "separator": "-"
        }
        res = self.client.post('/api/generate', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['mode'], 'passphrase')
        self.assertIn('-', data['password'])

    def test_analyze_endpoint(self):
        res = self.client.post('/api/analyze', json={"password": "TestPassword123!#"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('shannon_entropy_bits', data)
        self.assertIn('strength_label', data)

    def test_hash_and_verify_endpoints(self):
        pw = "MyMasterPassword2026!"
        hash_res = self.client.post('/api/hash', json={"password": pw, "iterations": 10000})
        self.assertEqual(hash_res.status_code, 200)
        hash_data = hash_res.get_json()
        self.assertIn('encoded', hash_data)

        # Successful verification
        verify_res = self.client.post('/api/verify', json={
            "password": pw,
            "encoded": hash_data['encoded']
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.get_json()['valid'])

        # Failed verification
        verify_fail = self.client.post('/api/verify', json={
            "password": "WrongPassword",
            "encoded": hash_data['encoded']
        })
        self.assertEqual(verify_fail.status_code, 200)
        self.assertFalse(verify_fail.get_json()['valid'])

    def test_vault_crud(self):
        # Create vault item
        item_payload = {
            "service_name": "TestService_HS_Offenburg",
            "username_or_email": "test@hs-offenburg.de",
            "password_value": "VerySecretPw!123",
            "category": "Academic"
        }
        post_res = self.client.post('/api/vault', json=item_payload)
        self.assertEqual(post_res.status_code, 201)
        item_id = post_res.get_json()['item_id']

        # Get vault items
        get_res = self.client.get('/api/vault')
        self.assertEqual(get_res.status_code, 200)
        vault_items = get_res.get_json()['vault']
        self.assertTrue(any(i['id'] == item_id for i in vault_items))

        # Delete item
        del_res = self.client.delete(f'/api/vault/{item_id}')
        self.assertEqual(del_res.status_code, 200)

    def test_user_registration_and_login(self):
        username = "hso_student_unit_test"
        password = "SecurePassword#2026"

        # Register
        reg_res = self.client.post('/api/users/register', json={
            "username": username,
            "password": password
        })
        # Could be 201 or 409 if exists
        self.assertIn(reg_res.status_code, [201, 409])

        # Login success
        login_res = self.client.post('/api/users/login', json={
            "username": username,
            "password": password
        })
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(login_res.get_json()['authenticated'])

        # Login failure
        login_fail = self.client.post('/api/users/login', json={
            "username": username,
            "password": "WrongPasswordAttempt"
        })
        self.assertEqual(login_fail.status_code, 401)
        self.assertFalse(login_fail.get_json()['authenticated'])

if __name__ == '__main__':
    unittest.main()
