import unittest
from unittest.mock import patch
from main import app, users_conf, posts_conf, auth_conf
from werkzeug.security import check_password_hash
from bson.objectid import ObjectId
import secrets
import hashlib

class AuthTestCase(unittest.TestCase):
    """This class contains tests for the authentication and password reset functionality."""

    def setUp(self):
        """Set up a test client and create a test user before each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing forms
        app.config['SECRET_KEY'] = 'test-secret-key' # Use a fixed secret key for testing
        self.client = app.test_client()

        # --- Create a test user ---
        self.test_user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'old_password',
            'is_confirmed': True
        }
        # Clean up any previous test user
        users_conf.delete_one({'username': self.test_user_data['username']})
        # Insert the new test user
        users_conf.insert_one({
            '_id': ObjectId("507f191e810c19729de860ea"), # Use a fixed ID for predictability
            'username': self.test_user_data['username'],
            'email': self.test_user_data['email'],
            'password': 'hashed_old_password', # In a real scenario, this would be hashed
            'is_confirmed': self.test_user_data['is_confirmed']
        })

        # --- Create a test post for the user ---
        posts_conf.delete_one({'author_id': ObjectId("507f191e810c19729de860ea")})
        posts_conf.insert_one({
            'title': 'Test Post',
            'content': 'This is a test.',
            'author_id': ObjectId("507f191e810c19729de860ea"),
            'author': self.test_user_data['username']
        })

    def tearDown(self):
        """Clean up the database after each test."""
        users_conf.delete_one({'username': 'newtestuser'})
        users_conf.delete_one({'username': self.test_user_data['username']})
        posts_conf.delete_one({'author_id': ObjectId("507f191e810c19729de860ea")})
        auth_conf.delete_one({'email': self.test_user_data['email']})

    @patch('main.send_reset_code') # Mock the email sending function
    def test_full_password_reset_flow(self, mock_send_reset_code):
        """
        Tests the entire password reset process:
        1. Request a reset link.
        2. Use the link to set a new username and password.
        3. Verify the changes and login with new credentials.
        """
        # --- Step 1: Request a password reset ---
        response = self.client.post('/forgot_password', data={'email': self.test_user_data['email']})
        self.assertEqual(response.status_code, 200) # Should render the page again
        self.assertIn(b"we&#39;ve sent you a password reset link", response.data)

        # --- Step 2: Extract the token from the mocked email function ---
        self.assertTrue(mock_send_reset_code.called)
        # Get the arguments passed to the mocked function
        call_args = mock_send_reset_code.call_args
        # The token is the second positional argument (index 1)
        reset_token = call_args[0][1] 
        self.assertIsNotNone(reset_token)

        # Verify the token was stored in the database (hashed)
        hashed_token = hashlib.sha256(reset_token.encode()).hexdigest()
        auth_record = auth_conf.find_one({'reset_token': hashed_token})
        self.assertIsNotNone(auth_record)
        self.assertEqual(auth_record['email'], self.test_user_data['email'])

        # --- Step 3: Access the reset page and submit new credentials ---
        new_username = 'newtestuser'
        new_password = 'new_password'
        response = self.client.post(f'/reset_password/{reset_token}', data={
            'username': new_username,
            'password': new_password,
            'confirm_password': new_password
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your password has been reset successfully", response.data)
        self.assertIn(b"Welcome Back", response.data) # Should be on the login page

        # --- Step 4: Verify the changes in the database ---
        # 4.1 Check that the auth token has been deleted
        self.assertIsNone(auth_conf.find_one({'reset_token': hashed_token}))

        # 4.2 Check that the user's details have been updated
        updated_user = users_conf.find_one({'email': self.test_user_data['email']})
        self.assertIsNotNone(updated_user)
        self.assertEqual(updated_user['username'], new_username)
        self.assertTrue(check_password_hash(updated_user['password'], new_password))
        self.assertFalse(check_password_hash(updated_user['password'], self.test_user_data['password']))

        # 4.3 Check that the user's posts have been updated
        updated_post = posts_conf.find_one({'author_id': ObjectId("507f191e810c19729de860ea")})
        self.assertEqual(updated_post['author'], new_username)

        # --- Step 5: Try to log in with the new credentials (should succeed) ---
        login_response = self.client.post('/login', data={
            'username': new_username,
            'password': new_password
        }, follow_redirects=True)
        self.assertEqual(login_response.status_code, 200)
        self.assertIn(f"Welcome back, {new_username}!".encode(), login_response.data)

        # --- Step 6: Try to log in with the old credentials (should fail) ---
        logout_response = self.client.get('/logout', follow_redirects=True) # Log out first
        self.assertIn(b'You have been logged out', logout_response.data)

        login_response_old = self.client.post('/login', data={
            'username': self.test_user_data['username'],
            'password': self.test_user_data['password']
        }, follow_redirects=True)
        self.assertEqual(login_response_old.status_code, 200)
        self.assertIn(b"Wrong details provided", login_response_old.data)


if __name__ == '__main__':
    unittest.main()