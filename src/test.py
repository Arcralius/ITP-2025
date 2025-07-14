import pytest
import os
import tempfile
import shutil
import zipfile
import time
from datetime import datetime
from unittest.mock import patch, MagicMock
from flask import Flask
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import config

# Import the functions from your main module
# Assuming your main file is named 'pdns_utils.KeySigServer.py'
from pdns_utils.KeySigServer import (
    app, 
    append_date_to_filename, 
    generate_keys_and_hash, 
    generate_password, 
    zip_keys, 
    verify_password,
    daily_task
)


class TestAppendDateToFilename:
    """Test the append_date_to_filename function"""
    
    def test_append_date_basic(self):
        """Test basic date appending functionality"""
        with patch('pdns_utils.KeySigServer.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "20240315"
            result = append_date_to_filename("test.txt")
            assert result == "test_20240315.txt"
    
    def test_append_date_no_extension(self):
        """Test date appending to file without extension"""
        with patch('pdns_utils.KeySigServer.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "20240315"
            result = append_date_to_filename("test")
            assert result == "test_20240315"
    
    def test_append_date_complex_path(self):
        """Test date appending with complex file path"""
        with patch('pdns_utils.KeySigServer.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "20240315"
            result = append_date_to_filename("./path/to/file.key")
            assert result == "./path/to/file_20240315.key"


class TestGenerateKeysAndHash:
    """Test the generate_keys_and_hash function"""
    
    def setup_method(self):
        """Set up temporary directory for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.aes_path = os.path.join(self.temp_dir, "aes.key")
        self.ed_priv_path = os.path.join(self.temp_dir, "ed_priv.pem")
        self.ed_pub_path = os.path.join(self.temp_dir, "ed_pub.pem")
    
    def teardown_method(self):
        """Clean up temporary directory after each test"""
        shutil.rmtree(self.temp_dir)
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_generate_keys_and_hash_success(self, mock_datetime):
        """Test successful key generation"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        generate_keys_and_hash(self.aes_path, self.ed_priv_path, self.ed_pub_path)
        
        # Check that files were created with date suffix
        aes_file = f"{os.path.splitext(self.aes_path)[0]}_20240315{os.path.splitext(self.aes_path)[1]}"
        ed_priv_file = f"{os.path.splitext(self.ed_priv_path)[0]}_20240315{os.path.splitext(self.ed_priv_path)[1]}"
        ed_pub_file = f"{os.path.splitext(self.ed_pub_path)[0]}_20240315{os.path.splitext(self.ed_pub_path)[1]}"
        
        assert os.path.exists(aes_file)
        assert os.path.exists(ed_priv_file)
        assert os.path.exists(ed_pub_file)
        
        # Check AES key is 32 bytes
        with open(aes_file, 'rb') as f:
            aes_key = f.read()
            assert len(aes_key) == 32
        
        # Check Ed25519 keys are valid PEM format
        with open(ed_priv_file, 'rb') as f:
            priv_data = f.read()
            assert b"-----BEGIN PRIVATE KEY-----" in priv_data
        
        with open(ed_pub_file, 'rb') as f:
            pub_data = f.read()
            assert b"-----BEGIN PUBLIC KEY-----" in pub_data


class TestGeneratePassword:
    """Test the generate_password function"""
   
    def setup_method(self):
        """Set up temporary directory and test files"""
        self.temp_dir = tempfile.mkdtemp()
        self.aes_path = os.path.join(self.temp_dir, "aes_20240315.key")
        self.ed_priv_path = os.path.join(self.temp_dir, "ed_priv_20240315.pem")
        self.pwd_path = os.path.join(self.temp_dir, "pwd_20240315.txt")
        
        print(f"Test temp directory: {self.temp_dir}")
        print(f"AES key path: {self.aes_path}")
        print(f"Ed25519 private key path: {self.ed_priv_path}")
        print(f"Password file path: {self.pwd_path}")
       
        # Create test key files
        with open(self.aes_path, 'wb') as f:
            f.write(b"test_aes_key_32_bytes_long_data!!")
       
        # Generate a real Ed25519 private key for testing
        priv_key = Ed25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(self.ed_priv_path, 'wb') as f:
            f.write(priv_bytes)
        
        # Verify files were created
        print(f"AES key file exists: {os.path.exists(self.aes_path)}")
        print(f"Ed25519 private key file exists: {os.path.exists(self.ed_priv_path)}")
   
    def teardown_method(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.temp_dir)
   
    @patch('pdns_utils.KeySigServer.datetime')
    def test_generate_password_success(self, mock_datetime):
        """Test successful password generation"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        try:
            generate_password(self.aes_path, self.ed_priv_path, self.pwd_path)
        except FileNotFoundError as e:
            print(f"FileNotFoundError: {e}")
            print(f"Error trying to access: {e.filename}")
            print(f"Current working directory: {os.getcwd()}")
            print(f"Files in temp directory: {os.listdir(self.temp_dir)}")
            raise
       
        # Check that password file was created
        pwd_file = append_date_to_filename(self.pwd_path)
        assert os.path.exists(pwd_file)
       
        # Check password is valid SHA-256 hex
        with open(pwd_file, 'r') as f:
            password = f.read().strip()
            assert len(password) == 64  # SHA-256 hex length
            assert all(c in '0123456789abcdef' for c in password)
   
    @patch('pdns_utils.KeySigServer.datetime')
    def test_generate_password_file_not_found(self, mock_datetime):
        """Test password generation with missing key files"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
       
        # Try with non-existent AES key file
        with pytest.raises(FileNotFoundError):
            generate_password("nonexistent.key", self.ed_priv_path, self.pwd_path)
   
    @patch('pdns_utils.KeySigServer.datetime')
    def test_generate_password_consistent_hash(self, mock_datetime):
        """Test that the same keys produce the same password"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
       
        try:
            # Generate password twice
            generate_password(self.aes_path, self.ed_priv_path, self.pwd_path)
            pwd_file = append_date_to_filename(self.pwd_path)
           
            with open(pwd_file, 'r') as f:
                password1 = f.read().strip()
           
            # Generate again
            generate_password(self.aes_path, self.ed_priv_path, self.pwd_path)
           
            with open(pwd_file, 'r') as f:
                password2 = f.read().strip()
           
            assert password1 == password2
        except FileNotFoundError as e:
            print(f"FileNotFoundError: {e}")
            print(f"Error trying to access: {e.filename}")
            print(f"Current working directory: {os.getcwd()}")
            print(f"Files in temp directory: {os.listdir(self.temp_dir)}")
            raise


class TestZipKeys:
    """Test the zip_keys function"""
    
    def setup_method(self):
        """Set up temporary directory and test files"""
        self.temp_dir = tempfile.mkdtemp()
        self.aes_path = os.path.join(self.temp_dir, "aes_20240315.key")
        self.ed_priv_path = os.path.join(self.temp_dir, "ed_priv_20240315.pem")
        self.zip_path = os.path.join(self.temp_dir, "keys.zip")
        
        # Create test files
        with open(self.aes_path, 'wb') as f:
            f.write(b"test_aes_key_data")
        
        with open(self.ed_priv_path, 'wb') as f:
            f.write(b"test_ed_priv_key_data")
    
    def teardown_method(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.temp_dir)
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_zip_keys_success(self, mock_datetime):
        """Test successful key zipping"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        zip_keys(self.aes_path, self.ed_priv_path, self.zip_path)
        
        # Check that zip file was created
        zip_file = append_date_to_filename(self.zip_path)
        assert os.path.exists(zip_file)
        
        # Check zip contents
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            files = zipf.namelist()
            assert len(files) == 2
            assert any("aes_20240315.key" in f for f in files)
            assert any("ed_priv_20240315.pem" in f for f in files)
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_zip_keys_missing_file(self, mock_datetime):
        """Test zipping with missing key file"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        # Remove one of the key files
        os.remove(self.aes_path)
        
        with pytest.raises(FileNotFoundError):
            zip_keys(self.aes_path, self.ed_priv_path, self.zip_path)


class TestVerifyPassword:
    """Test the verify_password function"""
    
    def setup_method(self):
        """Set up temporary directory and test files"""
        self.temp_dir = tempfile.mkdtemp()
        self.pwd_path = os.path.join(self.temp_dir, "pwd.txt")
    
    def teardown_method(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.temp_dir)
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_success(self, mock_datetime):
        """Test successful password verification with single password"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        test_password = "abc123def456hash789"
        
        # Create the dated password file
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w') as f:
            f.write(test_password)
        
        # Test valid password
        assert verify_password(test_password, self.pwd_path) is True
        
        # Test invalid password
        assert verify_password("wrong_password", self.pwd_path) is False
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_file_not_found(self, mock_datetime):
        """Test password verification with non-existent file"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        result = verify_password("any_password", "nonexistent.txt")
        assert result is False
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_empty_file(self, mock_datetime):
        """Test password verification with empty file"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w') as f:
            f.write("")
        
        result = verify_password("any_password", self.pwd_path)
        assert result is False
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_whitespace_handling(self, mock_datetime):
        """Test password verification handles whitespace correctly"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        test_password = "password123"
        
        # Create file with whitespace around password
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w') as f:
            f.write(f"  {test_password}  \n")
        
        # Should match because strip() removes whitespace
        assert verify_password(test_password, self.pwd_path) is True
        
        # Should not match whitespace-padded password
        assert verify_password(f"  {test_password}  ", self.pwd_path) is False
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_newline_handling(self, mock_datetime):
        """Test password verification handles newlines correctly"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        test_password = "password123"
        
        # Create file with newline at end
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w') as f:
            f.write(f"{test_password}\n")
        
        # Should match because strip() removes newlines
        assert verify_password(test_password, self.pwd_path) is True
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_exact_match_required(self, mock_datetime):
        """Test that password verification requires exact match"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        test_password = "exact_password_123"
        
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w') as f:
            f.write(test_password)
        
        # Exact match should work
        assert verify_password(test_password, self.pwd_path) is True
        
        # Partial matches should fail
        assert verify_password("exact_password", self.pwd_path) is False
        assert verify_password("password_123", self.pwd_path) is False
        assert verify_password("EXACT_PASSWORD_123", self.pwd_path) is False
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_different_dates(self, mock_datetime):
        """Test password verification with different date scenarios"""
        # Test with one date
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        test_password = "test_password_20240315"
        dated_pwd_path_1 = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path_1, 'w') as f:
            f.write(test_password)
        
        assert verify_password(test_password, self.pwd_path) is True
        
        # Change date and test that it looks for different file
        mock_datetime.now.return_value.strftime.return_value = "20240316"
        
        # Should fail because it's looking for pwd_20240316.txt which doesn't exist
        assert verify_password(test_password, self.pwd_path) is False
        
        # Create the new dated file
        dated_pwd_path_2 = f"{os.path.splitext(self.pwd_path)[0]}_20240316{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path_2, 'w') as f:
            f.write("different_password_20240316")
        
        # Should fail with old password
        assert verify_password(test_password, self.pwd_path) is False
        
        # Should succeed with new password
        assert verify_password("different_password_20240316", self.pwd_path) is True
    
    @patch('pdns_utils.KeySigServer.datetime')
    @patch('pdns_utils.KeySigServer.logging')
    def test_verify_password_file_read_error(self, mock_logging, mock_datetime):
        """Test password verification handles file read errors"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        dated_pwd_path = append_date_to_filename(self.pwd_path)
        
        # Create the password file
        with open(dated_pwd_path, 'w') as f:
            f.write("test_password")

        if os.name != 'nt':
            try:
                # Make file unreadable
                os.chmod(dated_pwd_path, 0o000)

                result = verify_password("test_password", self.pwd_path)
                assert result is False
                mock_logging.info.assert_called()
            finally:
                # Restore permissions for cleanup, regardless of test outcome
                os.chmod(dated_pwd_path, 0o644)
        else:
            # If on Windows, we can't reliably make the file unreadable,
            # so we skip this specific test assertion.
            pytest.skip("Skipping permission-based file read error test on Windows.")

    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_sha256_format(self, mock_datetime):
        """Test password verification with SHA-256 format passwords"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        # Test with actual SHA-256 hex string (64 characters)
        sha256_password = "a" * 64  # 64 hex characters
        
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w') as f:
            f.write(sha256_password)
        
        assert verify_password(sha256_password, self.pwd_path) is True
        assert verify_password("b" * 64, self.pwd_path) is False
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_verify_password_encoding_utf8(self, mock_datetime):
        """Test password verification with UTF-8 encoding"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        # Test with UTF-8 characters (though passwords are typically hex)
        test_password = "test_password_üñíçødé"
        
        dated_pwd_path = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(dated_pwd_path, 'w', encoding='utf-8') as f:
            f.write(test_password)
        
        assert verify_password(test_password, self.pwd_path) is True
        assert verify_password("wrong_password", self.pwd_path) is False

class TestFlaskRoutes:
    """Test Flask application routes with comprehensive security testing"""
   
    def setup_method(self):
        """Set up Flask test client"""
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
       
        # Set up temporary directory
        self.temp_dir = tempfile.mkdtemp()
        self.pwd_path = os.path.join(self.temp_dir, "pwd.txt")
        self.zip_path = os.path.join(self.temp_dir, "keys.zip")
   
    def teardown_method(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.temp_dir)
   
    @patch('pdns_utils.KeySigServer.verify_password')
    @patch('pdns_utils.KeySigServer.append_date_to_filename')
    @patch('config.ZIP_FILENAME')
    def test_download_success(self, mock_zip_path, mock_append_date, mock_verify):
        """Test successful file download"""
        mock_verify.return_value = True
        mock_append_date.return_value = self.zip_path
        mock_zip_path.return_value = self.zip_path
       
        # Create a test zip file
        with zipfile.ZipFile(self.zip_path, 'w') as zipf:
            zipf.writestr("test.txt", "test content")
       
        response = self.client.post('/download',
                                   json={'password': 'valid_password'},
                                   content_type='application/json')
       
        assert response.status_code == 200
        assert response.headers['Content-Disposition'].startswith('attachment')
        assert 'application/zip' in response.headers.get('Content-Type', '')
   
    @patch('pdns_utils.KeySigServer.verify_password')
    def test_download_invalid_password(self, mock_verify):
        """Test download with invalid password"""
        mock_verify.return_value = False
       
        response = self.client.post('/download',
                                   json={'password': 'wrong_password'},
                                   content_type='application/json')
       
        assert response.status_code == 401
        assert response.json['error'] == 'Invalid credentials'
   
    def test_download_missing_password(self):
        """Test download without password"""
        response = self.client.post('/download',
                                   json={},
                                   content_type='application/json')
       
        assert response.status_code == 400
        assert response.json['error'] == 'Password is required'
   
    def test_download_no_json(self):
        """Test download without JSON data"""
        response = self.client.post('/download')
       
        assert response.status_code == 400
        assert response.json['error'] == 'Content-Type must be application/json'
        
    def test_download_invalid_json(self):
        """Test download with invalid JSON"""
        response = self.client.post('/download',
                                   data='invalid json',
                                   content_type='application/json')
       
        assert response.status_code == 400
        assert response.json['error'] == 'Invalid request format'
        
    def test_download_empty_json(self):
        """Test download with empty JSON"""
        response = self.client.post('/download',
                                   json=None,
                                   content_type='application/json')
       
        assert response.status_code == 400
        assert response.json['error'] == 'Invalid JSON data'
   
    def test_download_password_validation(self):
        """Test various password validation scenarios"""
        # Empty password
        response = self.client.post('/download',
                                   json={'password': ''},
                                   content_type='application/json')
        assert response.status_code == 400
        assert response.json['error'] == 'Password cannot be empty'
        
        # Password with only whitespace
        response = self.client.post('/download',
                                   json={'password': '   '},
                                   content_type='application/json')
        assert response.status_code == 400
        assert response.json['error'] == 'Password cannot be empty'
        
        # Non-string password
        response = self.client.post('/download',
                                   json={'password': 123},
                                   content_type='application/json')
        assert response.status_code == 400
        assert response.json['error'] == 'Password must be a string'
        
        # Password too long
        long_password = 'a' * 1001
        response = self.client.post('/download',
                                   json={'password': long_password},
                                   content_type='application/json')
        assert response.status_code == 400
        assert response.json['error'] == 'Password too long'
   
    @patch('pdns_utils.KeySigServer.verify_password')
    def test_download_password_file_not_found(self, mock_verify):
        """Test when password file doesn't exist"""
        mock_verify.side_effect = FileNotFoundError("Password file not found")
       
        response = self.client.post('/download',
                                   json={'password': 'valid_password'},
                                   content_type='application/json')
       
        assert response.status_code == 503
        assert response.json['error'] == 'Authentication service unavailable'
        
    @patch('pdns_utils.KeySigServer.verify_password')
    def test_download_password_verification_error(self, mock_verify):
        """Test when password verification throws an error"""
        mock_verify.side_effect = Exception("Verification error")
       
        response = self.client.post('/download',
                                   json={'password': 'valid_password'},
                                   content_type='application/json')
       
        assert response.status_code == 500
        assert response.json['error'] == 'Authentication failed'
   
    @patch('pdns_utils.KeySigServer.verify_password')
    @patch('pdns_utils.KeySigServer.append_date_to_filename')
    @patch('config.ZIP_FILENAME')
    def test_download_source_file_not_found(self, mock_zip_path, mock_append_date, mock_verify):
        """Test download when source zip file doesn't exist"""
        mock_verify.return_value = True
        mock_zip_path.return_value = "nonexistent.zip"
       
        response = self.client.post('/download',
                                   json={'password': 'valid_password'},
                                   content_type='application/json')
       
        assert response.status_code == 404
        assert response.json['error'] == 'Requested file not available'
        
    @patch('pdns_utils.KeySigServer.verify_password')
    @patch('pdns_utils.KeySigServer.append_date_to_filename')
    @patch('config.ZIP_FILENAME')
    def test_download_generated_file_not_found(self, mock_zip_path, mock_append_date, mock_verify):
        """Test download when generated file doesn't exist"""
        mock_verify.return_value = True
        mock_zip_path.return_value = self.zip_path
        mock_append_date.return_value = "nonexistent_generated.zip"
        
        # Create the source file but not the generated one
        with zipfile.ZipFile(self.zip_path, 'w') as zipf:
            zipf.writestr("test.txt", "test content")
       
        response = self.client.post('/download',
                                   json={'password': 'valid_password'},
                                   content_type='application/json')
       
        assert response.status_code == 500
        assert response.json['error'] == 'File generation failed'
        
    @patch('pdns_utils.KeySigServer.verify_password')
    @patch('pdns_utils.KeySigServer.append_date_to_filename')
    @patch('config.ZIP_FILENAME')
    def test_download_path_traversal_protection(self, mock_zip_path, mock_append_date, mock_verify):
        """Test path traversal attack protection"""
        mock_verify.return_value = True
        mock_zip_path.return_value = self.zip_path
        
        # Try to access a file outside the expected directory
        evil_path = "/etc/passwd"
        mock_append_date.return_value = evil_path
        
        # Create the source file
        with zipfile.ZipFile(self.zip_path, 'w') as zipf:
            zipf.writestr("test.txt", "test content")
       
        response = self.client.post('/download',
                                   json={'password': 'valid_password'},
                                   content_type='application/json')
       
        assert response.status_code == 403
        assert response.json['error'] == 'Access denied'
        
    @patch('pdns_utils.KeySigServer.verify_password')
    @patch('pdns_utils.KeySigServer.append_date_to_filename')
    @patch('config.ZIP_FILENAME')
    def test_download_file_too_large(self, mock_zip_path, mock_append_date, mock_verify):
        """Test file size limit protection"""
        mock_verify.return_value = True
        mock_zip_path.return_value = self.zip_path
        mock_append_date.return_value = self.zip_path
        
        # Create a large file (mock the file size check)
        with zipfile.ZipFile(self.zip_path, 'w') as zipf:
            zipf.writestr("test.txt", "test content")
            
        with patch('os.path.getsize', return_value=200 * 1024 * 1024):  # 200MB
            response = self.client.post('/download',
                                       json={'password': 'valid_password'},
                                       content_type='application/json')
       
        assert response.status_code == 413
        assert response.json['error'] == 'File too large'
        
    @patch('pdns_utils.KeySigServer.verify_password')
    @patch('pdns_utils.KeySigServer.append_date_to_filename')
    @patch('config.ZIP_FILENAME')
    def test_download_permission_error(self, mock_zip_path, mock_append_date, mock_verify):
        """Test file permission error handling"""
        mock_verify.return_value = True
        mock_zip_path.return_value = self.zip_path
        mock_append_date.return_value = self.zip_path
        
        # Create the file but mock permission error
        with zipfile.ZipFile(self.zip_path, 'w') as zipf:
            zipf.writestr("test.txt", "test content")
            
        with patch('os.access', return_value=False):
            response = self.client.post('/download',
                                       json={'password': 'valid_password'},
                                       content_type='application/json')
       
        assert response.status_code == 403
        assert response.json['error'] == 'File access denied'
        
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Make multiple requests quickly
        for i in range(6):  # Exceed the limit of 5
            response = self.client.post('/download',
                                       json={'password': 'test'},
                                       content_type='application/json')
            if i < 5:
                # First 5 requests should process normally (even if they fail auth)
                assert response.status_code != 429
            else:
                # 6th request should be rate limited
                assert response.status_code == 429
                assert response.json['error'] == 'Too many requests'
                
    def test_rate_limiting_reset(self):
        """Test that rate limiting resets after time window"""
        # Make requests to hit rate limit
        for i in range(5):
            self.client.post('/download',
                            json={'password': 'test'},
                            content_type='application/json')
        
        # Mock time advancement
        with patch('time.time', return_value=time.time() + 301):  # 5+ minutes later
            response = self.client.post('/download',
                                       json={'password': 'test'},
                                       content_type='application/json')
            assert response.status_code != 429
            
    def test_security_headers(self):
        """Test that security headers are added to responses"""
        response = self.client.post('/download',
                                   json={'password': 'test'},
                                   content_type='application/json')
        
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
        assert 'X-XSS-Protection' in response.headers
        assert 'Strict-Transport-Security' in response.headers
        
    def test_request_size_limit(self):
        """Test request size limit handling"""
        # Create a very large request
        large_data = {'password': 'a' * 10000, 'extra': 'x' * 100000}
        
        response = self.client.post('/download',
                                   json=large_data,
                                   content_type='application/json')
        
        # Should be handled by request size validation or return 413
        assert response.status_code in [400, 413]
        
    def test_timing_attack_protection(self):
        """Test timing attack protection (basic test)"""
        # This is a basic test - in practice you'd measure actual timing
        start_time = time.time()
        
        response = self.client.post('/download',
                                   json={'password': 'wrong_password'},
                                   content_type='application/json')
        
        elapsed = time.time() - start_time
        
        # Should take at least 0.1 seconds due to timing protection
        assert elapsed >= 0.1
        assert response.status_code == 401
        
    def test_method_not_allowed(self):
        """Test that only POST method is allowed"""
        response = self.client.get('/download')
        assert response.status_code == 405
        
        response = self.client.put('/download')
        assert response.status_code == 405
        
        response = self.client.delete('/download')
        assert response.status_code == 405

class TestDailyTask:
    """Test the scheduled daily task"""
    
    @patch('pdns_utils.KeySigServer.zip_keys')
    @patch('pdns_utils.KeySigServer.generate_password')
    @patch('pdns_utils.KeySigServer.generate_keys_and_hash')
    def test_daily_task_success(self, mock_gen_keys, mock_gen_pwd, mock_zip):
        """Test successful execution of daily task"""
        mock_gen_keys.return_value = None
        mock_gen_pwd.return_value = None
        mock_zip.return_value = None
        
        # Should not raise any exception
        daily_task()
        
        # Verify all functions were called
        mock_gen_keys.assert_called_once()
        mock_gen_pwd.assert_called_once()
        mock_zip.assert_called_once()
    
    @patch('pdns_utils.KeySigServer.zip_keys')
    @patch('pdns_utils.KeySigServer.generate_password')
    @patch('pdns_utils.KeySigServer.generate_keys_and_hash')
    @patch('pdns_utils.KeySigServer.logging')
    def test_daily_task_exception_handling(self, mock_logging, mock_gen_keys, mock_gen_pwd, mock_zip):
        """Test daily task handles exceptions properly"""
        mock_gen_keys.side_effect = Exception("Test exception")
        
        # Should not raise exception, but should log it
        daily_task()
        
        # Verify exception was logged
        mock_logging.exception.assert_called_once()

# Integration tests
class TestIntegration:
    """Integration tests for the complete workflow"""
    
    def setup_method(self):
        """Set up temporary directory for integration tests"""
        self.temp_dir = tempfile.mkdtemp()
        self.aes_path = os.path.join(self.temp_dir, "aes.key")
        self.ed_priv_path = os.path.join(self.temp_dir, "ed_priv.pem")
        self.ed_pub_path = os.path.join(self.temp_dir, "ed_pub.pem")
        self.pwd_path = os.path.join(self.temp_dir, "pwd.txt")
        self.zip_path = os.path.join(self.temp_dir, "keys.zip")
    
    def teardown_method(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.temp_dir)
    
    @patch('pdns_utils.KeySigServer.datetime')
    def test_complete_workflow(self, mock_datetime):
        """Test the complete key generation and verification workflow"""
        mock_datetime.now.return_value.strftime.return_value = "20240315"
        
        # Step 1: Generate keys
        generate_keys_and_hash(self.aes_path, self.ed_priv_path, self.ed_pub_path)
        
        # Step 2: Generate password
        generate_password(self.aes_path, self.ed_priv_path, self.pwd_path)
        
        # Step 3: Zip keys
        zip_keys(self.aes_path, self.ed_priv_path, self.zip_path)
        
        # Step 4: Verify password works
        pwd_file = f"{os.path.splitext(self.pwd_path)[0]}_20240315{os.path.splitext(self.pwd_path)[1]}"
        with open(pwd_file, 'r') as f:
            password = f.read().strip()
        
        assert verify_password(password, self.pwd_path) is True
        
        # Step 5: Verify zip file exists and contains correct files
        zip_file = f"{os.path.splitext(self.zip_path)[0]}_20240315{os.path.splitext(self.zip_path)[1]}"
        assert os.path.exists(zip_file)
        
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            files = zipf.namelist()
            assert len(files) == 2


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])