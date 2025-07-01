import requests
import os
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from zipfile import ZipFile, BadZipFile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


TEST_LINK = "http://localhost:5000/downloads"
OUT_DIR   = "./client_download"
ZIP_NAME  = "keys.zip"
VERIFY_SSL= False


def sign_and_package_file(file_to_sign: str, signature_file: str, output_path: str):
    try:
        # Load the private key for signing
        try:
            with open('private_key.pem', 'rb') as key_file:
                private_key = ECC.import_key(key_file.read())
        except FileNotFoundError:
            raise FileNotFoundError("Private key file 'private_key.pem' not found.")
        except Exception as e:
            raise Exception(f"Error loading private key: {e}")

        # Prepare the file to be signed
        try:
            with open(file_to_sign, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File to sign '{file_to_sign}' not found.")
        except Exception as e:
            raise Exception(f"Error reading file to sign: {e}")

        # Create the signature
        try:
            signer = eddsa.new(private_key)
            h = SHA512.new(file_data)
            signature = signer.sign(h)
        except Exception as e:
            raise Exception(f"Error signing the file: {e}")

        # Save the signature to the specified file
        try:
            with open(signature_file, 'wb') as sig_file:
                sig_file.write(signature)
        except Exception as e:
            raise Exception(f"Error writing signature to file '{signature_file}': {e}")

        # Package the file and signature into a ZIP archive
        try:
            with ZipFile(output_path, 'w') as zipf:
                zipf.write(file_to_sign, os.path.basename(file_to_sign))
                zipf.write(signature_file, os.path.basename(signature_file))
        except Exception as e:
            raise Exception(f"Error creating ZIP archive '{output_path}': {e}")

        print(f"File signed and packaged successfully. Output saved to: {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")


def encrypt_file(file_to_encrypt: str, key_file: str, output_path: str):
    try:
        # Read the AES key from the specified file
        try:
            with open(key_file, 'rb') as key_file:
                aes_key = key_file.read()
                if len(aes_key) != 32:
                    raise ValueError("AES key must be 256 bits (32 bytes).")
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file not found: {key_file}")
        except Exception as e:
            raise Exception(f"Error reading key file: {e}")

        # Generate a random IV (Initialization Vector)
        iv = get_random_bytes(AES.block_size)

        # Create AES cipher instance
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Read the file to encrypt
        try:
            with open(file_to_encrypt, 'rb') as f:
                plaintext = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File to encrypt not found: {file_to_encrypt}")
        except Exception as e:
            raise Exception(f"Error reading file to encrypt: {e}")

        # Pad the plaintext to be a multiple of AES.block_size
        padded_data = pad(plaintext, AES.block_size)

        # Encrypt the padded data
        ciphertext = cipher.encrypt(padded_data)

        # Write the IV and ciphertext to the output file
        try:
            with open(output_path, 'wb') as out_file:
                out_file.write(iv)  # Prepend the IV to the ciphertext
                out_file.write(ciphertext)
            print(f"File encrypted successfully. Encrypted file saved to: {output_path}")
        except Exception as e:
            raise Exception(f"Error writing encrypted file: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")


def download_sig_and_key(download_link: str, password: str, output_dir: str, verify_ssl: bool = True):
    try:
        # Prepare the POST data
        data = {'password': password}

        # Send the POST request
        response = requests.post(download_link, json=data, stream=True, verify=verify_ssl)
        response.raise_for_status()  # Raise an error for bad status codes

        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Define the path for the downloaded ZIP file
        zip_path = os.path.join(output_dir, ZIP_NAME)

        # Write the response content to the ZIP file
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        print(f"ZIP file downloaded and saved to: {zip_path}")

        # Extract the ZIP file
        with ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
            print(f"Files extracted to: {output_dir}")

    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    except BadZipFile as zip_err:
        print(f"Error extracting ZIP file: {zip_err}")
    except Exception as err:
        print(f"An unexpected error occurred: {err}")


if __name__ == '__main__':
    password = input("Enter your password: ")
    download_sig_and_key(TEST_LINK, password, OUT_DIR, VERIFY_SSL)
    