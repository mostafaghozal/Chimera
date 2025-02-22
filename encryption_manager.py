# encryption_manager.py

import os
import base64
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class EncryptionManager:
    """
    A simple encryption manager that uses AES-CBC with PKCS7 padding.
    
    Methods:
      - encrypt(plaintext, key): Encrypts the plaintext string with the provided key (passphrase).
      - decrypt(ciphertext_b64, key): Decrypts the Base64-encoded ciphertext using the same key.
    
    The key is derived from the passphrase using SHA-256 (first 16 bytes for AES-128).
    """

    @staticmethod
    def derive_key(passphrase: str) -> bytes:
        """
        Derive a 16-byte key from the given passphrase using SHA-256.
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(passphrase.encode('utf-8'))
        return digest.finalize()[:16]

    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt the plaintext string using AES-CBC.
        
        :param plaintext: The message to encrypt.
        :param key: A passphrase used to derive the AES key.
        :return: A Base64 URL-safe encoded string containing the IV + ciphertext.
        """
        key_bytes = EncryptionManager.derive_key(key)
        plaintext_bytes = plaintext.encode('utf-8')

        # Pad plaintext to the block size (128 bits for AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()

        # Generate a random IV
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Prepend IV to ciphertext and encode as Base64
        result = iv + ciphertext
        return base64.urlsafe_b64encode(result).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext_b64: str, key: str) -> str:
        """
        Decrypt a Base64 URL-safe encoded ciphertext using AES-CBC.
        
        :param ciphertext_b64: The Base64-encoded string containing the IV + ciphertext.
        :param key: The same passphrase used for encryption.
        :return: The original plaintext string.
        """
        key_bytes = EncryptionManager.derive_key(key)
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64)

        # Extract the IV (first 16 bytes) and the actual ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

        # Unpad the plaintext
        unpadder = padding.PKCS7(128).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext_bytes.decode('utf-8')
    
    def encode_fragment_data(data, fragment_size=10):
        """Encode and split data into small fragments to evade detection."""
        encoded = base64.urlsafe_b64encode(data.encode()).decode()
        return [encoded[i:i+fragment_size] for i in range(0, len(encoded), fragment_size)]
