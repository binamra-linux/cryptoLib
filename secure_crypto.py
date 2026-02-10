import os
import json
import base64
import re
from typing import Optional, Tuple, Union
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class SecureKeyGenerator:
    """Generate cryptographically secure keys with safe defaults."""
    
    # Security constants - only strong parameters allowed
    MIN_RSA_KEY_SIZE = 3072  # NIST recommendation for 2030+
    RECOMMENDED_RSA_KEY_SIZE = 4096
    AES_KEY_SIZE = 256  # bits
    SALT_SIZE = 32  # bytes
    PBKDF2_ITERATIONS = 600000  # OWASP 2023 recommendation
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = RECOMMENDED_RSA_KEY_SIZE) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair with strong security defaults.
        
        Args:
            key_size: RSA key size in bits (minimum 3072, recommended 4096)
            
        Returns:
            Tuple of (private_key_pem, public_key_pem) as bytes
            
        Raises:
            ValueError: If key_size is below minimum security threshold
        """
        if key_size < SecureKeyGenerator.MIN_RSA_KEY_SIZE:
            raise ValueError(
                f"Key size {key_size} is insecure. "
                f"Minimum allowed: {SecureKeyGenerator.MIN_RSA_KEY_SIZE} bits"
            )
        
        # Generate private key with secure public exponent
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # F4, most common secure exponent
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize private key with encryption recommended
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # User can encrypt if needed
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate a secure 256-bit AES key."""
        return os.urandom(SecureKeyGenerator.AES_KEY_SIZE // 8)
    
    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive a secure encryption key from a password using PBKDF2.
        
        Args:
            password: User password
            salt: Optional salt (will be generated if not provided)
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(SecureKeyGenerator.SALT_SIZE)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=SecureKeyGenerator.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

class RSAEncryption:
    """RSA encryption with OAEP padding for strong security."""
    
    def __init__(self, private_key_pem: Optional[bytes] = None, 
                 public_key_pem: Optional[bytes] = None):
        """
        Initialize RSA encryption.
        
        Args:
            private_key_pem: PEM-encoded private key
            public_key_pem: PEM-encoded public key
        """
        self.private_key = None
        self.public_key = None
        
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            # Derive public key from private key if not provided
            if not public_key_pem:
                self.public_key = self.private_key.public_key()
        
        if public_key_pem:
            self.public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using RSA-OAEP.
        
        Args:
            plaintext: Data to encrypt (max ~470 bytes for 4096-bit key)
            
        Returns:
            Encrypted ciphertext
            
        Raises:
            ValueError: If no public key available or data too large
        """
        if not self.public_key:
            raise ValueError("No public key available for encryption")
        
        # Check size limit (conservative estimate)
        max_size = (self.public_key.key_size // 8) - 114  # OAEP overhead
        if len(plaintext) > max_size:
            raise ValueError(
                f"Data too large for RSA encryption. "
                f"Maximum {max_size} bytes, got {len(plaintext)} bytes. "
                f"Use hybrid encryption for larger data."
            )
        
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt RSA-OAEP encrypted data.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If no private key available
        """
        if not self.private_key:
            raise ValueError("No private key available for decryption")
        
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using RSA-PSS.
        
        Args:
            message: Message to sign
            
        Returns:
            Digital signature
        """
        if not self.private_key:
            raise ValueError("No private key available for signing")
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a digital signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.public_key:
            raise ValueError("No public key available for verification")
        
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class AESEncryption:
    """AES-256 encryption with GCM mode for authenticated encryption."""
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize AES encryption.
        
        Args:
            key: 256-bit encryption key (will be generated if not provided)
        """
        self.key = key if key else SecureKeyGenerator.generate_aes_key()
        
        if len(self.key) != 32:
            raise ValueError("AES key must be exactly 32 bytes (256 bits)")
    
    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Dictionary containing 'ciphertext', 'nonce', and 'tag'
        """
        # Generate a random 96-bit nonce (recommended for GCM)
        nonce = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': encryptor.tag
        }
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt AES-256-GCM encrypted data.
        
        Args:
            ciphertext: Encrypted data
            nonce: Nonce used during encryption
            tag: Authentication tag
            
        Returns:
            Decrypted plaintext
            
        Raises:
            InvalidTag: If authentication fails (data tampered)
        """
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext