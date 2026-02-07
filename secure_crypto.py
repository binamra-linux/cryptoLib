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