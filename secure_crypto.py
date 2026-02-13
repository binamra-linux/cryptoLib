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

class SecureFileEncryption:
    """
    Hybrid encryption for files using RSA + AES.
    
    Uses RSA to encrypt a random AES key, then AES-GCM to encrypt the file.
    This provides both security and efficiency for large files.
    """
    
    def __init__(self, rsa_encryption: Optional[RSAEncryption] = None):
        """
        Initialize file encryption.
        
        Args:
            rsa_encryption: RSAEncryption instance (optional for password-based encryption)
        """
        self.rsa = rsa_encryption
    
    def encrypt_file(self, input_path: Union[str, Path], 
                    output_path: Union[str, Path],
                    password: Optional[str] = None) -> dict:
        """
        Encrypt a file using hybrid encryption or password-based encryption.
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output
            password: Optional password for key derivation (instead of RSA)
            
        Returns:
            Metadata dictionary (save this for decryption!)
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read file
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate random AES key for this file
        aes = AESEncryption()
        
        # Encrypt file content
        encrypted_data = aes.encrypt(plaintext)
        
        metadata = {
            'version': '1.0',
            'algorithm': 'AES-256-GCM',
            'nonce': base64.b64encode(encrypted_data['nonce']).decode('utf-8'),
            'tag': base64.b64encode(encrypted_data['tag']).decode('utf-8'),
            'original_filename': input_path.name
        }
        
        # Handle key encryption
        if password:
            # Password-based encryption
            key, salt = SecureKeyGenerator.derive_key_from_password(password)
            metadata['key_derivation'] = 'PBKDF2-SHA256'
            metadata['salt'] = base64.b64encode(salt).decode('utf-8')
            metadata['iterations'] = SecureKeyGenerator.PBKDF2_ITERATIONS
            
            # Encrypt the AES key with the derived key
            key_encryptor = AESEncryption(key)
            encrypted_aes_key = key_encryptor.encrypt(aes.key)
            metadata['encrypted_key'] = base64.b64encode(encrypted_aes_key['ciphertext']).decode('utf-8')
            metadata['key_nonce'] = base64.b64encode(encrypted_aes_key['nonce']).decode('utf-8')
            metadata['key_tag'] = base64.b64encode(encrypted_aes_key['tag']).decode('utf-8')
            
        elif self.rsa:
            # RSA-based encryption
            encrypted_key = self.rsa.encrypt(aes.key)
            metadata['encrypted_key'] = base64.b64encode(encrypted_key).decode('utf-8')
            metadata['key_encryption'] = 'RSA-OAEP-SHA256'
        else:
            raise ValueError("Either password or RSA encryption must be provided")
        
        # Write encrypted file
        with open(output_path, 'wb') as f:
            # Write metadata as JSON header
            metadata_json = json.dumps(metadata).encode('utf-8')
            metadata_length = len(metadata_json)
            
            # Write: [4 bytes: metadata length] [metadata] [encrypted content]
            f.write(metadata_length.to_bytes(4, byteorder='big'))
            f.write(metadata_json)
            f.write(encrypted_data['ciphertext'])
        
        return metadata
    
    def decrypt_file(self, input_path: Union[str, Path], 
                    output_path: Union[str, Path],
                    password: Optional[str] = None) -> dict:
        """
        Decrypt a file encrypted with encrypt_file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            password: Password if file was encrypted with password
            
        Returns:
            Metadata dictionary
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read encrypted file
        with open(input_path, 'rb') as f:
            # Read metadata length
            metadata_length = int.from_bytes(f.read(4), byteorder='big')
            
            # Read and parse metadata
            metadata_json = f.read(metadata_length)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Read encrypted content
            ciphertext = f.read()
        
        # Decrypt the AES key
        if 'key_derivation' in metadata:
            # Password-based decryption
            if not password:
                raise ValueError("Password required for decryption")
            
            salt = base64.b64decode(metadata['salt'])
            key, _ = SecureKeyGenerator.derive_key_from_password(password, salt)
            
            # Decrypt the AES key
            key_decryptor = AESEncryption(key)
            aes_key = key_decryptor.decrypt(
                base64.b64decode(metadata['encrypted_key']),
                base64.b64decode(metadata['key_nonce']),
                base64.b64decode(metadata['key_tag'])
            )
        else:
            # RSA-based decryption
            if not self.rsa:
                raise ValueError("RSA encryption instance required for decryption")
            
            encrypted_key = base64.b64decode(metadata['encrypted_key'])
            aes_key = self.rsa.decrypt(encrypted_key)
        
        # Decrypt file content
        aes = AESEncryption(aes_key)
        plaintext = aes.decrypt(
            ciphertext,
            base64.b64decode(metadata['nonce']),
            base64.b64decode(metadata['tag'])
        )
        
        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return metadata

class PasswordValidator:
    """
    Validate password strength and provide feedback.
    
    Helps users choose secure passwords by checking various criteria.
    """
    
    @staticmethod
    def check_strength(password: str) -> dict:
        """
        Check password strength and return detailed analysis.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with 'score', 'strength', and 'issues'
        """
        score = 0
        issues = []
        
        # Length checks
        if len(password) < 8:
            issues.append("Too short (minimum 8 characters, 12+ recommended)")
        elif len(password) < 12:
            issues.append("Consider using 12+ characters for better security")
            score += 15
        else:
            score += 25
        
        if len(password) >= 16:
            score += 15
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 15
        else:
            issues.append("Missing lowercase letters (a-z)")
        
        if re.search(r'[A-Z]', password):
            score += 15
        else:
            issues.append("Missing uppercase letters (A-Z)")
        
        if re.search(r'\d', password):
            score += 10
        else:
            issues.append("Missing numbers (0-9)")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/]', password):
            score += 10
        else:
            issues.append("Missing special characters (!@#$%^&*...)")
        
        # Additional security checks
        if len(set(password)) < len(password) * 0.6:
            issues.append("Too many repeated characters")
            score -= 10
        
        # Sequential characters check
        if any(password[i:i+3] in '0123456789' or 
               password[i:i+3] in 'abcdefghijklmnopqrstuvwxyz'
               for i in range(len(password) - 2)):
            issues.append("Contains sequential characters (123, abc)")
            score -= 5
        
        # Common password check
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football', 'admin'
        ]
        
        if password.lower() in common_passwords:
            score = 0
            issues = ["⚠️  CRITICAL: This is a commonly used password!"]
        
        # Ensure score is in valid range
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 80:
            strength = "Strong"
        elif score >= 60:
            strength = "Good"
        elif score >= 40:
            strength = "Fair"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'score': score,
            'strength': strength,
            'issues': issues
        }
    
    @staticmethod
    def suggest_improvements(password: str) -> list:
        """
        Suggest specific improvements for a password.
        
        Args:
            password: Password to analyze
            
        Returns:
            List of improvement suggestions
        """
        result = PasswordValidator.check_strength(password)
        suggestions = []
        
        if result['score'] < 60:
            suggestions.append("Consider using a passphrase (e.g., 'My@Dog#Ate$Pizza!2024')")
            suggestions.append("Use a password manager to generate and store strong passwords")
        
        if len(password) < 12:
            suggestions.append("Increase length to at least 12-16 characters")
        
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        
        if not re.search(r'\d', password):
            suggestions.append("Add numbers")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/]', password):
            suggestions.append("Add special characters")
        
        return suggestions