import os
import json
import base64
import bcrypt
import secrets
import string
from typing import Dict, Any, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoManager:
    def __init__(self, iterations: int = 600_000):
        if iterations < 100_000:
            raise ValueError("Iterations must be at least 100,000.")

        self.iterations = iterations
        self.salt_size = 16
        self.nonce_size = 12
        self.key_size = 32

  

    def generate_salt(self) -> bytes:
        return os.urandom(self.salt_size)

    def generate_nonce(self) -> bytes:
        return os.urandom(self.nonce_size)

    def encode_base64(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        return base64.b64encode(data).decode("utf-8")

    def decode_base64(self, data: str) -> bytes:
        if not isinstance(data, str):
            raise TypeError("Base64 data must be a string.")

        try:
            return base64.b64decode(data.encode("utf-8"))
        except Exception:
            raise ValueError("Invalid Base64 format.")

  

    def validate_master_password(self, password: str) -> Tuple[bool, str]:
        if not isinstance(password, str):
            return False, "Password must be a string."

        if len(password) < 8:
            return False, "Password must be at least 8 characters."

        if not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter."

        if not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter."

        if not any(char.isdigit() for char in password):
            return False, "Password must contain at least one digit."

        if not any(not char.isalnum() for char in password):
            return False, "Password must contain at least one symbol."

        return True, "Strong password."

    def generate_strong_password(self, length: int = 16) -> str:
        if length < 12:
            raise ValueError("Password length must be at least 12.")

        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"

        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+[]{};:,.?/")
        ]

        password += [secrets.choice(chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

   

    def hash_master_password(self, master_password: str) -> str:
        is_valid, message = self.validate_master_password(master_password)

        if not is_valid:
            raise ValueError(message)

        hashed = bcrypt.hashpw(
            master_password.encode("utf-8"),
            bcrypt.gensalt()
        )

        return hashed.decode("utf-8")

    def verify_master_password(self, master_password: str, stored_hash: str) -> bool:
        if not isinstance(master_password, str) or not isinstance(stored_hash, str):
            return False

        if not master_password or not stored_hash:
            return False

        try:
            return bcrypt.checkpw(
                master_password.encode("utf-8"),
                stored_hash.encode("utf-8")
            )
        except ValueError:
            return False

    

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        if not isinstance(master_password, str) or not master_password:
            raise ValueError("Master password is required.")

        if not isinstance(salt, bytes) or len(salt) != self.salt_size:
            raise ValueError("Invalid salt size.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations
        )

        return kdf.derive(master_password.encode("utf-8"))

    def validate_encryption_key(self, encryption_key: bytes) -> None:
        if not isinstance(encryption_key, bytes):
            raise TypeError("Encryption key must be bytes.")

        if len(encryption_key) != self.key_size:
            raise ValueError("Invalid encryption key length.")

  

    def encrypt_vault(
        self,
        vault_data: Dict[str, Any],
        encryption_key: bytes
    ) -> Dict[str, str]:

        if not isinstance(vault_data, dict):
            raise TypeError("Vault data must be a dictionary.")

        self.validate_encryption_key(encryption_key)

        nonce = self.generate_nonce()

        try:
            json_data = json.dumps(
                vault_data,
                ensure_ascii=False,
                indent=2
            ).encode("utf-8")

            aesgcm = AESGCM(encryption_key)
            ciphertext = aesgcm.encrypt(nonce, json_data, None)

            return {
                "algorithm": "AES-256-GCM",
                "nonce": self.encode_base64(nonce),
                "ciphertext": self.encode_base64(ciphertext)
            }

        except TypeError:
            raise TypeError("Vault data must be JSON serializable.")

    def decrypt_vault(
        self,
        encrypted_package: Dict[str, str],
        encryption_key: bytes
    ) -> Dict[str, Any]:

        if not isinstance(encrypted_package, dict):
            raise TypeError("Encrypted package must be a dictionary.")

        required_fields = ["algorithm", "nonce", "ciphertext"]

        for field in required_fields:
            if field not in encrypted_package:
                raise ValueError(f"Missing required field: {field}")

        if encrypted_package["algorithm"] != "AES-256-GCM":
            raise ValueError("Unsupported encryption algorithm.")

        self.validate_encryption_key(encryption_key)

        try:
            nonce = self.decode_base64(encrypted_package["nonce"])
            ciphertext = self.decode_base64(encrypted_package["ciphertext"])

            if len(nonce) != self.nonce_size:
                raise ValueError("Invalid nonce size.")

            aesgcm = AESGCM(encryption_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

            return json.loads(decrypted_data.decode("utf-8"))

        except InvalidTag:
            raise ValueError("Data integrity check failed. Data may be corrupted or tampered with.")

        except json.JSONDecodeError:
            raise ValueError("Decrypted data is not valid JSON.")

   

    def create_new_vault(
        self,
        master_password: str,
        vault_data: Dict[str, Any]
    ) -> Dict[str, Any]:

        salt = self.generate_salt()
        master_hash = self.hash_master_password(master_password)
        encryption_key = self.derive_key(master_password, salt)
        encrypted_vault = self.encrypt_vault(vault_data, encryption_key)

        return {
            "master_hash": master_hash,
            "salt": self.encode_base64(salt),
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": self.iterations,
            "vault": encrypted_vault
        }

    def unlock_vault(
        self,
        master_password: str,
        vault_package: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not isinstance(vault_package, dict):
            raise TypeError("Vault package must be a dictionary.")

        required_fields = ["master_hash", "salt", "kdf", "iterations", "vault"]

        for field in required_fields:
            if field not in vault_package:
                raise ValueError(f"Missing required field: {field}")

        if vault_package["kdf"] != "PBKDF2-HMAC-SHA256":
            raise ValueError("Unsupported key derivation function.")

        if not self.verify_master_password(master_password, vault_package["master_hash"]):
            raise ValueError("Wrong master password.")

        salt = self.decode_base64(vault_package["salt"])
        encryption_key = self.derive_key(master_password, salt)

        return self.decrypt_vault(vault_package["vault"], encryption_key)