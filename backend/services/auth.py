from typing import Optional, Dict, Any
from .db.manager import DatabaseManager
from .core.crypto import CryptoManager # We will move/import the provided crypto logic here

class AuthService:
    def __init__(self, db: DatabaseManager, crypto: CryptoManager):
        self.db = db
        self.crypto = crypto

    def register(self, email: str, master_password: str) -> bool:
        # 1. Validate password strength
        is_valid, msg = self.crypto.validate_master_password(master_password)
        if not is_valid:
            raise ValueError(msg)

        # 2. Generate Salt for the Vault Key Derivation (KDF)
        salt = self.crypto.generate_salt()
        salt_b64 = self.crypto.encode_base64(salt)

        # 3. Hash Master Password for server-side authentication (bcrypt)
        master_hash = self.crypto.hash_master_password(master_password)

        # 4. Store in DB
        try:
            self.db.execute(
                "INSERT INTO users (email, master_password_hash, vault_salt, kdf_iterations) VALUES (?, ?, ?, ?)",
                (email, master_hash, salt_b64, self.crypto.iterations)
            )
            return True
        except Exception as e:
            if "UNIQUE constraint failed" in str(e):
                raise ValueError("Email already registered.")
            raise e

    def login(self, email: str, master_password: str) -> Optional[Dict[str, Any]]:
        user = self.db.fetch_one("SELECT * FROM users WHERE email = ?", (email,))
        if not user:
            return None

        if self.crypto.verify_master_password(master_password, user["master_password_hash"]):
            return {
                "id": user["id"],
                "email": user["email"],
                "vault_salt": user["vault_salt"],
                "iterations": user["kdf_iterations"]
            }
        return None
