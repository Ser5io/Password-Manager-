import json
from typing import List, Dict, Any
from backend.db.manager import DatabaseManager
from backend.core.crypto import CryptoManager

class VaultService:
    def __init__(self, db: DatabaseManager, crypto: CryptoManager):
        self.db = db
        self.crypto = crypto

    def add_item(self, user_id: int, master_password: str, item_details: Dict[str, str]):
        """
        item_details: { 'name': ..., 'username': ..., 'password': ..., 'url': ... }
        """
        # 1. Get user salt to derive the key
        user = self.db.fetch_one("SELECT vault_salt FROM users WHERE id = ?", (user_id,))
        salt = self.crypto.decode_base64(user["vault_salt"])
        
        # 2. Derive Encryption Key
        key = self.crypto.derive_key(master_password, salt)

        # 3. Encrypt the whole item dictionary
        encrypted_package = self.crypto.encrypt_vault(item_details, key)
        encrypted_json = json.dumps(encrypted_package)

        # 4. Save to DB
        self.db.execute(
            "INSERT INTO vault_items (user_id, encrypted_data) VALUES (?, ?)",
            (user_id, encrypted_json)
        )

    def get_items(self, user_id: int, master_password: str) -> List[Dict[str, Any]]:
        user = self.db.fetch_one("SELECT vault_salt FROM users WHERE id = ?", (user_id,))
        salt = self.crypto.decode_base64(user["vault_salt"])
        key = self.crypto.derive_key(master_password, salt)

        rows = self.db.fetch_all("SELECT * FROM vault_items WHERE user_id = ?", (user_id,))
        decrypted_items = []

        for row in rows:
            encrypted_package = json.loads(row["encrypted_data"])
            try:
                item_data = self.crypto.decrypt_vault(encrypted_package, key)
                item_data["id"] = row["id"]
                decrypted_items.append(item_data)
            except Exception:
                # Decryption failure (likely wrong master password or corrupted data)
                continue
        
        return decrypted_items

    def delete_item(self, user_id: int, item_id: int):
        self.db.execute("DELETE FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))

    def export_vault(self, user_id: int) -> str:
        """Returns the raw encrypted items as a JSON string for backup."""
        rows = self.db.fetch_all("SELECT encrypted_data FROM vault_items WHERE user_id = ?", (user_id,))
        items = [json.loads(row["encrypted_data"]) for row in rows]
        return json.dumps(items)

    def import_vault(self, user_id: int, encrypted_items_json: str):
        items = json.loads(encrypted_items_json)
        for item in items:
            self.db.execute(
                "INSERT INTO vault_items (user_id, encrypted_data) VALUES (?, ?)",
                (user_id, json.dumps(item))
            )
