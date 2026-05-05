import sqlite3
import os

class DatabaseManager:
    def __init__(self, db_path="password_manager.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        # Increased timeout to handle concurrent access
        conn = sqlite3.connect(self.db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r") as f:
            schema = f.read()
        
        conn = self._get_connection()
        # Set WAL mode once during initialization
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(schema)
        conn.commit()
        conn.close()

    def execute(self, query, params=()):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            conn.commit()
            return cursor
        finally:
            conn.close()

    def fetch_one(self, query, params=()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone()
        conn.close()
        return result

    def fetch_all(self, query, params=()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        return results

    def log_security_event(self, user_id, action):
        """Records a security-related action in the database."""
        self.execute(
            "INSERT INTO security_logs (user_id, action) VALUES (?, ?)",
            (user_id, action)
        )
