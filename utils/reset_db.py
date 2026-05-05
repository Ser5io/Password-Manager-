import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), "..", "password_manager.db")

def reset_database():
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        print("Removing all records from database...")

        # Delete all records from all tables
        cursor.execute("DELETE FROM vault_items")
        cursor.execute("DELETE FROM security_logs")
        cursor.execute("DELETE FROM users")
        
        # Reset autoincrement counters
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='vault_items'")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='security_logs'")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")

        conn.commit()
        
        # Optimize and shrink the file
        cursor.execute("VACUUM")
        conn.commit()

        print("Success: All records have been removed and IDs have been reset.")

    except sqlite3.Error as e:
        print(f"Error while resetting database: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    confirm = input("Are you sure you want to DELETE ALL RECORDS? (y/n): ")
    if confirm.lower() == 'y':
        reset_database()
    else:
        print("Operation cancelled.")
