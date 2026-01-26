import sqlite3
import random
import datetime

DB_NAME = "dais_test.db"

def create_dummy_db():
    print(f"Creating dummy database: {DB_NAME}...")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 1. Create 'users' table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            status INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Create 'logs' table (for large text testing)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT,
            message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Populate 'users' (100 rows)
    users_data = []
    for i in range(1, 101):
        users_data.append((f"user_{i}", f"user{i}@example.com", random.choice([0, 1])))
    
    cursor.executemany("INSERT INTO users (username, email, status) VALUES (?, ?, ?)", users_data)
    print(f"Inserted 100 rows into 'users'.")

    # 4. Populate 'logs' (50 rows with some long text)
    logs_data = []
    levels = ["INFO", "WARNING", "ERROR", "DEBUG"]
    for i in range(50):
        level = random.choice(levels)
        msg = f"Log entry {i}: " + "Detailed error message with stack trace " * random.randint(1, 5)
        logs_data.append((level, msg))
        
    cursor.executemany("INSERT INTO logs (level, message) VALUES (?, ?)", logs_data)
    print(f"Inserted 50 rows into 'logs'.")

    conn.commit()
    conn.close()
    print("Database setup complete.")

if __name__ == "__main__":
    create_dummy_db()
