import sqlite3

# Create (or connect to) the database
conn = sqlite3.connect('vulns.db')
cursor = conn.cursor()

# Create the vulnerabilities table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    port INTEGER,
    service TEXT,
    state TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
conn.close()

print(" Database initialized: vulns.db")