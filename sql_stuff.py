import sqlite3
from user import User

conn = sqlite3.connect('user.db')

c = conn.cursor()

user_1 = User('Deez', 'Nutz')

conn.commit()

print(c.fetchall())

conn.commit()

conn.close()