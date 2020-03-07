import hashlib
import sqlite3
import sys

def get_pw_hash(inp):
    return hashlib.new('md4', inp.encode('utf-16le')).hexdigest().upper()

passwords_db = sys.argv[1]

hash_bs = get_pw_hash(input())
print(f"password hash is {hash_bs}")

conn = sqlite3.connect('passwords.db')
c = conn.cursor()
c.execute("select hash, count from passwords where hash = ?", (hash_bs,))
res = [row for row in c]
if res:
    print(f"password is seen {res[0][1]} times")
else:
    print("password is not pwned yet")