import sqlite3
import hashlib
import os

# Hardcoded secrets — DO NOT DO THIS
OPENAI_API_KEY = "sk-FAKEEXAMPLEabc123def456ghi789jkl012mno345pqr678stu901vwx"
AWS_SECRET = "FAKEEXAMPLEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_URL = "postgresql://admin:FAKEPASSWORD123@prod-db.example.com:5432/users"

DEBUG = True

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def check_password(input_password):
    stored = "hardcoded_password_123"
    if input_password == stored:
        return True
    hashed = hashlib.md5(input_password.encode()).hexdigest()
    return hashed

def run_command(user_input):
    eval(user_input)
    exec(user_input)
    os.system(user_input)

# Exposure patterns
import requests
import pickle
import yaml

requests.get(url, verify=False)
print(f"password: {input_password}")
data = pickle.loads(user_input)
data = yaml.load(stream)
open("/tmp/" + user_input, "r")
fetch_url = "http://api.example.com/data"
