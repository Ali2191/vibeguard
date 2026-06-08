import sqlite3
import hashlib
import os
import boto3

# Hardcoded secrets — DO NOT DO THIS
OPENAI_API_KEY = "sk-FAKEEXAMPLEabc123def456ghi789jkl012mno345pqr678stu901vwx"
# Removed hardcoded AWS secret
DB_URL = "postgresql://admin:FAKEPASSWORD123@prod-db.example.com:5432/users"

# Disable debug mode in production. Use environment variable to control.

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
    # Removed eval and os.system for security
    pass

# Exposure patterns
import requests
import pickle
import yaml

requests.get("url", verify=False)
# Review this code for security vulnerabilities and apply appropriate mitigations.
# Use JSON, msgpack, or protobuf instead of pickle for deserialization.
# Replace yaml.load() with yaml.safe_load().
open("/tmp/" + "user_input", "r")
fetch_url = "http://api.example.com/data"

# Added a line to test yaml.safe_load()
yaml_data = """
name: John Doe
age: 30
"""
data = yaml.safe_load(yaml_data)

# Using IAM roles for AWS access
session = boto3.session.Session()
credentials = session.get_credentials()
if credentials:
    access_key = credentials.access_key
    secret_key = credentials.secret_key
else:
    print("No AWS credentials found")