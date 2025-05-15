import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

# Constants
DATA_FILE = "encrypted_data.json"
LOCKOUT_DURATION = 300  # 5 minutes in seconds

# Initialize session state variables
if "users" not in st.session_state:
    st.session_state.users = {}  # Store user credentials {username: {hashed_password, salt}}
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = {}
if "fernet" not in st.session_state:
    st.session_state.fernet = Fernet(base64.urlsafe_b64encode(os.urandom(32)))
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Load data from JSON file
def load_data():
    try:
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
            # Load users into session state
            if "users" in data:
                st.session_state.users = {
                    username: {
                        "hashed_password": info["hashed_password"],
                        "salt": base64.b64decode(info["salt"])
                    } for username, info in data["users"].items()
                }
            return data
    except FileNotFoundError:
        return {"users": {}, "data": {}}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Function to hash passkey/password using PBKDF2
def hash_passkey(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key.decode()

# Check if user is locked out
def is_locked_out(username):
    if username in st.session_state.lockout_time:
        if time.time() < st.session_state.lockout_time[username]:
            remaining = int(st.session_state.lockout_time[username] - time.time())
            return True, remaining
    return False, 0

# Register page
def register_page():
    st.title("Register")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in st.session_state.users:
                st.error("Username already exists")
            else:
                # Generate a unique salt for this user
                salt = os.urandom(16)
                hashed_password = hash_passkey(password, salt)
                # Store the user with their salt
                st.session_state.users[username] = {
                    "hashed_password": hashed_password,
                    "salt": salt
                }
                # Load existing data and update users
                data = load_data()
                data["users"][username] = {
                    "hashed_password": hashed_password,
                    "salt": base64.b64encode(salt).decode()  # Store salt as base64 string
                }
                save_data(data)
                st.success("Registration successful! Please login.")
                # Add a delay to show the message
                time.sleep(2)
                st.rerun()
        else:
            st.error("Please provide both username and password")

# Login page
def login_page():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        locked, remaining = is_locked_out(username)
        if locked:
            st.error(f"Account locked. Try again in {remaining} seconds.")
            return
        if username in st.session_state.users:
            user_info = st.session_state.users[username]
            salt = user_info["salt"]
            hashed_password = hash_passkey(password, salt)
            if hashed_password == user_info["hashed_password"]:
                st.session_state.current_user = username
                st.session_state.authenticated = True
                st.session_state.failed_attempts[username] = 0
                st.success("Login successful!")
                time.sleep(2)
                st.rerun()
            else:
                st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
                if st.session_state.failed_attempts[username] >= 3:
                    st.session_state.lockout_time[username] = time.time() + LOCKOUT_DURATION
                    st.session_state.failed_attempts[username] = 0
                    st.error("Too many failed attempts. Account locked for 5 minutes.")
                else:
                    st.error(f"Invalid credentials. Attempt {st.session_state.failed_attempts[username]}/3")
        else:
            st.error("Username not found")

# Insert data page
def insert_data_page():
    st.title(f"Store Data - {st.session_state.current_user}")
    data = st.text_area("Enter data to store")
    passkey = st.text_input("Enter passkey", type="password")
    if st.button("Store"):
        if data and passkey:
            # Encrypt data
            encrypted_data = st.session_state.fernet.encrypt(data.encode()).decode()
            # Hash passkey with a new salt
            salt = os.urandom(16)
            hashed_passkey = hash_passkey(passkey, salt)
            # Load existing data
            data_store = load_data()
            # Initialize user data if not exists
            if "data" not in data_store:
                data_store["data"] = {}
            if st.session_state.current_user not in data_store["data"]:
                data_store["data"][st.session_state.current_user] = {}
            # Store data
            data_id = f"data{len(data_store['data'][st.session_state.current_user]) + 1}"
            data_store["data"][st.session_state.current_user][data_id] = {
                "encrypted_text": encrypted_data,
                "passkey": hashed_passkey,
                "salt": base64.b64encode(salt).decode()
            }
            save_data(data_store)
            st.success("Data stored securely!")
        else:
            st.error("Please provide both data and passkey")

# Retrieve data page
def retrieve_data_page():
    st.title(f"Retrieve Data - {st.session_state.current_user}")
    data_store = load_data()
    user_data = data_store.get("data", {}).get(st.session_state.current_user, {})
    data_id = st.selectbox("Select data ID", list(user_data.keys()) if user_data else ["No data available"])
    
    locked, remaining = is_locked_out(st.session_state.current_user)
    if locked:
        st.error(f"Account locked. Try again in {remaining} seconds.")
        return
    
    passkey = st.text_input("Enter passkey", type="password")
    st.write(f"Failed attempts: {st.session_state.failed_attempts.get(st.session_state.current_user, 0)}/3")
    
    if st.button("Retrieve"):
        if data_id == "No data available":
            st.error("No data to retrieve")
            return
        if st.session_state.failed_attempts.get(st.session_state.current_user, 0) >= 3:
            st.session_state.lockout_time[st.session_state.current_user] = time.time() + LOCKOUT_DURATION
            st.session_state.failed_attempts[st.session_state.current_user] = 0
            st.error("Too many failed attempts. Account locked for 5 minutes.")
            st.session_state.authenticated = False
            st.rerun()
        else:
            if passkey:
                stored = user_data.get(data_id)
                salt = base64.b64decode(stored["salt"])
                hashed_passkey = hash_passkey(passkey, salt)
                if stored and stored["passkey"] == hashed_passkey:
                    decrypted_data = st.session_state.fernet.decrypt(stored["encrypted_text"].encode()).decode()
                    st.success("Data retrieved successfully!")
                    st.write("Decrypted Data:", decrypted_data)
                    st.session_state.failed_attempts[st.session_state.current_user] = 0
                else:
                    st.session_state.failed_attempts[st.session_state.current_user] = st.session_state.failed_attempts.get(st.session_state.current_user, 0) + 1
                    st.error(f"Invalid passkey. Attempt {st.session_state.failed_attempts[st.session_state.current_user]}/3")
                    if st.session_state.failed_attempts[st.session_state.current_user] >= 3:
                        st.error("Too many failed attempts. Account locked for 5 minutes.")
                        st.session_state.lockout_time[st.session_state.current_user] = time.time() + LOCKOUT_DURATION
                        st.session_state.authenticated = False
                        st.rerun()
            else:
                st.error("Please provide a passkey")

# Home page
def home_page():
    st.title(f"Secure Data Encryption System - {st.session_state.current_user}")
    option = st.radio("Choose an action", ["Store New Data", "Retrieve Data", "Logout"])
    if option == "Store New Data":
        insert_data_page()
    elif option == "Retrieve Data":
        retrieve_data_page()
    else:
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.success("Logged out successfully!")
        time.sleep(2)
        st.rerun()

# Main app logic
def main():
    # Load data at the start
    load_data()
    st.sidebar.title("Navigation")
    if not st.session_state.authenticated:
        page = st.sidebar.radio("Select page", ["Login", "Register"])
        if page == "Login":
            login_page()
        else:
            register_page()
    else:
        home_page()

if __name__ == "__main__":
    main()