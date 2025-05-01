import streamlit as st
import hashlib
import json
import time
import os
from cryptography.fernet import Fernet
import base64
import secrets

# --------- Constants ---------
USERS_FILE = "users.json"
DATA_FILE = "data.json"
LOCKOUT_TIME = 60  # seconds (after 3 failed attempts)

# --------- Utilities ---------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file)

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return base64.b64encode(pwd_hash).decode(), salt

def verify_password(password, stored_hash, salt):
    new_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(new_hash, stored_hash)

def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_data(text, password):
    key = generate_key(password)
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text.decode()

def decrypt_data(encrypted_text, password):
    key = generate_key(password)
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
    return decrypted_text.decode()

# --------- Session States Initialization ---------
if 'page' not in st.session_state:
    st.session_state.page = "login"
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None
if 'user' not in st.session_state:
    st.session_state.user = None

# --------- Pages ---------
def signup():
    st.title("Sign Up")
    users = load_users()
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if email in users:
            st.error("User already exists.")
        else:
            pwd_hash, salt = hash_password(password)
            users[email] = {"password": pwd_hash, "salt": salt}
            save_users(users)
            st.success("Account created! Please login now.")
            st.session_state.page = "login"

def login():
    st.title("Login")
    users = load_users()

    # Check if locked out
    if st.session_state.lockout_time:
        if time.time() - st.session_state.lockout_time < LOCKOUT_TIME:
            remaining = LOCKOUT_TIME - int(time.time() - st.session_state.lockout_time)
            st.error(f"Locked out due to too many attempts. Try again in {remaining} seconds.")
            return
        else:
            st.session_state.login_attempts = 0
            st.session_state.lockout_time = None

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = users.get(email)
        if user and verify_password(password, user["password"], user["salt"]):
            st.success("Login successful!")
            st.session_state.user = email
            st.session_state.page = "home"
        else:
            st.error("Invalid credentials.")
            st.session_state.login_attempts += 1
            if st.session_state.login_attempts >= 3:
                st.session_state.lockout_time = time.time()

    st.info("Don't have an account? Click below to Sign up.")
    if st.button("Go to Sign Up"):
        st.session_state.page = "signup"

def home():
    st.title(f"Welcome {st.session_state.user}!")
    choice = st.selectbox("Choose an action", ["Insert Data", "Retrieve Data", "Logout"])
    if choice == "Insert Data":
        insert_data()
    elif choice == "Retrieve Data":
        retrieve_data()
    elif choice == "Logout":
        st.session_state.page = "login"
        st.session_state.user = None

def insert_data():
    st.header("Insert Data")
    data = load_data()
    user_data = data.get(st.session_state.user, {})

    text = st.text_area("Enter your secret text")
    passkey = st.text_input("Set a passkey for this data", type="password")

    if st.button("Store Data"):
        encrypted_text = encrypt_data(text, passkey)
        data_key = f"data_{len(user_data)+1}"

        user_data[data_key] = {
            "encrypted_text": encrypted_text
        }
        data[st.session_state.user] = user_data
        save_data(data)
        st.success(f"Data stored with key: {data_key}")

def retrieve_data():
    st.header("Retrieve Data")
    data = load_data()
    user_data = data.get(st.session_state.user, {})

    if not user_data:
        st.warning("No data found.")
        return

    key = st.text_input("Enter the data key (e.g., data_1)")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve"):
        record = user_data.get(key)
        if record:
            try:
                decrypted_text = decrypt_data(record["encrypted_text"], passkey)
                st.success("Data Decrypted Successfully!")
                st.write(decrypted_text)
            except Exception:
                st.error("Incorrect passkey.")
        else:
            st.error("Invalid data key.")

# --------- Main ---------
def main():
    if st.session_state.page == "signup":
        signup()
    elif st.session_state.page == "login":
        login()
    elif st.session_state.page == "home":
        home()

if __name__ == "__main__":
    main()
