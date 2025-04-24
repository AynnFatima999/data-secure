import streamlit as st
import json
import hashlib
import base64
import os
import time
from cryptography.fernet import Fernet

# ---------- Helpers ----------
def save_data_to_file(data, filename="data.json"):
    with open(filename, "w") as f:
        json.dump(data, f)

def load_data_from_file(filename="data.json"):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def hash_passkey_pbkdf2(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.b64encode(key).decode(), base64.b64encode(salt).decode()

def generate_cipher_key():
    return Fernet.generate_key()

def encrypt_text(text, key):
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt_text(ciphertext, key):
    return Fernet(key).decrypt(ciphertext.encode()).decode()

# ---------- Global State ----------
stored_data = load_data_from_file()
failed_attempts_info = {}
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 60

# ---------- Auth Logic ----------
def is_locked_out(username):
    info = failed_attempts_info.get(username)
    if info and info["count"] >= MAX_ATTEMPTS:
        if time.time() - info["last_attempt"] < LOCKOUT_DURATION:
            return True
    return False

def register_failed_attempt(username):
    if username not in failed_attempts_info:
        failed_attempts_info[username] = {"count": 1, "last_attempt": time.time()}
    else:
        failed_attempts_info[username]["count"] += 1
        failed_attempts_info[username]["last_attempt"] = time.time()

# ---------- Streamlit Pages ----------
def login_page():
    st.title("🔐 Login Page")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        if is_locked_out(username):
            st.error("Too many failed attempts. Please wait and try again later.")
            return

        user = stored_data.get(username)
        if user:
            salt = base64.b64decode(user["salt"])
            hashed_input, _ = hash_passkey_pbkdf2(passkey, salt)
            if hashed_input == user["hashed_passkey"]:
                st.session_state["user"] = username
                st.success("Login successful!")
            else:
                register_failed_attempt(username)
                st.error("Invalid passkey")
        else:
            st.error("User not found")

def store_data_page():
    st.title("📥 Store Data")
    username = st.text_input("Choose a username")
    text = st.text_area("Enter your text")
    passkey = st.text_input("Choose a passkey", type="password")

    if st.button("Store"):
        if username in stored_data:
            st.error("Username already exists. Please login to update.")
            return
        hashed_passkey, salt = hash_passkey_pbkdf2(passkey)
        cipher_key = generate_cipher_key()
        encrypted_text = encrypt_text(text, cipher_key)
        
        stored_data[username] = {
            "hashed_passkey": hashed_passkey,
            "salt": salt,
            "encrypted_text": encrypted_text,
            "cipher_key": cipher_key.decode()
        }
        save_data_to_file(stored_data)
        st.success("Data stored successfully!")

def retrieve_data_page():
    st.title("📤 Retrieve Data")
    if "user" not in st.session_state:
        st.warning("Please log in to view your data.")
        login_page()
        return

    username = st.session_state["user"]
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        user = stored_data.get(username)
        if not user:
            st.error("User not found")
            return

        salt = base64.b64decode(user["salt"])
        hashed_input, _ = hash_passkey_pbkdf2(passkey, salt)

        if hashed_input == user["hashed_passkey"]:
            decrypted = decrypt_text(user["encrypted_text"], user["cipher_key"].encode())
            st.success("Decrypted Data:")
            st.code(decrypted)
        else:
            register_failed_attempt(username)
            st.error("Invalid passkey")

# ---------- Main UI ----------
def main():
    st.sidebar.title("🔐 Secure Data System")
    page = st.sidebar.selectbox("Choose a page", ["Home", "Login", "Store Data", "Retrieve Data"])

    if page == "Login":
        login_page()
    elif page == "Store Data":
        store_data_page()
    elif page == "Retrieve Data":
        retrieve_data_page()
    else:
        st.title("Welcome to Secure Data Vault")
        st.write("Choose an option from the sidebar to get started.")

if __name__ == "__main__":
    main()

