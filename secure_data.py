import streamlit as st
import hashlib
import json
import os
import time
import base64

from cryptography.fernet import Fernet

# ----------------------------- CONFIGURATION -----------------------------
DATA_FILE = "data_store.json"
SESSION_TIMEOUT = 60  # seconds
MAX_ATTEMPTS = 3
LOGIN_CREDENTIAL = {"username": "admin", "password": "admin123"}

# ----------------------------- SECURITY UTILS -----------------------------
def generate_key():
    return Fernet.generate_key()

def get_cipher(passkey: str):
    # Hash the passkey to generate a Fernet key
    hashed = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(hashed[:32]))

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    cipher = get_cipher(passkey)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(ciphertext, passkey):
    cipher = get_cipher(passkey)
    return cipher.decrypt(ciphertext.encode()).decode()

# ----------------------------- DATA UTILS -----------------------------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# ----------------------------- APP STATE -----------------------------
if "data" not in st.session_state:
    st.session_state.data = load_data()
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "locked_until" not in st.session_state:
    st.session_state.locked_until = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = False

# ----------------------------- LOGIN PAGE -----------------------------
def login_page():
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == LOGIN_CREDENTIAL["username"] and password == LOGIN_CREDENTIAL["password"]:
            st.success("Login successful")
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = 0
            st.session_state.authorized = True
        else:
            st.error("Invalid credentials")

# ----------------------------- HOME PAGE -----------------------------


def home_page():
    st.title("🛡️ Secure Data Storage")
    st.write("Choose an action:")
    if st.button("🔐 Store New Data"):
        insert_data_page()
    if st.button("🔓 Retrieve Stored Data"):
        retrieve_data_page()

# ----------------------------- INSERT DATA -----------------------------
def insert_data_page():
    st.title("🔐 Store New Data")
    username = st.text_input("Enter Username")
    text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Encrypt and Store"):
        if username and text and passkey:
            encrypted = encrypt_data(text, passkey)
            st.session_state.data[username] = {
                "encrypted_text": encrypted,
                "passkey_hash": hash_passkey(passkey)
            }
            save_data(st.session_state.data)
            st.success("Data stored successfully!")
        else:
            st.error("All fields are required.")

# ----------------------------- RETRIEVE DATA -----------------------------
def retrieve_data_page():
    if time.time() < st.session_state.locked_until:
        st.warning("Too many attempts. Please try again later.")
        return

    st.title("🔓 Retrieve Data")
    username = st.text_input("Enter Username")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve"):
        user_data = st.session_state.data.get(username)
        if not user_data:
            st.error("No data found for this user.")
            return

        if hash_passkey(passkey) == user_data["passkey_hash"]:
            try:
                decrypted = decrypt_data(user_data["encrypted_text"], passkey)
                st.success(f"Decrypted data: {decrypted}")
                st.session_state.failed_attempts = 0
            except:
                st.error("Decryption failed.")
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Invalid passkey! Attempt {st.session_state.failed_attempts} of {MAX_ATTEMPTS}")

        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
            st.session_state.locked_until = time.time() + SESSION_TIMEOUT
            st.warning("Too many failed attempts. Redirecting to login.")
            st.session_state.authorized = False

# ----------------------------- MAIN ROUTING -----------------------------
def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Home", "Insert Data", "Retrieve Data", "Login"])

    if page == "Login":
        login_page()
    elif not st.session_state.authorized and st.session_state.failed_attempts >= MAX_ATTEMPTS:
        login_page()
    elif page == "Home":
        home_page()
    elif page == "Insert Data":
        insert_data_page()
    elif page == "Retrieve Data":
        retrieve_data_page()

main()
