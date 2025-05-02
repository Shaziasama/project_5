#develop a streamlit based secure data storage and retrieval system 

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

from base64 import  urlsafe_b64encode
from hashlib import pbkdf2_hmac

# data information of users
DATA_FILE = "secured_data.json"
SALT = b'secure_salt-value'
LOCKOUT_DURATION = 60

# section login details
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

    # if data is load
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            return json.load(file)
    
        return {}
    
def save_data(data):
    with open(DATA_FILE, 'w') as file:
        json.dump(data, file)


def generate_key(passkey):
    # Generate a key using PBKDF2 and the provided password
    key = (pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000))
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# cryptography.fernet used
def encrypt_text(text, key):
    cipher = Fernet(key)
    return  cipher.encrypted_text(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()

# navigation bar
st.sidebar.title("🔐 Secure Data Encryption System")
menu = [" Home, Login", "Register", "Store Data", "Retrieve Data"]
choice =st.sidebar.selectbox("Select an option", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System")
    st.markdown("This system allows you to securely store and retrieve sensitive data.")
    
    st.write("Please log in or register to get started.")

elif choice == "Register":
    st.subheader(" 🗄️Register a New user")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Register"):
        if username and password:
            hashed_password = hash_password(password)
            stored_data[username] = hashed_password
            save_data(stored_data)
            st.success("User registered successfully!")
        else:
            st.error("Please enter both username and password.")
        
    elif choice == "Login":
        st.subheader("🔑 User Login")
    
        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f" ⏱️Too many failed attempts. Please wait {remaining} seconds.")
            st.stop()

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
                
                if username in stored_data and stored_data[username]["pasword"] == hash_password(password):
                    st.session_state.authenticated_user = username
                
                    st.session_state.failed_attempts = 0
                    st.success(f" ✅Welcome {username}!")
                else:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = 3 - st.session_state.failed_attempts
                    st.error(f" ❌Invalid credentials! Attempt left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                        st.error(f" 🛑Too many failed attempts. Locked for 60 seconds.")
                        st.stop()



    elif choice == "Store Data":
        if not st.session_state.authenticated_user:
            st.warning("Please login to store data.")
        else:st.subheader("🔒 Store Encrypted Data")
        data = st.text_area("Enter data to store")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt And Save"):
            if data and passkey:
                
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success(f" ✅Data encrypted and saved successfully!")
            

            else:
                st.error("Please enter both data and passkey")

    elif choice == "Retrieve Data":
        if not st.session_state.authenticated_user:
            st.warning("Please login first ")
        else:
            st.subheader("🔑 Retrieve Data")
            user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
            if not user_data:
                st.info("No data found!")
            else:
                st.write("Encrypted Data Enteries:")
                for i, item in enumerate(user_data):
                    st.code(item, language="text")

                    encrypt_input = st.text_input("Enter the Encrypted Text")
                    passkey = st.text_input("Enter passkey to Descrpt", type="password")
                    if st.button("Decrypt"):
                        result = decrypt_text(encrypt_input, passkey)
                        if result:
                            st.success(f" ✅Decrypted Data: {result}")
                        else:
                            st.error(" ❌Invalid passkey or corrupted data.")

        




            
        
                