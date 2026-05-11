import streamlit as st
import secrets
import pyperclip
import bcrypt
import re
from win10toast import ToastNotifier
import mysql.connector

# Load rockyou.txt into memory
def load_rockyou():
    try:
        with open("./rockyou.txt", "r", encoding="latin-1") as file:
            return set(file.read().splitlines())
    except FileNotFoundError:
        st.error("rockyou.txt file not found! Ensure it is in the same directory as the script.")
        return set()

breached_passwords = load_rockyou()

# MySQL Database Connection
try:
    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root"
    )
    dbcursor = mydb.cursor()
    dbcursor.execute('CREATE DATABASE IF NOT EXISTS password_manager')
    mydb.database = 'password_manager'
    dbcursor.execute(
        'CREATE TABLE IF NOT EXISTS accounts (email VARCHAR(80), password TEXT, username VARCHAR(80), url VARCHAR(80) PRIMARY KEY)'
    )
except mysql.connector.Error as err:
    st.error(f"Database Error: {err}")
    st.stop()
except ModuleNotFoundError as e:
    st.error(f"Dependency Missing: {e}. Please install the required modules.")
    st.stop()

# Password components
UPPER_CASE_ALPHABETS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LOWER_CASE_ALPHABETS = 'abcdefghijklmnopqrstuvwxyz'
SPECIAL_CHARACTERS = '~`!@#$%^&*()_-+={[}]|\\:;<,>.?/'
NUMERICAL_CHARACTERS = '0123456789'

# Function to validate email
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Password hashing functions
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# Streamlit UI
st.title("Password Manager with Breach Detection and Security Features")

# Password Generator
st.header("Password Generator")
var_uppercase = st.checkbox("Include Uppercase Alphabets")
var_special = st.checkbox("Include Special Characters")
var_numerical = st.checkbox("Include Numerical Characters")
password_length = st.slider("Password Length", 8, 32, 12)

def generate_password():
    res_password = ''
    while len(res_password) < password_length:
        if var_uppercase:
            res_password += secrets.choice(UPPER_CASE_ALPHABETS)
        if var_special:
            res_password += secrets.choice(SPECIAL_CHARACTERS)
        if var_numerical:
            res_password += secrets.choice(NUMERICAL_CHARACTERS)
        res_password += secrets.choice(LOWER_CASE_ALPHABETS)
    candidate_password = res_password[:password_length]
    # Check against breached passwords
    if candidate_password in breached_passwords:
        st.warning("Generated password found in breach list. Generating a new one.")
        return generate_password()
    return candidate_password

if st.button("Generate Password"):
    resultant_password = generate_password()
    st.write(f"Generated Password: {resultant_password}")
    pyperclip.copy(resultant_password)
    st.success("Password copied to clipboard!")

# Password Manager
st.header("Password Manager")
with st.form("password_form"):
    email = st.text_input("Email")
    username = st.text_input("Username")
    url = st.text_input("URL / App Name")
    show_password = st.checkbox("Show Password")
    password_input_type = "text" if show_password else "password"
    password = st.text_input("Password", type=password_input_type)
    submitted = st.form_submit_button("Save Data")

if submitted:
    if not validate_email(email):
        st.error("Invalid email format.")
    elif len(password) < 8:
        st.error("Password must be at least 8 characters long.")
    elif password in breached_passwords:
        st.error("This password has previously appeared in a data breach and should never be used. If you've ever used it anywhere before, change it!")
    else:
        hashed_password = hash_password(password)
        try:
            dbcursor.execute(
                'INSERT INTO accounts (email, password, username, url) VALUES (%s, %s, %s, %s)',
                (email, hashed_password, username, url)
            )
            mydb.commit()
            st.success("Data Saved Successfully!")
        except mysql.connector.errors.IntegrityError:
            st.error("Data Save was Unsuccessful! Duplicate URL/App name.")

# Retrieve Password
st.header("Retrieve Password")
url_to_retrieve = st.text_input("Enter URL / App Name to Retrieve Password")

if st.button("Get Password"):
    dbcursor.execute('SELECT password FROM accounts WHERE url = %s', (url_to_retrieve,))
    result = dbcursor.fetchone()
    if result:
        hashed_password = result[0]
        st.write("Password retrieved, but it's stored securely. Please update your records.")
    else:
        st.error("Record Not Found!")


# Show All Passwords
st.header("Show All Passwords")
search_query = st.text_input("Search by URL / App Name")
sort_order = st.selectbox("Sort by", ["Email", "Username", "URL"])

if st.button("Show All Passwords"):
    query = "SELECT * FROM accounts"
    if search_query:
        query += f" WHERE url LIKE '%{search_query}%'"
    if sort_order:
        query += f" ORDER BY {sort_order.lower()}"
    dbcursor.execute(query)
    all_pwds = dbcursor.fetchall()
    if all_pwds:
        for pwd in all_pwds:
            st.write(f"Email: {pwd[0]}")
            st.write(f"Username: {pwd[2]}")
            st.write(f"URL: {pwd[3]}")
            st.write("---")
    else:
        st.warning("No passwords stored yet.")
