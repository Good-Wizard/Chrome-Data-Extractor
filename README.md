# Chrome Data Extractor
#### This Python script is designed to extract sensitive data from Google Chrome, including saved passwords, cookies, and browsing history. It utilizes various libraries to access and decrypt the data stored in Chrome's SQLite databases.

# Key Features:
## Password Extraction:
### The extract_passwords() function retrieves saved passwords from Chrome's login database. It does this by:
#### Accessing the Chrome Local State file to obtain the encryption key.
#### Connecting to the SQLite database that stores login credentials.
#### Decrypting the passwords using the AES encryption algorithm.
#### Saving the decrypted passwords in a text file (decrypted_passwords.txt) in a readable format.
## Cookie Extraction:
### The extract_cookies() function extracts cookies from Chrome's cookie database. It performs the following steps:
#### Unlocks the cookie database file to allow access.
#### Copies the cookie database to a temporary file.
#### Queries the database to retrieve cookie information (host, name, value, path, expiration, last access time, and security status).
#### Saves the extracted cookies in a JSON file (chrome_cookies.txt).
## Browsing History Extraction:
### The script also extracts browsing history from Chrome. It does this by:
#### Copying the history database to a temporary file.
#### Querying the database for URLs, titles, visit counts, and last visit times.
#### Converting Chrome's internal timestamp format to a human-readable format.
#### Saving the extracted history in a text file (chrome_history.txt).
## Error Handling:
#### The script includes error handling to manage exceptions that may arise during file access, database connections, and decryption processes. It provides informative error messages to the user.
## Cross-Platform Compatibility:
#### While primarily designed for Windows, the script can be adapted for other operating systems with minor modifications.
# Usage:
#### To run the script, ensure you have the required libraries installed (psutil, Cryptodome, and any others as needed).
#### Execute the script in a Python environment. It will extract passwords, cookies, and browsing history from Google Chrome and save them to the specified output files.
# Important Note:
#### This script is intended for educational purposes only. Unauthorized access to personal data, including passwords and cookies, is illegal and unethical. Always ensure you have permission to extract data from any system or user account.
