import bcrypt
import pyotp
import secrets
import sqlite3
import qrcode
from PIL import Image  # To display the QR code

# Initialize database connection
conn = sqlite3.connect('auth_system.db')
cursor = conn.cursor()

# Create a table for users if it doesn't already exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT,
        mfa_secret TEXT
    )
''')
conn.commit()

def register_user(username, password):
    # Check if the username already exists
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        print(f"Username '{username}' already exists. Updating the password and MFA secret...")
        
        # Hash the new password and generate a new MFA secret (Base32 encoded)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        mfa_secret = pyotp.random_base32()  # Base32 encoded secret required for Google Authenticator
        
        # Update the existing user's record
        cursor.execute('UPDATE users SET password_hash = ?, mfa_secret = ? WHERE username = ?', 
                       (password_hash, mfa_secret, username))
        conn.commit()

        # Generate the provisioning URI for Google Authenticator with correct format
        totp = pyotp.TOTP(mfa_secret)
        totp_uri = totp.provisioning_uri(name=username, issuer_name="MyApp")
        
        # Generate the QR code
        qr = qrcode.make(totp_uri)
        qr.save(f"{username}_mfa_qrcode.png")
        
        # Open the QR code image so it can be scanned
        img = Image.open(f"{username}_mfa_qrcode.png")
        img.show()
        
        print(f"QR code saved as '{username}_mfa_qrcode.png'. Scan this image with Google Authenticator.")
        
        return True

    # If the username does not exist, proceed with new user registration
    # Hash the password with bcrypt (includes salt)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate a random MFA secret using the pyotp Base32 secret generator
    mfa_secret = pyotp.random_base32()  # Google Authenticator requires Base32-encoded secret

    # Store the username, password hash, and MFA secret in the database
    cursor.execute('INSERT INTO users (username, password_hash, mfa_secret) VALUES (?, ?, ?)', 
                   (username, password_hash, mfa_secret))
    conn.commit()

    # Generate the provisioning URI for Google Authenticator with correct format
    totp = pyotp.TOTP(mfa_secret)
    totp_uri = totp.provisioning_uri(name=username, issuer_name="MyApp")

    # Create a QR code from the provisioning URI
    qr = qrcode.make(totp_uri)

    # Save the QR code as an image file
    qr.save(f"{username}_mfa_qrcode.png")
    
    # Open the QR code image so it can be scanned
    img = Image.open(f"{username}_mfa_qrcode.png")
    img.show()

    print(f"QR code saved as '{username}_mfa_qrcode.png'. Scan this image with Google Authenticator.")
    
    return True

def authenticate_user(username, password, otp_code):
    # Retrieve the stored password hash and MFA secret from the database
    cursor.execute('SELECT password_hash, mfa_secret FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    
    if result is None:
        print("User not found!")
        return False
    
    stored_password_hash, mfa_secret = result
    
    # Verify the password
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
        print("Invalid password!")
        return False

    # Verify the TOTP (Google Authenticator) code
    totp = pyotp.TOTP(mfa_secret)
    if not totp.verify(otp_code):
        print("Invalid TOTP code!")
        return False
    
    print("Authentication successful!")
    return True

# Example registration and login process
if __name__ == "__main__":
    # Step 1: Register a new user (or update existing user)
    print("Registering a new user or updating existing user...")
    register_user('test_user', 'new_secure_password')

    # Step 2: Simulate login with the correct password and TOTP
    print("\nSimulating login...")
    otp_code = input("Enter the TOTP code from Google Authenticator: ")
    authenticate_user('test_user', 'new_secure_password', otp_code)
