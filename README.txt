Two-Factor Authentication System with Google Authenticator
Overview

This project implements a simple two-factor authentication (2FA) system using bcrypt for password hashing and pyotp for generating time-based one-time passwords (TOTP) that can be integrated with the Google Authenticator app. The system stores user credentials (username, password hash, and MFA secret) in a SQLite database and generates a QR code for easy registration of the MFA secret in Google Authenticator.
Features

    Password Hashing: Securely hashes passwords using bcrypt.
    Multi-Factor Authentication (MFA): Uses pyotp to generate TOTP codes compatible with Google Authenticator.
    QR Code Generation: Generates a QR code to easily configure MFA in Google Authenticator.
    SQLite Database Integration: Stores user credentials securely in an SQLite database.
    Authentication: Verifies users by checking their password and MFA code during login.

Requirements

Make sure you have the following dependencies installed:

bash

pip install bcrypt pyotp qrcode[pil] Pillow

These libraries provide:

    bcrypt: Password hashing and verification.
    pyotp: Generating TOTP secrets and verifying codes.
    qrcode: Generating QR codes for MFA secret provisioning.
    Pillow: Used for displaying the generated QR code.

How It Works
1. User Registration

When a user is registered:

    The system checks if the username already exists.
        If the user exists, it updates their password and generates a new MFA secret.
        If the user doesn't exist, it creates a new record with a hashed password and an MFA secret.
    The system generates a QR code containing the MFA secret in a format compatible with Google Authenticator.
    The QR code is saved as an image and displayed, allowing the user to scan it with Google Authenticator to enable 2FA.

2. User Authentication

During login:

    The system retrieves the stored password hash and MFA secret from the database.
    It verifies the provided password using bcrypt.
    It verifies the TOTP code generated by Google Authenticator using pyotp.

Database Schema

The system uses a simple SQLite database schema for storing user information:
Field	      Type	Description
username	  TEXT	The unique username of the user (Primary Key)
password_hash TEXT	The hashed password (using bcrypt)
mfa_secret	  TEXT	The Base32 encoded secret for TOTP generation
QR Code for Google Authenticator

The system generates a QR code that encodes a URL in the following format:

ruby

otpauth://totp/<Issuer>:<Username>?secret=<MFASecret>&issuer=<Issuer>

Where:

    <Issuer> is the name of your app or service (e.g., "MyApp").
    <Username> is the user's username.
    <MFASecret> is the secret used for generating TOTP codes.

This URL can be scanned by Google Authenticator to automatically configure 2FA.
Usage
Registering a New User

To register a new user, call the register_user function:

python

register_user('test_user', 'new_secure_password')

This will:

    Hash the password.
    Generate a new MFA secret.
    Store these in the SQLite database.
    Generate a QR code image and display it for scanning with Google Authenticator.

Authenticating a User

To authenticate a user, call the authenticate_user function with the username, password, and TOTP code provided by Google Authenticator:

python

otp_code = input("Enter the TOTP code from Google Authenticator: ")
authenticate_user('test_user', 'new_secure_password', otp_code)

This will:

    Verify the password using bcrypt.
    Verify the TOTP code using the MFA secret stored in the database.
    Confirm if authentication is successful or not.

Example

The following steps show a full user registration and login process:

    Register the user:

    python

register_user('test_user', 'new_secure_password')

Login with the username, password, and TOTP code:

python

    otp_code = input("Enter the TOTP code from Google Authenticator: ")
    authenticate_user('test_user', 'new_secure_password', otp_code)

Important Notes

    Ensure your system's time is synchronized with the internet for accurate TOTP verification.
    Always store passwords securely using hashing algorithms like bcrypt.
    TOTP secrets should be stored securely as they are critical for MFA.

License

This project is open-source and available for anyone to use and modify.
