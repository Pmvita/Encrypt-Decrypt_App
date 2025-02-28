# Encryption/Decryption Application

A simple GUI application for encrypting and decrypting text using Fernet symmetric encryption.

## Features

- Encrypt text with a password
- Decrypt text with the same password
- Copy encrypted/decrypted text to clipboard
- Save encrypted/decrypted text to a file
- Load text from a file

## Requirements

- Python 3.6+
- cryptography package

## Installation

1. Clone this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the application:
```
python app.py
```

1. Enter the text you want to encrypt/decrypt in the input field
2. Enter a password (this will be used to generate the encryption key)
3. Click "Encrypt" or "Decrypt" button
4. The result will appear in the output field
5. Use the "Copy" button to copy the result to clipboard
6. Use "Save" to save the result to a file
7. Use "Load" to load text from a file

## How it works

This application uses Fernet symmetric encryption from the cryptography package. The password you provide is used to generate a key for encryption and decryption. 