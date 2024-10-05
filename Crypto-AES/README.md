# Crypto-AES

**Crypto-AES** is a simple Python application that allows users to encrypt and decrypt messages using AES with a 256-bit key. The program features a user-friendly graphical interface built with `tkinter`, enabling seamless encryption and decryption operations.

## Table of Contents

1. [Imports](#1-imports)
2. [GUI Components](#2-gui-components)
3. [Key Validation](#3-key-validation)
4. [Encryption Process (`encrypt_message` method)](#4-encryption-process-encrypt_message-method)
5. [Decryption Process (`decrypt_message` method)](#5-decryption-process-decrypt_message-method)
6. [How to Use the Program](#6-how-to-use-the-program)

---

## 1. Imports

The program utilizes several Python libraries to handle encryption, GUI creation, and data manipulation:

- **`tkinter`**: Used for creating the GUI components.
- **`messagebox`**: Provides pop-up dialog boxes for user notifications.
- **`cryptography.hazmat.primitives.ciphers`**: Provides AES cipher functionalities.
- **`cryptography.hazmat.primitives.padding`**: Handles padding of plaintext messages.
- **`os`**: Used for generating secure random bytes (IV).
- **`binascii`**: For converting between binary data and hexadecimal representation.

---

## 2. GUI Components

The graphical user interface is designed to be intuitive and straightforward:

- **Message Input**: An entry field where users can type the message they want to encrypt.
- **Key Input**: An entry field where users can input a 256-bit key in hexadecimal format. The key field is masked by default for security, with an option to show/hide the key.
- **Encrypt Button**: When clicked, it triggers the encryption process.
- **Decrypt Button**: When clicked, it triggers the decryption process.
- **Ciphertext Display**: An entry field that displays the encrypted message in hexadecimal format.

---

## 3. Key Validation

Ensuring the security and correctness of the encryption process involves validating the encryption key:

- The program expects the key to be a **64-character hexadecimal string** (representing 32 bytes or 256 bits).
- The `validate_key` method ensures:
  - **Length Check**: The key is exactly 64 hexadecimal characters long.
  - **Format Check**: The key contains only valid hexadecimal characters.
- If the key is invalid, an error message is displayed to the user.

---

## 4. Encryption Process (`encrypt_message` method)

The encryption process involves several critical steps to ensure data security:

1. **Input Retrieval**: Gets the plaintext message and the key from the input fields.
2. **Validation**: Checks if the message is not empty and the key is valid.
3. **Padding**: Pads the plaintext to make its length a multiple of the AES block size (16 bytes) using PKCS7 padding.
4. **IV Generation**: Generates a random 16-byte Initialization Vector (IV) using `os.urandom`.
5. **Cipher Creation**: Initializes the AES cipher in CBC mode with the provided key and generated IV.
6. **Encryption**: Encrypts the padded plaintext.
7. **Ciphertext Formation**: Prepends the IV to the ciphertext to ensure it can be used for decryption.
8. **Display**: Converts the ciphertext (including IV) to a hexadecimal string and displays it in the ciphertext field.

---

## 5. Decryption Process (`decrypt_message` method)

The decryption process reverses the encryption steps to retrieve the original message:

1. **Input Retrieval**: Gets the ciphertext (in hex) and the key from the input fields.
2. **Validation**: Checks if the ciphertext is not empty and the key is valid.
3. **Hex Conversion**: Converts the ciphertext from a hexadecimal string back to bytes.
4. **IV Extraction**: Extracts the first 16 bytes as the IV and the rest as the actual ciphertext.
5. **Cipher Creation**: Initializes the AES cipher in CBC mode with the provided key and extracted IV.
6. **Decryption**: Decrypts the ciphertext.
7. **Unpadding**: Removes the PKCS7 padding to retrieve the original plaintext.
8. **Display**: Shows the decrypted plaintext in a pop-up message box.


## 6. How to Use the Program

### Run the Program

```bash
python Crypto-AES.py
