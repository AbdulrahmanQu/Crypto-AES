import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import binascii

class CryptoAESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto-AES")

        # Initialize variables
        self.message_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.ciphertext_var = tk.StringVar()

        # Create and place widgets

        # Message Input
        tk.Label(root, text="Enter your message:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
        self.message_entry = tk.Entry(root, textvariable=self.message_var, width=50)
        self.message_entry.grid(row=0, column=1, padx=10, pady=10)

        # Key Input
        tk.Label(root, text="Enter 256-bit Key (64 hex chars):").grid(row=1, column=0, padx=10, pady=10, sticky='e')
        self.key_entry = tk.Entry(root, textvariable=self.key_var, width=50, show="*")
        self.key_entry.grid(row=1, column=1, padx=10, pady=10)

        # Encrypt and Decrypt Buttons
        tk.Button(root, text="Encrypt", command=self.encrypt_message, width=15).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt_message, width=15).grid(row=2, column=1, padx=10, pady=10)

        # Ciphertext Display
        tk.Label(root, text="Encrypted Message (Hex):").grid(row=3, column=0, padx=10, pady=10, sticky='e')
        self.ciphertext_entry = tk.Entry(root, textvariable=self.ciphertext_var, width=50)
        self.ciphertext_entry.grid(row=3, column=1, padx=10, pady=10)

        # Show/Hide Key Checkbox
        self.show_key = tk.BooleanVar()
        self.show_key_check = tk.Checkbutton(root, text="Show Key", variable=self.show_key, command=self.toggle_key_visibility)
        self.show_key_check.grid(row=1, column=2, padx=10, pady=10)

    def toggle_key_visibility(self):
        if self.show_key.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")

    def validate_key(self, key_hex):
        if len(key_hex) != 64:
            return False, "Key must be exactly 64 hexadecimal characters (256 bits)."
        try:
            key_bytes = binascii.unhexlify(key_hex)
            return True, key_bytes
        except binascii.Error:
            return False, "Key must be a valid hexadecimal string."

    def encrypt_message(self):
        message = self.message_var.get()
        key_hex = self.key_var.get()

        if not message:
            messagebox.showwarning("Input Error", "Please enter a message to encrypt.")
            return

        is_valid, key = self.validate_key(key_hex)
        if not is_valid:
            messagebox.showerror("Key Error", key)
            return

        try:
            ciphertext = self.aes_encrypt(key, message)
            self.ciphertext_var.set(binascii.hexlify(ciphertext).decode())
            messagebox.showinfo("Success", "Message encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during encryption: {e}")

    def decrypt_message(self):
        ciphertext_hex = self.ciphertext_var.get()
        key_hex = self.key_var.get()

        if not ciphertext_hex:
            messagebox.showwarning("Input Error", "Please enter the ciphertext to decrypt.")
            return

        is_valid, key = self.validate_key(key_hex)
        if not is_valid:
            messagebox.showerror("Key Error", key)
            return

        try:
            ciphertext = binascii.unhexlify(ciphertext_hex)
        except binascii.Error:
            messagebox.showerror("Ciphertext Error", "Ciphertext must be a valid hexadecimal string.")
            return

        try:
            plaintext = self.aes_decrypt(key, ciphertext)
            messagebox.showinfo("Decrypted Message", f"Decrypted Message:\n{plaintext}")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}")

    def aes_encrypt(self, key, plaintext):
        # Pad the plaintext to be a multiple of block size (16 bytes for AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        # Generate a random 16-byte IV
        iv = os.urandom(16)

        # Create Cipher object and encryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Prepend IV to ciphertext for use in decryption
        return iv + ciphertext

    def aes_decrypt(self, key, ciphertext):
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is too short. It must contain the IV and the encrypted data.")

        # Extract IV from the beginning
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]

        # Create Cipher object and decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext_bytes.decode()

def main():
    root = tk.Tk()
    app = CryptoAESApp(root)
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()