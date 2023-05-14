import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Protocol.KDF import PBKDF2
import base64


def encrypt_text():
    plaintext = input_text.get("1.0", "end-1c")
    key = key_entry.get()
    key = key.encode()
    salt = b'\x00' * AES.block_size
    key = PBKDF2(key, salt, dkLen=32, count=1000)
    plaintext = plaintext.encode()
    ciphertext = encrypt(plaintext, key)
    ciphertext = ciphertext.decode()
    input_text.delete("1.0", tk.END)
    input_text.insert(tk.END, ciphertext)
    print("Plaintext: ", plaintext.decode())
    print("Key: ", key.hex())
    print("Encrypted text: ", ciphertext)
    print("")
    return ciphertext


def decrypt_text():
    ciphertext = input_text.get("1.0", "end-1c")
    key = key_entry.get()
    key = key.encode()
    salt = b'\x00' * AES.block_size
    key = PBKDF2(key, salt, dkLen=32, count=1000)
    ciphertext = ciphertext.encode()
    plaintext = decrypt(ciphertext, key)
    plaintext = plaintext.decode()
    input_text.delete("1.0", tk.END)
    input_text.insert(tk.END, plaintext)
    print("Ciphertext: ", ciphertext.decode())
    print("Key: ", key.hex())
    print("Decrypted text: ", plaintext)
    print("")

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = Padding.pad(plaintext, 16)
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext)

def decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, 16)
    return plaintext

root = tk.Tk()
root.title("Cool Cypher")
root.configure(bg='#1c1c1c')
root.geometry("400x450")

for i in range(3):
    root.grid_columnconfigure(i, weight=1, minsize=100)
    root.grid_rowconfigure(i, weight=1, minsize=100)

input_text = tk.Text(root, bg='#1c1c1c',fg='white')
input_text.grid(row=0, column=0, columnspan=3, padx=5, pady=5,sticky='nsew')

key_label = tk.Label(root, text="Enter key:", bg='#1c1c1c',fg='white')
key_label.grid(row=1, column=0, padx=5, pady=5,sticky='nsew')
key_entry = tk.Entry(root, bg='#1c1c1c',fg='white')
key_entry.grid(row=1, column=1, columnspan=2,padx=5, pady=5,sticky='nsew')

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text, bg='#1c1c1c',fg='white')
encrypt_button.grid(row=2, column=0, padx=5, pady=5,sticky='nsew')
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text, bg='#1c1c1c',fg='white')
decrypt_button.grid(row=2, column=1, padx=5, pady=5,sticky='nsew')

root.mainloop()