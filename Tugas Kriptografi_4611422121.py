import tkinter as tk
from tkinter import filedialog, messagebox

# Function to compute modular inverse
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# Function to multiply a 3x3 matrix by a 3x1 vector
def matrix_vector_multiply(matrix, vector):
    return [
        (matrix[0][0] * vector[0] + matrix[0][1] * vector[1] + matrix[0][2] * vector[2]) % 26,
        (matrix[1][0] * vector[0] + matrix[1][1] * vector[1] + matrix[1][2] * vector[2]) % 26,
        (matrix[2][0] * vector[0] + matrix[2][1] * vector[1] + matrix[2][2] * vector[2]) % 26
    ]

# Hill cipher encryption function (for 3x3 matrix)
def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.replace(" ", "").upper()
    if len(plaintext) % 3 != 0:
        # Padding with 'X' to make length a multiple of 3
        plaintext += 'X' * (3 - len(plaintext) % 3)

    encrypted = ""
    for i in range(0, len(plaintext), 3):
        vector = [ord(plaintext[i]) - ord('A'), ord(plaintext[i + 1]) - ord('A'), ord(plaintext[i + 2]) - ord('A')]
        encrypted_vector = matrix_vector_multiply(key_matrix, vector)
        encrypted += chr(encrypted_vector[0] + ord('A')) + chr(encrypted_vector[1] + ord('A')) + chr(encrypted_vector[2] + ord('A'))

    return encrypted

# Hill cipher decryption function (for 3x3 matrix)
def hill_decrypt(ciphertext, key_matrix):
    determinant = (key_matrix[0][0] * (key_matrix[1][1] * key_matrix[2][2] - key_matrix[1][2] * key_matrix[2][1]) -
                   key_matrix[0][1] * (key_matrix[1][0] * key_matrix[2][2] - key_matrix[1][2] * key_matrix[2][0]) +
                   key_matrix[0][2] * (key_matrix[1][0] * key_matrix[2][1] - key_matrix[1][1] * key_matrix[2][0])) % 26
    determinant_inv = mod_inverse(determinant, 26)

    if determinant_inv is None:
        raise ValueError("Key matrix is not invertible under modulo 26")

    inv_key_matrix = [
        [
            ((key_matrix[1][1] * key_matrix[2][2] - key_matrix[1][2] * key_matrix[2][1]) * determinant_inv) % 26,
            ((key_matrix[0][2] * key_matrix[2][1] - key_matrix[0][1] * key_matrix[2][2]) * determinant_inv) % 26,
            ((key_matrix[0][1] * key_matrix[1][2] - key_matrix[0][2] * key_matrix[1][1]) * determinant_inv) % 26
        ],
        [
            ((key_matrix[1][2] * key_matrix[2][0] - key_matrix[1][0] * key_matrix[2][2]) * determinant_inv) % 26,
            ((key_matrix[0][0] * key_matrix[2][2] - key_matrix[0][2] * key_matrix[2][0]) * determinant_inv) % 26,
            ((key_matrix[0][2] * key_matrix[1][0] - key_matrix[0][0] * key_matrix[1][2]) * determinant_inv) % 26
        ],
        [
            ((key_matrix[1][0] * key_matrix[2][1] - key_matrix[1][1] * key_matrix[2][0]) * determinant_inv) % 26,
            ((key_matrix[0][1] * key_matrix[2][0] - key_matrix[0][0] * key_matrix[2][1]) * determinant_inv) % 26,
            ((key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) * determinant_inv) % 26
        ]
    ]

    decrypted = ""
    for i in range(0, len(ciphertext), 3):
        vector = [ord(ciphertext[i]) - ord('A'), ord(ciphertext[i + 1]) - ord('A'), ord(ciphertext[i + 2]) - ord('A')]
        decrypted_vector = matrix_vector_multiply(inv_key_matrix, vector)
        decrypted += chr(decrypted_vector[0] + ord('A')) + chr(decrypted_vector[1] + ord('A')) + chr(decrypted_vector[2] + ord('A'))

    return decrypted

# Vigenere cipher function
def vigenere_cipher(text, key, encrypt=True):
    result = ""
    key = key.upper() * (len(text) // len(key)) + key.upper()[:len(text) % len(key)]
    for i in range(len(text)):
        if text[i].isalpha():
            shift = ord(key[i]) - ord('A')
            if not encrypt:
                shift = -shift
            if text[i].isupper():
                result += chr((ord(text[i]) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += chr((ord(text[i]) - ord('a') + shift) % 26 + ord('a'))
        else:
            result += text[i]
    return result

# Playfair cipher function
def playfair_cipher(text, key, encrypt=True):
    key = ''.join(sorted(set(key), key=lambda x: key.index(x))).upper()
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in key:
            key += char
    key_matrix = [key[i:i+5] for i in range(0, len(key), 5)]

    def prepare_text(plain_text):
        plain_text = plain_text.replace("J", "I").upper()
        processed = ""
        i = 0
        while i < len(plain_text):
            if i == len(plain_text) - 1 or plain_text[i] == plain_text[i + 1]:
                processed += plain_text[i] + 'X'
                i += 1
            else:
                processed += plain_text[i] + plain_text[i + 1]
                i += 2
        return processed

    def encrypt_decrypt_pairs(pair, encrypt):
        row1, col1 = divmod(key.index(pair[0]), 5)
        row2, col2 = divmod(key.index(pair[1]), 5)

        if row1 == row2:
            return key[row1 * 5 + (col1 + (1 if encrypt else -1)) % 5] + key[row2 * 5 + (col2 + (1 if encrypt else -1)) % 5]
        elif col1 == col2:
            return key[((row1 + (1 if encrypt else -1)) % 5) * 5 + col1] + key[((row2 + (1 if encrypt else -1)) % 5) * 5 + col2]
        else:
            return key[row1 * 5 + col2] + key[row2 * 5 + col1]

    text = prepare_text(text)
    result = ""
    for i in range(0, len(text), 2):
        result += encrypt_decrypt_pairs(text[i:i + 2], encrypt)
    return result

# File upload function
def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filepath:
        try:
            with open(filepath, 'r') as file:
                input_text.delete("1.0", tk.END)
                input_text.insert(tk.END, file.read())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

# Process text for encryption/decryption
def process_text():
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get()

    if len(key.split(",")) != 12 and cipher_type.get() == "Hill":
        messagebox.showerror("Error", "Hill cipher key must contain exactly 12 integers.")
        return

    try:
        if cipher_type.get() == "Vigenere":
            output = vigenere_cipher(text, key, encrypt=(encrypt_var.get() == 1))

        elif cipher_type.get() == "Playfair":
            output = playfair_cipher(text, key, encrypt=(encrypt_var.get() == 1))

        elif cipher_type.get() == "Hill":
            key_matrix = [int(num) for num in key.split(",")]
            key_matrix = [key_matrix[:3], key_matrix[3:6], key_matrix[6:9]]  # Use the first 9 integers for a 3x3 matrix
            if encrypt_var.get() == 1:
                output = hill_encrypt(text, key_matrix)
            else:
                output = hill_decrypt(text, key_matrix)

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, output)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Setup GUI
root = tk.Tk()
root.title("Cryptography Project")

# Input text area
input_text = tk.Text(root, height=10, width=50)
input_text.pack()

# Key entry
key_entry = tk.Entry(root, width=50)
key_entry.pack()

# Cipher type selection
cipher_type = tk.StringVar(value="Vigenere")
tk.Radiobutton(root, text="Vigenere Cipher", variable=cipher_type, value="Vigenere").pack()
tk.Radiobutton(root, text="Playfair Cipher", variable=cipher_type, value="Playfair").pack()
tk.Radiobutton(root, text="Hill Cipher", variable=cipher_type, value="Hill").pack()

# Encrypt/Decrypt option
encrypt_var = tk.IntVar(value=1)
tk.Radiobutton(root, text="Encrypt", variable=encrypt_var, value=1).pack()
tk.Radiobutton(root, text="Decrypt", variable=encrypt_var, value=0).pack()

# File upload button
tk.Button(root, text="Upload File", command=upload_file).pack()
tk.Button(root, text="Process", command=process_text).pack()

# Output text area
output_text = tk.Text(root, height=10, width=50)
output_text.pack()

root.mainloop()
