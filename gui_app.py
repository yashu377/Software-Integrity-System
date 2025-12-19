import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# ---------------------------
# Helper Functions
# ---------------------------

def select_file():
    file_path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, file_path)

def verify_file():
    file_path = entry_file.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file first.")
        return

    try:
        # Read file
        with open(file_path, "rb") as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).digest()

        # Load public key
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        # Load signature
        with open("signature.sig", "rb") as sig_file:
            signature = sig_file.read()

        # Verify
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "✅ File integrity is intact!")
    except FileNotFoundError:
        messagebox.showerror("Error", "Signature or public key not found!")
    except InvalidSignature:
        messagebox.showerror("Error", "❌ File may have been modified or tampered with.")

# ---------------------------
# GUI Layout
# ---------------------------

root = tk.Tk()
root.title("Software Integrity Verification")
root.geometry("500x200")

tk.Label(root, text="Select File to Verify:").pack(pady=10)
entry_file = tk.Entry(root, width=60)
entry_file.pack()
tk.Button(root, text="Browse", command=select_file).pack(pady=5)
tk.Button(root, text="Verify File", command=verify_file).pack(pady=20)

root.mainloop()
