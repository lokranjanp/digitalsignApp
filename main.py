import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib

class DigitalSignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signer")

        self.upload_button = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_button.pack(pady=20)

        self.sign_button = tk.Button(root, text="Sign File", command=self.sign_file, state=tk.DISABLED)
        self.sign_button.pack(pady=20)

        self.verify_button = tk.Button(root, text="Verify File", command=self.verify_file, state=tk.DISABLED)
        self.verify_button.pack(pady=20)

        self.file_path = None
        self.signature = None
        self.private_key, self.public_key = self.generate_key_pair()

    def generate_key_pair(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        # Ask user for directory to save public key
        pub_key_path = filedialog.asksaveasfilename(defaultextension=".pem",
                                                    filetypes=[("PEM Files", "*.pem")],
                                                    title="Save Public Key As",
                                                    initialfile="public_key.pem")
        if pub_key_path:
            with open(pub_key_path, "wb") as pub_file:
                pub_file.write(public_key)
            messagebox.showinfo("Success", f"Public key saved as {pub_key_path}.")
        else:
            messagebox.showerror("Error", "Public key was not saved.")

        return private_key, public_key

    def upload_file(self):
        self.file_path = filedialog.askopenfilename(title="Select File")
        if self.file_path:
            self.sign_button.config(state=tk.NORMAL)

    def hash_file(self, file_path):
        h = hashlib.sha256()
        with open(file_path, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                h.update(chunk)
        return h.hexdigest()

    def sign_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file uploaded.")
            return
        message = self.hash_file(self.file_path)
        hash_obj = SHA256.new(message.encode())
        self.signature = pkcs1_15.new(RSA.import_key(self.private_key)).sign(hash_obj)

        # Save the signature to a file
        signature_file_path = filedialog.asksaveasfilename(defaultextension=".sig",
                                                           filetypes=[("Signature Files", "*.sig")],
                                                           title="Save Signature As")
        if signature_file_path:
            with open(signature_file_path, "wb") as sig_file:
                sig_file.write(self.signature)
            messagebox.showinfo("Success", f"File signed successfully.\nSignature saved as {signature_file_path}.")

        self.verify_button.config(state=tk.NORMAL)

    def verify_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file uploaded.")
            return

        # Upload the signature file
        sig_file_path = filedialog.askopenfilename(title="Select Signature File",
                                                   filetypes=[("Signature Files", "*.sig")])
        if not sig_file_path:
            messagebox.showerror("Error", "No signature file uploaded.")
            return

        with open(sig_file_path, 'rb') as sig_file:
            signature = sig_file.read()

        # Upload the public key file
        pub_key_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("Public Key Files", "*.pem")])
        if not pub_key_path:
            messagebox.showerror("Error", "No public key file uploaded.")
            return

        with open(pub_key_path, 'rb') as pub_file:
            public_key = pub_file.read()

        # Re-hash the original file
        message = self.hash_file(self.file_path)
        hash_obj = SHA256.new(message.encode())

        # Verify the signature
        try:
            pkcs1_15.new(RSA.import_key(public_key)).verify(hash_obj, signature)
            messagebox.showinfo("Success", "The signature is valid.")
        except (ValueError, TypeError):
            messagebox.showerror("Error", "The signature is not valid.")


if __name__ == "__main__":
    root = tk.Tk()
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    window_x = int((screen_width / 2) - (window_width / 2))
    window_y = int((screen_height / 2) - (window_height / 2))

    root.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")
    root.resizable(True, True)
    app = DigitalSignerApp(root)
    root.mainloop()
