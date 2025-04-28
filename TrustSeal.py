import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Backend Functionality (RSA Operations)


# Prime generation with Miller-Rabin
def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
# n-1=(2^s)*d (d is odd , s is how many times it's divided b 2)
# n-1=(2^s)*d (d is odd , s is how many times it's divided b 2)
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
# Witness loop
    for _ in range(k):
        a = random.randint(2, min(n-2, 1<<20)) # Random a where (2=<a=<n-2)
        x = pow(a, d, n) # This is b0 = a^d mod n
        if x == 1 or x == n-1:
            continue # True for this iteration
        for _ in range(s-1): # Repeat s-1 times
            x = pow(x, 2, n) # bi = (bi-1)^2 mod n
            if x == n-1:
                break
        else:
            return False
    return True

def generate_large_prime(length=1024):
    """Generate large prime numbers"""
    while True:
        p = random.getrandbits(length)
        p |= (1 << length - 1) | 1  # Ensure high bit length set and odd sinc LSB=1
        if is_prime(p):
            return p

# Key generation
def generate_keys():
    p = generate_large_prime()
    q = generate_large_prime()
    while p == q:
        q = generate_large_prime()
    n = p * q
    phi = (p-1) * (q-1)

    # Choose e
    e = 65537 # Common e that is secure enough
    while phi % e == 0: # Ensure e is coprime to phi
        e = random.randint(2, phi-1)

    # Compute d 
    def modinv(a, m): # Makes sure e⋅d≡1modϕ(n)
        g, x, y = extended_gcd(a, m) # For ax+by=gcd(a,b)
        if g != 1:
            return None # No modular inverse exists for e
        else:
            return x % m

    def extended_gcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    d = modinv(e, phi)
    while d is None:
        e = random.randint(2, phi - 1)
        d = modinv(e, phi)
    return (n, e, d, p, q) # n = modulus , e = public key , d = private key , p and q = primes used

# Encryption/Decryption
def encrypt(message, e, n):
    msg_int = int.from_bytes(message.encode(), 'big') # Convert message to integer
    cipher_int = pow(msg_int, e, n) # Cipher= message^e mod n
    return cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, 'big').hex() # Convert to hex for display

def decrypt(cipher_hex, d, n):
    cipher_int = int.from_bytes(bytes.fromhex(cipher_hex), 'big')
    msg_int = pow(cipher_int, d, n) # Message= cipher^d mod n
    return msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big').decode()

# Digital Signature, Signing uses the private key (d) to encrypt the message.
# Verifying uses the public key (e) to decrypt the signature and compare it to the original message.
def sign(message, d, n):
    msg_int = int.from_bytes(message.encode(), 'big')
    signature = pow(msg_int, d, n)
    return signature.to_bytes((signature.bit_length() + 7) // 8, 'big').hex()

def verify(message, signature_hex, e, n):
    sig_int = int.from_bytes(bytes.fromhex(signature_hex), 'big')
    decrypted_hash = pow(sig_int, e, n)
    original_hash = int.from_bytes(message.encode(), 'big')
    return decrypted_hash == original_hash

# GUI Implementation

class RSAGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TrustSeal - RSA Operations")
        self.style = ttk.Style()
        self.configure_styles()
        
        # Key storage
        self.n = None
        self.e = None
        self.d = None
        
        self.create_widgets()
    
    def configure_styles(self):
        """Configure blue/green theme"""
        self.style.theme_use('clam')
        self.style.configure('.', background='#e0f0ff')
        self.style.configure('TFrame', background='#e0f0ff')
        self.style.configure('TButton', background='#4dc3ff', foreground='black')
        self.style.configure('TLabel', background='#e0f0ff', foreground='#006600')
        self.style.map('TButton', background=[('active', '#0099cc')])
    
    def create_widgets(self):
        # Notebook for different sections
        notebook = ttk.Notebook(self.root)
        notebook.pack(padx=10, pady=10, expand=True, fill='both')
        
        # Key Generation Tab
        key_frame = ttk.Frame(notebook)
        self.create_key_generation_ui(key_frame)
        notebook.add(key_frame, text="Key Generation")
        # Encryption/Decryption Tab    
        enc_frame = ttk.Frame(notebook)
        self.create_encryption_ui(enc_frame)
        notebook.add(enc_frame, text="Encryption/Decryption")
        
        # Digital Signature Tab
        sig_frame = ttk.Frame(notebook)
        self.create_signature_ui(sig_frame)
        notebook.add(sig_frame, text="Digital Signature")
        
        # Key Validation Tab
        valid_frame = ttk.Frame(notebook)
        self.create_key_validation_ui(valid_frame)
        notebook.add(valid_frame, text="Key Validation")
    
    def create_key_generation_ui(self, frame):
        ttk.Label(frame, text="Generate RSA Keys", font=('Helvetica', 14, 'bold')).pack(pady=10)

        ttk.Button(frame, text="Generate Keys", command=self.generate_keys).pack(pady=5)
        self.key_info = scrolledtext.ScrolledText(frame, height=8, width=60)
        self.key_info.pack(pady=10)
    
    def create_encryption_ui(self, frame):
        ttk.Label(frame, text="Message Encryption", font=('Helvetica', 14, 'bold')).pack(pady=10)

        ttk.Label(frame, text="Message:").pack()
        self.msg_entry = ttk.Entry(frame, width=50)
        self.msg_entry.pack()

        ttk.Button(frame, text="Encrypt", command=self.do_encrypt).pack(pady=5)
        self.cipher_display = ttk.Label(frame, text="", wraplength=400)
        self.cipher_display.pack(pady=5)

        ttk.Button(frame, text="Decrypt", command=self.do_decrypt).pack(pady=5)
        self.decrypted_display = ttk.Label(frame, text="")
        self.decrypted_display.pack()
    
    def create_signature_ui(self, frame):
        ttk.Label(frame, text="Digital Signature", font=('Helvetica', 14, 'bold')).pack(pady=10)

        ttk.Label(frame, text="Message:").pack()
        self.sig_msg_entry = ttk.Entry(frame, width=50)
        self.sig_msg_entry.pack()

        ttk.Button(frame, text="Sign Message", command=self.do_sign).pack(pady=5)
        self.sig_display = ttk.Label(frame, text="", wraplength=400)
        self.sig_display.pack()

        ttk.Button(frame, text="Verify Signature", command=self.do_verify).pack(pady=5)
        self.verify_result = ttk.Label(frame, text="")
        self.verify_result.pack()
    
    def create_key_validation_ui(self, frame):
        ttk.Label(frame, text="Validate RSA Parameters", font=('Helvetica', 14, 'bold')).pack(pady=10)
        entry_frame = ttk.Frame(frame)
        entry_frame.pack(pady=5)
        # Create entries for n, e, d, p, q
        labels = ["n (modulus):", "e (public key):", "d (private key):", "p (prime1):", "q (prime2):"]
        self.param_entries = {}
        for label_text in labels:
            row = ttk.Frame(entry_frame)
            row.pack(fill='x', pady=2)
            ttk.Label(row, text=label_text, width=15).pack(side='left')
            entry = ttk.Entry(row, width=50)
            entry.pack(side='left', expand=True, fill='x')
            self.param_entries[label_text] = entry
        ttk.Button(frame, text="Validate Keys", command=self.do_validate_keys).pack(pady=10)
        self.validation_result = ttk.Label(frame, text="", wraplength=400)
        self.validation_result.pack(pady=5)
    
    def generate_keys(self):
        n, e, d, p, q = generate_keys()
        self.n = n
        self.e = e
        self.d = d
        self.key_info.delete(1.0, tk.END)
        self.key_info.insert(tk.END, 
            f"p (prime1): {p}\nq (prime2): {q}\n\nModulus (n): {n}\nPublic Key (e): {e}\nPrivate Key (d): {d}")
        messagebox.showinfo("Success", "Keys generated successfully!")
    
    def do_encrypt(self):
        if not self.e or not self.n:
            messagebox.showerror("Error", "Generate keys first!")
            return
        cipher = encrypt(self.msg_entry.get(), self.e, self.n)
        self.cipher_display.config(text=f"Ciphertext: {cipher}")
    
    def do_decrypt(self):
        if not self.d or not self.n:
            messagebox.showerror("Error", "Generate keys first!")
            return
        try:
            decrypted = decrypt(self.cipher_display.cget("text")[12:], self.d, self.n)
            self.decrypted_display.config(text=f"Decrypted: {decrypted}")
        except Exception as ex:
            messagebox.showerror("Error", f"Invalid ciphertext\n{ex}")
    
    def do_sign(self):
        if not self.d or not self.n:
            messagebox.showerror("Error", "Generate keys first!")
            return
        signature = sign(self.sig_msg_entry.get(), self.d, self.n)
        self.sig_display.config(text=f"Signature: {signature}")
    
    def do_verify(self):
        if not self.e or not self.n:
            messagebox.showerror("Error", "Generate keys first!")
            return
        is_valid = verify(
            self.sig_msg_entry.get(),
            self.sig_display.cget("text")[11:],
            self.e,
            self.n
        )
        self.verify_result.config(text="Signature Valid!" if is_valid else "Signature Invalid!")
    
    def do_validate_keys(self):
        try:
            n = int(self.param_entries["n (modulus):"].get())
            e = int(self.param_entries["e (public key):"].get())
            d = int(self.param_entries["d (private key):"].get())
            p = int(self.param_entries["p (prime1):"].get())
            q = int(self.param_entries["q (prime2):"].get())
        except ValueError:
            self.validation_result.config(text="Error: Please enter valid integer values.", foreground="red")
            return

        if n != p * q:
            self.validation_result.config(text="Invalid keys: n is not equal to p * q.", foreground="red")
            return

        phi = (p - 1) * (q - 1)
        if (e * d) % phi != 1:
            self.validation_result.config(text="Invalid keys: e and d do not satisfy e * d ≡ 1 (mod φ(n)).", foreground="red")
            return

        if not is_prime(p) or not is_prime(q):
            self.validation_result.config(text="Invalid keys: One or both of p and q are not prime.", foreground="red")
            return

        self.validation_result.config(text="The provided RSA parameters are valid!", foreground="green")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAGUI(root)
    root.mainloop()
