import tkinter as tk  # Import the main tkinter module for GUI
from tkinter import ttk, filedialog, messagebox  # Import specific components from tkinter
import base64  # For encoding/decoding data
import os  # For file operations
from cryptography.fernet import Fernet  # For encryption/decryption
from cryptography.hazmat.primitives import hashes  # For hashing in key generation
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For key derivation from password

class EncryptDecryptApp:
    def __init__(self, root):
        """
        Initialize the application with the main window and setup
        
        Parameters:
            root: The main tkinter window
        """
        self.root = root
        self.root.title("Encryption/Decryption Tool")  # Set window title
        self.root.geometry("700x500")  # Set window size
        self.root.resizable(True, True)  # Allow window to be resized
        
        # Configure the visual style of GUI elements
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Arial', 10))  # Style for buttons
        self.style.configure('TLabel', font=('Arial', 10))   # Style for labels
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'))  # Style for header labels
        
        self.create_widgets()  # Call method to create all GUI elements
        
    def create_widgets(self):
        """
        Create and arrange all GUI elements in the window
        """
        # Main frame to contain all elements
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title label at the top
        title_label = ttk.Label(main_frame, text="Encryption/Decryption Tool", style='Header.TLabel')
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 20))
        
        # Input section - where user enters text to encrypt/decrypt
        input_label = ttk.Label(main_frame, text="Input Text:")
        input_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        
        self.input_text = tk.Text(main_frame, height=8, width=60, wrap=tk.WORD)
        self.input_text.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Password section - where user enters encryption/decryption password
        password_label = ttk.Label(main_frame, text="Password:")
        password_label.grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
        
        self.password_entry = ttk.Entry(main_frame, show="*", width=30)  # Password field with hidden characters
        self.password_entry.grid(row=3, column=1, sticky=tk.W, pady=(0, 10))
        
        # Show password checkbox - toggle password visibility
        self.show_password_var = tk.BooleanVar()
        show_password_check = ttk.Checkbutton(
            main_frame, 
            text="Show Password", 
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        show_password_check.grid(row=3, column=2, sticky=tk.W, pady=(0, 10))
        
        # Action buttons section - contains encrypt, decrypt, load, clear buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=4, pady=(0, 10))
        
        encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text)
        encrypt_button.grid(row=0, column=0, padx=5)
        
        decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_text)
        decrypt_button.grid(row=0, column=1, padx=5)
        
        load_button = ttk.Button(button_frame, text="Load File", command=self.load_file)
        load_button.grid(row=0, column=2, padx=5)
        
        clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_fields)
        clear_button.grid(row=0, column=3, padx=5)
        
        # Output section - where encrypted/decrypted text is displayed
        output_label = ttk.Label(main_frame, text="Output Text:")
        output_label.grid(row=5, column=0, sticky=tk.W, pady=(0, 5))
        
        self.output_text = tk.Text(main_frame, height=8, width=60, wrap=tk.WORD)
        self.output_text.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Output action buttons - copy to clipboard and save to file
        output_button_frame = ttk.Frame(main_frame)
        output_button_frame.grid(row=7, column=0, columnspan=4)
        
        copy_button = ttk.Button(output_button_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        copy_button.grid(row=0, column=0, padx=5)
        
        save_button = ttk.Button(output_button_frame, text="Save to File", command=self.save_to_file)
        save_button.grid(row=0, column=1, padx=5)
        
        # Configure grid weights to make the layout responsive
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(2, weight=1)
        main_frame.columnconfigure(3, weight=1)
        
    def toggle_password_visibility(self):
        """
        Toggle the password field between showing and hiding characters
        Based on the state of the show_password_var checkbox
        """
        if self.show_password_var.get():
            self.password_entry.config(show="")  # Show password characters
        else:
            self.password_entry.config(show="*")  # Hide password characters with asterisks
    
    def get_key_from_password(self, password):
        """
        Generate an encryption key from the user's password
        
        Parameters:
            password: The user's password string
            
        Returns:
            A base64-encoded key suitable for Fernet encryption
        """
        # Convert password to bytes
        password_bytes = password.encode()
        # Generate a random salt (in a real app, you'd want to store and reuse this salt)
        salt = b'salt_'  # In a real app, use a secure random salt and store it
        
        # Create a key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Use SHA-256 hashing algorithm
            length=32,                  # 32-byte key length
            salt=salt,                  # Salt to prevent rainbow table attacks
            iterations=100000,          # Number of iterations (higher is more secure but slower)
        )
        
        # Derive the key from the password and encode it in base64
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def encrypt_text(self):
        """
        Encrypt the text from the input field using the provided password
        and display the result in the output field
        """
        text = self.input_text.get("1.0", tk.END).strip()  # Get text from input field
        password = self.password_entry.get()  # Get password
        
        # Validate inputs
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        try:
            # Generate key from password
            key = self.get_key_from_password(password)
            
            # Create Fernet cipher with the key
            cipher = Fernet(key)
            
            # Encrypt the text (must be bytes)
            encrypted_text = cipher.encrypt(text.encode())
            
            # Convert to base64 string for display (more readable)
            result = base64.urlsafe_b64encode(encrypted_text).decode()
            
            # Display result in output field
            self.output_text.delete("1.0", tk.END)  # Clear output field
            self.output_text.insert("1.0", result)  # Insert encrypted result
            
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred: {str(e)}")
    
    def decrypt_text(self):
        """
        Decrypt the text from the input field using the provided password
        and display the result in the output field
        """
        text = self.input_text.get("1.0", tk.END).strip()  # Get text from input field
        password = self.password_entry.get()  # Get password
        
        # Validate inputs
        if not text:
            messagebox.showerror("Error", "Please enter text to decrypt")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        try:
            # Generate key from password
            key = self.get_key_from_password(password)
            
            # Create Fernet cipher with the key
            cipher = Fernet(key)
            
            # Try to decode from base64 first if it's in that format
            try:
                text_to_decrypt = base64.urlsafe_b64decode(text)
            except:
                # If not base64, try to decrypt directly
                text_to_decrypt = text.encode()
            
            # Decrypt the text
            decrypted_text = cipher.decrypt(text_to_decrypt).decode()
            
            # Display result in output field
            self.output_text.delete("1.0", tk.END)  # Clear output field
            self.output_text.insert("1.0", decrypted_text)  # Insert decrypted result
            
        except Exception as e:
            messagebox.showerror("Decryption Error", 
                                "Failed to decrypt. Make sure you're using the correct password and the text is properly encrypted.")
    
    def load_file(self):
        """
        Open a file dialog to select a file and load its contents into the input field
        """
        file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.input_text.delete("1.0", tk.END)  # Clear input field
                    self.input_text.insert("1.0", content)  # Insert file content
            except Exception as e:
                messagebox.showerror("File Error", f"Error loading file: {str(e)}")
    
    def save_to_file(self):
        """
        Open a file dialog to save the contents of the output field to a file
        """
        content = self.output_text.get("1.0", tk.END).strip()  # Get text from output field
        
        if not content:
            messagebox.showerror("Error", "No content to save")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save to file",
            defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(content)
                messagebox.showinfo("Success", "Content saved successfully")
            except Exception as e:
                messagebox.showerror("File Error", f"Error saving file: {str(e)}")
    
    def copy_to_clipboard(self):
        """
        Copy the contents of the output field to the clipboard
        """
        content = self.output_text.get("1.0", tk.END).strip()  # Get text from output field
        
        if not content:
            messagebox.showerror("Error", "No content to copy")
            return
        
        self.root.clipboard_clear()  # Clear clipboard
        self.root.clipboard_append(content)  # Add content to clipboard
        messagebox.showinfo("Success", "Content copied to clipboard")
    
    def clear_fields(self):
        """
        Clear all input fields (input text, output text, and password)
        """
        self.input_text.delete("1.0", tk.END)  # Clear input field
        self.output_text.delete("1.0", tk.END)  # Clear output field
        self.password_entry.delete(0, tk.END)  # Clear password field

# Entry point of the application
if __name__ == "__main__":
    root = tk.Tk()  # Create the main window
    app = EncryptDecryptApp(root)  # Create the application instance
    root.mainloop()  # Start the GUI event loop
