import cv2
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from typing import Optional
import threading

# Constants
CHUNK_SIZE = 3
MAX_CHAR_VALUE = 255
OUTPUT_FORMAT = ".png"

COLORS = {
    'primary': '#2D2B3E',  # Dark purple
    'secondary': '#4B4759',  # Medium purple
    'accent': '#A7A0B8',  # Light purple
    'background': '#FDF6EC',  # Cream
    'text': '#000000',  # Pure black for text
    'button_text': '#FFFFFF',  # White for button text
    'hover': '#3D3B4E',  # Slightly lighter purple for hover
    'text_area': '#FFFFFF'  # White background for text areas
}


class CustomStyle:

    def __init__(self):
        self.style = ttk.Style()
        self.configure_styles()

    def configure_styles(self):
        # Configure main theme
        self.style.configure('Custom.TFrame', background=COLORS['background'])

        # Configure button styles with explicit foreground color
        self.style.configure('Custom.TButton',
                             padding=(20, 10),
                             background=COLORS['primary'],
                             foreground=COLORS['text'],
                             font=('Helvetica', 12, 'bold'),
                             borderwidth=1,
                             relief='solid')

        # Add button hover effect
        self.style.map('Custom.TButton',
                       background=[('active', COLORS['hover']),
                                   ('pressed', COLORS['hover'])],
                       foreground=[('active', COLORS['text']),
                                   ('pressed', COLORS['button_text'])])

        # Configure regular label style
        self.style.configure('Custom.TLabel',
                             background=COLORS['background'],
                             foreground=COLORS['text'],
                             font=('Helvetica', 12),
                             padding=5)

        # Configure heading label style
        self.style.configure('Heading.TLabel',
                             background=COLORS['background'],
                             foreground=COLORS['text'],
                             font=('Helvetica', 22, 'bold'),
                             padding=15)

        # Configure entry field style
        self.style.configure('Custom.TEntry',
                             fieldbackground=COLORS['text_area'],
                             foreground=COLORS['text'],
                             font=('Helvetica', 12),
                             padding=5)

        # Configure progress bar
        self.style.configure('Custom.Horizontal.TProgressbar',
                             troughcolor=COLORS['background'],
                             background=COLORS['accent'],
                             bordercolor=COLORS['primary'],
                             lightcolor=COLORS['accent'],
                             darkcolor=COLORS['accent'])

        # Configure separator
        self.style.configure('TSeparator', background=COLORS['primary'])

        # Configure dialog style
        self.style.configure('Dialog.TFrame',
                             background=COLORS['background'],
                             relief='solid',
                             borderwidth=1)

        # Configure text widget style - Note: This is applied directly to tk.Text widgets
        self.text_style = {
            'background': COLORS['text_area'],
            'foreground': COLORS['text'],
            'font': ('Helvetica', 12),
            'relief': 'solid',
            'borderwidth': 1,
            'padx': 5,
            'pady': 5
        }

        # Configure message box style
        self.style.configure('Message.TLabel',
                             background=COLORS['background'],
                             foreground=COLORS['text'],
                             font=('Helvetica', 11),
                             wraplength=300,
                             padding=10)

        # Add hover effect for all interactive elements
        self.style.map('TEntry',
                       fieldbackground=[('active', COLORS['text_area']),
                                        ('focus', COLORS['text_area'])])

        # Configure focus highlight
        self.style.map('Custom.TButton',
                       relief=[('pressed', 'sunken'), ('!pressed', 'solid')],
                       borderwidth=[('active', 2)])

        # Status bar style
        self.style.configure('Status.TLabel',
                             background=COLORS['background'],
                             foreground=COLORS['text'],
                             font=('Helvetica', 10, 'italic'),
                             padding=5)

        # Error message style
        self.style.configure('Error.TLabel',
                             background=COLORS['background'],
                             foreground='red',
                             font=('Helvetica', 11),
                             padding=5)

    def apply_text_widget_style(self, text_widget):
        """Apply the text widget style to a tk.Text widget"""
        for key, value in self.text_style.items():
            text_widget[key] = value


class ImageCrypto:

    def __init__(self):
        self.salt = b'salt_'

    def get_key_from_password(self, password: str) -> Fernet:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)


class SteganographyApp:

    def __init__(self):
        self.crypto = ImageCrypto()

    def validate_image(self, img, message_length: int = 0) -> bool:
        if img is None:
            raise ValueError("Unable to load image")

        max_bytes = (img.shape[0] * img.shape[1] * 3) // 8
        if message_length and message_length > max_bytes:
            raise ValueError(
                f"Image too small for message. Max size: {max_bytes} bytes")

        return True

    def encode(self, image_path: str, message: str, password: str) -> str:
        if not all([image_path, message, password]):
            raise ValueError("All inputs must be provided")

        img = cv2.imread(image_path)
        self.validate_image(img, len(message))

        f = self.crypto.get_key_from_password(password)
        encrypted_data = f.encrypt(message.encode())

        n, m, z = 0, 0, 0
        for byte in encrypted_data:
            img[n, m, z] = byte
            z = (z + 1) % CHUNK_SIZE
            if z == 0:
                m += 1
            if m >= img.shape[1]:
                m = 0
                n += 1

        output_path = os.path.splitext(
            image_path)[0] + "_encoded" + OUTPUT_FORMAT
        cv2.imwrite(output_path, img)
        return output_path

    def decode(self, image_path: str, password: str) -> str:
        if not all([image_path, password]):
            raise ValueError("Both image and password must be provided")

        img = cv2.imread(image_path)
        self.validate_image(img)

        f = self.crypto.get_key_from_password(password)
        encrypted_data = bytearray()
        n, m, z = 0, 0, 0

        try:
            while n < img.shape[0]:
                encrypted_data.append(img[n, m, z])
                z = (z + 1) % CHUNK_SIZE
                if z == 0:
                    m += 1
                if m >= img.shape[1]:
                    m = 0
                    n += 1
                if len(encrypted_data) >= 100000:  # Safety limit
                    break

            decrypted_message = f.decrypt(bytes(encrypted_data))
            return decrypted_message.decode().rstrip('\0')

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


class ModernDialog(tk.Toplevel):

    def __init__(self,
                 parent,
                 title: str,
                 prompt: str,
                 show: Optional[str] = None):
        super().__init__(parent)
        self.result = None

        # Window setup
        self.title(title)
        self.geometry("400x200")
        self.configure(background=COLORS['background'])
        self.resizable(False, False)

        # Center the dialog
        self.transient(parent)
        self.grab_set()

        # Create widgets with enhanced visibility
        main_frame = ttk.Frame(self, style='Custom.TFrame')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        ttk.Label(main_frame, text=prompt,
                  style='Custom.TLabel').pack(pady=(0, 10))

        # Enhanced entry field with white background
        self.entry = ttk.Entry(main_frame, show=show, font=('Helvetica', 12))
        self.entry.pack(fill='x', pady=(0, 20))

        button_frame = ttk.Frame(main_frame, style='Custom.TFrame')
        button_frame.pack(fill='x')

        ttk.Button(button_frame,
                   text="OK",
                   style='Custom.TButton',
                   command=self.ok).pack(side='right', padx=5)

        ttk.Button(button_frame,
                   text="Cancel",
                   style='Custom.TButton',
                   command=self.cancel).pack(side='right')

        self.entry.focus_set()
        self.bind("<Return>", lambda e: self.ok())
        self.bind("<Escape>", lambda e: self.cancel())

    def ok(self):
        self.result = self.entry.get()
        self.destroy()

    def cancel(self):
        self.destroy()


class GUI:

    def __init__(self):
        self.steg = SteganographyApp()
        self.root = tk.Tk()
        self.root.title("Secure Data Hiding in Image Using Steganography")
        self.root.geometry("850x400")
        self.root.configure(background=COLORS['background'])

        # Initialize custom styles
        self.style = CustomStyle()

        self.setup_gui()

    def setup_gui(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, style='Custom.TFrame')
        main_frame.pack(fill='both', expand=True, padx=40, pady=40)

        # Header with decorative line
        header_frame = ttk.Frame(main_frame, style='Custom.TFrame')
        header_frame.pack(fill='x', pady=(0, 30))

        ttk.Label(header_frame,
                  text="Secure Data Hiding in Image Using Steganography",
                  style='Heading.TLabel').pack(pady=(0, 5))

        # Separator
        separator = ttk.Separator(header_frame, orient='horizontal')
        separator.pack(fill='x', pady=(0, 15))

        # Description
        ttk.Label(
            main_frame,
            text="Hide your confidential messages within images securely",
            style='Custom.TLabel',
            font=('Helvetica', 12)).pack(pady=(0, 30))

        # Buttons container
        button_frame = ttk.Frame(main_frame, style='Custom.TFrame')
        button_frame.pack(fill='x', pady=20)

        # Encode button
        encode_btn = ttk.Button(button_frame,
                                text="Encode Message",
                                style='Custom.TButton',
                                command=self.encode_window)
        encode_btn.pack(fill='x', pady=10, ipady=5)

        # Decode button
        decode_btn = ttk.Button(button_frame,
                                text="Decode Message",
                                style='Custom.TButton',
                                command=self.decode_window)
        decode_btn.pack(fill='x', pady=10, ipady=5)

        def close_app():
            for thread in threading.enumerate():
                if thread != threading.main_thread():
                    thread.join(timeout=1)  # Wait for threads to stop
            self.root.quit()
            self.root.destroy()

        # Exit button
        exit_btn = ttk.Button(button_frame,
                              text="Exit",
                              style='Custom.TButton',
                              command=close_app)
        exit_btn.pack(fill='x', pady=(20, 0), ipady=5)

        # Status bar
        status_frame = ttk.Frame(main_frame, style='Custom.TFrame')
        status_frame.pack(side='bottom', fill='x', pady=(30, 0))

        self.status_var = tk.StringVar()
        self.status_var.set("Ready to process your secret messages")
        status_label = ttk.Label(status_frame,
                                 textvariable=self.status_var,
                                 style='Custom.TLabel',
                                 font=('Helvetica', 10, 'italic'))
        status_label.pack(side='left')

    def show_dialog(self,
                    title: str,
                    prompt: str,
                    show: Optional[str] = None) -> Optional[str]:
        dialog = ModernDialog(self.root, title, prompt, show)
        self.root.wait_window(dialog)
        return dialog.result

    def encode_window(self):
        win = tk.Toplevel(self.root)
        win.title("Encode Message")
        win.geometry("500x400")
        win.configure(background=COLORS['background'])

        main_frame = ttk.Frame(win, style='Custom.TFrame')
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)

        ttk.Label(main_frame,
                  text="Encode Secret Message",
                  style='Heading.TLabel').pack(pady=(0, 20))

        def encode():
            try:
                file_path = filedialog.askopenfilename(
                    title="Select an Image",
                    filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])

                if not file_path:
                    return

                message = self.show_dialog("Input", "Enter secret message:")
                if not message:
                    return

                password = self.show_dialog("Input",
                                            "Enter a password:",
                                            show="*")
                if not password:
                    return

                self.status_var.set("Encoding message...")
                output_path = self.steg.encode(file_path, message, password)
                self.status_var.set("Ready")
                messagebox.showinfo(
                    "Success", f"Message encoded and saved as:\n{output_path}")
                win.destroy(
                )  # Close the encode window after successful operation

            except Exception as e:
                self.status_var.set("Ready")
                messagebox.showerror("Error", str(e))

        ttk.Button(main_frame,
                   text="Select Image & Encode",
                   style='Custom.TButton',
                   command=encode).pack(fill='x', pady=10)

        ttk.Button(main_frame,
                   text="Back",
                   style='Custom.TButton',
                   command=win.destroy).pack(fill='x', pady=10)

    def decode_window(self):
        win = tk.Toplevel(self.root)
        win.title("Decode Message")
        win.geometry("500x400")
        win.configure(background=COLORS['background'])

        main_frame = ttk.Frame(win, style='Custom.TFrame')
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)

        ttk.Label(main_frame,
                  text="Decode Secret Message",
                  style='Heading.TLabel').pack(pady=(0, 20))

        def decode():
            try:
                file_path = filedialog.askopenfilename(
                    title="Select Encoded Image",
                    filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])

                if not file_path:
                    return

                password = self.show_dialog("Input",
                                            "Enter the password:",
                                            show="*")
                if not password:
                    return

                self.status_var.set("Decoding message...")
                message = self.steg.decode(file_path, password)
                self.status_var.set("Ready")

                # Show result in a custom-styled dialog
                result_win = tk.Toplevel(win)
                result_win.title("Decoded Message")
                result_win.geometry("400x300")
                result_win.configure(background=COLORS['background'])

                result_frame = ttk.Frame(result_win, style='Custom.TFrame')
                result_frame.pack(fill='both', expand=True, padx=20, pady=20)

                ttk.Label(result_frame,
                          text="Decoded Message:",
                          style='Custom.TLabel').pack(pady=(0, 10))

                # Enhanced text widget with better visibility
                text_widget = tk.Text(result_frame,
                                      wrap='word',
                                      height=8,
                                      font=('Helvetica', 12),
                                      bg=COLORS['text_area'],
                                      fg=COLORS['text'])
                text_widget.pack(fill='both', expand=True, pady=(0, 10))
                text_widget.insert('1.0', message)
                text_widget.configure(state='disabled')

                def close_all():
                    result_win.destroy()
                    win.destroy(
                    )  # Close both windows after viewing the message

                ttk.Button(result_frame,
                           text="Close",
                           style='Custom.TButton',
                           command=close_all).pack(fill='x')

            except Exception as e:
                self.status_var.set("Ready")
                messagebox.showerror("Error", str(e))

        ttk.Button(main_frame,
                   text="Select Image & Decode",
                   style='Custom.TButton',
                   command=decode).pack(fill='x', pady=10)

        ttk.Button(main_frame,
                   text="Back",
                   style='Custom.TButton',
                   command=win.destroy).pack(fill='x', pady=10)

    def run(self):
        # Center the window on screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

        # Set minimum window size
        self.root.minsize(500, 700)

        # Make sure the window appears on top when launched
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.attributes('-topmost', False)

        # Start the main event loop
        self.root.mainloop()


if __name__ == "__main__":
    app = GUI()
    app.run()
