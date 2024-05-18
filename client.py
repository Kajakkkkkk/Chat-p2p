import socket
import socks
from cryptography.fernet import Fernet
import base64
from tkinter import scrolledtext, font, messagebox
import tkinter as tk

socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
socket.socket = socks.socksocket


def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode())


def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_message).decode()


def send_message():
    key_input = key_entry.get()
    message_to_send = message_entry.get()
    address = address_entry.get()
    default_port = 80

    try:
        key = base64.urlsafe_b64decode(key_input)
    except Exception as e:
        messagebox.showerror("Błąd klucza", "Nieprawidłowy klucz szyfrowania!")
        return

    try:
        s = socket.socket()
        s.settimeout(30)
        s.connect((address, default_port))

        encrypted_msg = encrypt_message(message_to_send, key)
        s.send(encrypted_msg)

        response = s.recv(1024)
        if response:
            decrypted_response = decrypt_message(response, key)
            response_text.insert(tk.END, f"Odebrano: {decrypted_response}\n")
        else:
            response_text.insert(tk.END, "Brak odpowiedzi od serwera.\n")

    except socket.timeout:
        messagebox.showerror("Błąd połączenia", "Połączenie przekroczyło limit czasu.")
    except Exception as e:
        messagebox.showerror("Błąd połączenia", str(e))
    finally:
        s.close()


# GUI
root = tk.Tk()
root.title("Klient (CHAT-P2P)")

root.configure(bg="#2b2b2b")
root.geometry("750x500")

custom_font = font.Font(family="Helvetica", size=10)

top_frame = tk.Frame(root, bg="#2b2b2b", pady=10)
top_frame.pack(fill=tk.X)

# ADDRESS
address_label = tk.Label(top_frame, text="Adres (.onion):", font=custom_font, bg="#2b2b2b", fg="#ffffff")
address_label.pack(pady=5)

address_entry = tk.Entry(top_frame, font=custom_font, bg="#3d3b3b", fg="#ffffff", relief=tk.FLAT)
address_entry.pack(pady=5, padx=10, fill=tk.X)

# KEY
key_label = tk.Label(top_frame, text="Klucz szyfrowania (base64):", font=custom_font, bg="#2b2b2b", fg="#ffffff")
key_label.pack(pady=5)

key_entry = tk.Entry(top_frame, font=custom_font, bg="#3d3b3b", fg="#ffffff", relief=tk.FLAT)
key_entry.pack(pady=5, padx=10, fill=tk.X)

# RECEIVED TEXTS
middle_frame = tk.Frame(root, bg="#2b2b2b", pady=10)
middle_frame.pack(fill=tk.BOTH, expand=True)

response_text = scrolledtext.ScrolledText(middle_frame, width=50, height=10, font=custom_font, wrap=tk.WORD,
                                          bg="#808080", fg="#ffffff", relief=tk.FLAT)
response_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

# ENTRY MESSAGE + BUTTON
bottom_frame = tk.Frame(root, bg="#2b2b2b", pady=10)
bottom_frame.pack(fill=tk.X)

message_entry = tk.Entry(bottom_frame, bg="#808080", fg="#ffffff", width=50, font=custom_font)
message_entry.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

send_button = tk.Button(bottom_frame, text="Wyślij", command=send_message, font=custom_font, bg="#2b2b2b", fg="#ffffff")
send_button.pack(side=tk.RIGHT, padx=10, pady=6)
