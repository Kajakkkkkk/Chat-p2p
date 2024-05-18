from stem.control import Controller
from cryptography.fernet import Fernet
from tkinter import scrolledtext, font
import tkinter as tk
import socket
import base64
import threading

conn = None
cipher_suite = None

def send_response():
    global conn, cipher_suite
    response_message = response_entry.get()
    encrypted_response = cipher_suite.encrypt(response_message.encode())
    conn.send(encrypted_response)

def start_server(address_entry, key_entry, received_messages_text):
    global conn, cipher_suite

    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        response = controller.create_ephemeral_hidden_service({80: 5000}, await_publication=True)
        
        address_entry.delete(0, tk.END)
        address_entry.insert(0, response.service_id + ".onion")
        print("Adres:", response.service_id + ".onion")

        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        
        key_entry.delete(0, tk.END)
        key_entry.insert(0, base64.urlsafe_b64encode(key).decode())
        print("Klucz szyfrowania (base64):", base64.urlsafe_b64encode(key).decode())

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', 5000))
        s.listen(1)
        conn, addr = s.accept()

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                received_message = cipher_suite.decrypt(data).decode()
                received_messages_text.insert(tk.END, "Odebrano: " + received_message + "\n")
            except Exception as e:
                print("Wystąpił błąd:", e)
                break

        conn.close()
        s.close()
       
# GUI 
root = tk.Tk()
root.title("Serwer (CHAT-P2P)")

root.configure(bg="#2b2b2b")
root.geometry("750x500")

custom_font = font.Font(family="Helvetica", size=10)

top_frame = tk.Frame(root, bg="#2b2b2b", pady=10)
top_frame.pack(fill=tk.X)

# ADDRESS
address_label = tk.Label(top_frame, text="Adres (.onion):", font=custom_font, bg="#2b2b2b", fg="#ffffff")
address_label.pack(pady=5)

address_frame = tk.Frame(top_frame, bg="#3c3f41", padx=2, pady=2, relief=tk.GROOVE, bd=2)
address_frame.pack(pady=5, padx=10, fill=tk.X)

address_entry = tk.Entry(top_frame, font=custom_font, bg="#3d3b3b", fg="#ffffff", relief=tk.FLAT)
address_entry.insert(0, "Generowanie...")
address_entry.config(state='readonly')
address_entry.config(state=tk.NORMAL)
address_entry.pack(pady=5, padx=10, fill=tk.X)

# KEY
key_label = tk.Label(top_frame, text="Klucz szyfrowania (base64):", font=custom_font, bg="#2b2b2b", fg="#ffffff")
key_label.pack(pady=5)

key_frame = tk.Frame(top_frame, bg="#3c3f41", padx=2, pady=2, relief=tk.GROOVE, bd=2)
key_frame.pack(pady=5, padx=10, fill=tk.X)

key_entry = tk.Entry(top_frame, font=custom_font, bg="#3d3b3b", fg="#ffffff", relief=tk.FLAT)
key_entry.insert(0, "Generowanie...")
key_entry.config(state='readonly')
key_entry.config(state=tk.NORMAL)
key_entry.pack(pady=5, padx=10, fill=tk.X)

# RECEIVED TEXTS
middle_frame = tk.Frame(root, bg="#2b2b2b", pady=10)
middle_frame.pack(fill=tk.BOTH, expand=True)

received_messages_text = scrolledtext.ScrolledText(middle_frame, width=50, height=10, font=custom_font, wrap=tk.WORD, bg="#808080", fg="#ffffff", relief=tk.FLAT)
received_messages_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

# ENTRY MESSAGE + BUTTON
bottom_frame = tk.Frame(root, bg="#2b2b2b", pady=10)
bottom_frame.pack(fill=tk.X)

response_entry = tk.Entry(bottom_frame, bg="#808080", fg="#ffffff", width=50, font=custom_font)
response_entry.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

send_button = tk.Button(bottom_frame, text="Wyślij", command=send_response, font=custom_font, bg="#2b2b2b", fg="#ffffff")
send_button.pack(side=tk.RIGHT, padx=10, pady=6)

#####
server_thread = threading.Thread(target=start_server, args=(address_entry, key_entry, received_messages_text))
server_thread.start()

root.mainloop()
