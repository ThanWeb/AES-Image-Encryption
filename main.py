from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from tkinter import *
from tkinter import filedialog
from PIL import Image
from datetime import datetime
import os
import pyperclip
import pathlib

def browse_image():
  file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
  entry.delete(0, END)
  entry.insert(0, file_path)

def encrypt_image(input_path, output_path, key, filename):
  cipher = AES.new(key, AES.MODE_CBC)
  with open(input_path, 'rb') as f:
    plaintext = f.read()

  encrypted_image = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))

  with open(output_path, 'wb') as f:
    f.write(encrypted_image)
  
  # Create a encryption folder
  original_folder, original_filename = os.path.split(filename)
  encryption_folder = os.path.join(original_folder, "encrypted")
  os.makedirs(encryption_folder, exist_ok=True)

  # Rename the file with the provided filename in the encryption folder
  decrypted_file_path = os.path.join(encryption_folder, original_filename)
  os.rename(output_path, decrypted_file_path)

def decrypt_image(input_path, output_path, key, filename):
  with open(input_path, 'rb') as f:
    encrypted_data = f.read()

  iv = encrypted_data[:AES.block_size]
  ciphertext = encrypted_data[AES.block_size:]

  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

  with open(output_path, 'wb') as f:
    f.write(decrypted_data)
  
  # Create a decryption folder
  original_folder, original_filename = os.path.split(filename)
  decryption_folder = os.path.join(original_folder, "decrypted")
  os.makedirs(decryption_folder, exist_ok=True)

  # Rename the file with the provided filename in the decryption folder
  decrypted_file_path = os.path.join(decryption_folder, original_filename)
  os.rename(output_path, decrypted_file_path)

def copy_key():
  key = key_hex_label.cget("text")
  pyperclip.copy(key)

def encrypt():
  input_path = entry.get()
  if not input_path:
    info_label.config(text="Please select an image file.", fg="red")
    return

  encryption_key = key_entry.get()
  if not encryption_key:
    info_label.config(text="Please enter an encryption key.", fg="red")
    return

  # Ubah kunci yang dimasukkan menjadi bytes
  key = bytes.fromhex(encryption_key)
  if len(key) != 16:
    info_label.config(text="Please enter a valid 128-bit key in hexadecimal format.", fg="red")
    return

  now = datetime.now()
  ext = pathlib.Path(input_path).suffix
  filename = now.strftime("%m-%d-%Y-%H-%M-%S" + ext)

  encrypt_image(input_path, filename, key, filename)
  key_hex_label.config(text=key.hex(), fg="black")
  copy_key_button.pack(side=TOP)
  info_label.config(text="Encryption complete.", fg="green")

def popup_notification(message, color):
  popup = Tk()
  popup.title("Notification")
  popup.geometry("300x100")
  label = Label(popup, text=message, fg=color)
  label.pack(pady=20)
  popup.mainloop()

def decrypt():
  input_path = entry.get()
  if not input_path:
    info_label.config(text="Please select an encrypted image file.", fg="red")
    return
  
  key_hex = key_entry.get()
  key = bytes.fromhex(key_hex)
  if not key:
    info_label.config(text="Please enter a valid key.", fg="red")
    return
  
  now = datetime.now()
  ext = pathlib.Path(input_path).suffix
  filename = now.strftime("%m-%d-%Y-%H-%M-%S" + ext)

  decryption_successful = False
  try:
    decrypt_image(input_path, filename, key, filename)
    decryption_successful = True
  except ValueError as e:
    popup_notification("Decryption failed. Incorrect key.", "red")
  
  if decryption_successful:
    popup_notification("Decryption successful.", "green")
  else:
    popup_notification("Decryption failed.", "red")

def set_encryption_mode():
  key_label.pack(side=TOP)
  key_entry.pack(side=TOP)
  
  # Hapus elemen-elemen yang tidak dibutuhkan pada mode enkripsi
  filename_label.pack_forget()
  filename_entry.pack_forget()
  decrypt_button.pack_forget()

  if copy_key_button.winfo_exists():
    copy_key_button.pack_forget()

  encrypt_button.pack(side=TOP)
  browse_button.pack(side=TOP)
  info_label.pack(side=TOP)
  key_hex_label.pack(side=TOP)
  entry.delete(0, END)  # Membersihkan kolom input file
  key_entry.delete(0, END)  # Membersihkan kolom input kunci

    

def browse_decrypted_image():
  file_path = filedialog.askopenfilename(filetypes=[("Encrypted Image files", "*.png *.jpg *.jpeg *.bmp")])
  entry.delete(0, END)
  entry.insert(0, file_path)

def set_decryption_mode():
  filename_label.pack_forget()
  filename_entry.pack_forget()
  browse_button.config(command=browse_decrypted_image, text="Browse Encrypted Image")
  encrypt_button.pack_forget()
  info_label.pack_forget()
  key_hex_label.pack_forget()
  copy_key_button.pack_forget()  # Menghapus tombol 'Copy Key'
  key_label.pack(side=TOP)
  key_entry.pack(side=TOP)
  decrypt_button.pack(side=TOP)
  entry.delete(0, END)  # Membersihkan kolom input file
  key_entry.delete(0, END)  # Membersihkan kolom input kunci

root = Tk()
root.title("Aplikasi Keamanan Kartu Mahasiswa")
root.configure(bg='lightblue')

def start_encryption_mode():
  set_encryption_mode()
  entry.delete(0, END)  # Membersihkan kolom input file
  key_entry.delete(0, END)  # Membersihkan kolom input kunci
  root.config(menu=None)
    

def start_decryption_mode():
  set_decryption_mode()
  entry.delete(0, END)  # Membersihkan kolom input file
  key_entry.delete(0, END)  # Membersihkan kolom input kunci
  root.config(menu=None)
    

menu = Menu(root)
root.config(menu=menu)

mode_menu = Menu(menu)
menu.add_cascade(label="Start Mode", menu=mode_menu)
mode_menu.add_command(label="Encryption", command=start_encryption_mode)
mode_menu.add_command(label="Decryption", command=start_decryption_mode)

label = Label(root, text="Select an image to encrypt/decrypt:", bg='lightblue', fg='black')
label.pack()

entry = Entry(root, bg='white', fg='black', width=40)
entry.pack()

browse_button = Button(root, text="Browse", command=browse_image, bg='blue', fg='white')
browse_button.pack()

filename_label = Label(root, text="Enter the output filename:", bg='lightblue', fg='black')

filename_entry = Entry(root, bg='white', fg='black', width=40)

key_label = Label(root, text="Enter the encryption key:", bg='lightblue', fg='black')

key_entry = Entry(root, bg='white', fg='black', width=40)

encrypt_button = Button(root, text="Encrypt", command=encrypt, bg='green', fg='white')

key_label = Label(root, text="Enter the decryption key:", bg='lightblue', fg='black')

key_entry = Entry(root, bg='white', fg='black', width=40)

decrypt_button = Button(root, text="Decrypt", command=decrypt, bg='red', fg='white')

copy_key_button = Button(root, text="Copy Key", command=copy_key, bg='lightblue', fg='black')

key_hex_label = Label(root, text="", bg='lightblue', fg='black')

info_label = Label(root, text="", bg='lightblue', fg='black')

root.mainloop()