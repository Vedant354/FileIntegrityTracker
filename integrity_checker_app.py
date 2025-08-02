import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib

def generate_hash(file_path):
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            sha256_hash.update(chunk)
            sha1_hash.update(chunk)
    
    return sha256_hash.hexdigest(), sha1_hash.hexdigest()

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def compute_hash():
    file_path = file_entry.get()
    if file_path:
        sha256_hash, sha1_hash = generate_hash(file_path)
        sha256_hash_result.set(sha256_hash)
        sha1_hash_result.set(sha1_hash)
    else:
        messagebox.showwarning("Input Error", "Please select a file")

def compare_sha256():
    new_sha256_hash = sha256_hash_result.get()
    old_sha256_hash = old_sha256_entry.get()
    if new_sha256_hash == old_sha256_hash:
        comparison_sha256_result.set("FILE INTEGRITY IS MAINTAINED")
        sha256_comparison_label.config(fg="green", font=("Helvetica", 16))
    else:
        comparison_sha256_result.set("FILE INTEGRITY LOST")
        sha256_comparison_label.config(fg="red", font=("Helvetica", 16))

def compare_sha1():
    new_sha1_hash = sha1_hash_result.get()
    old_sha1_hash = old_sha1_entry.get()
    if new_sha1_hash == old_sha1_hash:
        comparison_sha1_result.set("FILE INTEGRITY IS MAINTAINED")
        sha1_comparison_label.config(fg="green", font=("Helvetica", 16))
    else:
        comparison_sha1_result.set("FILE INTEGRITY LOST")
        sha1_comparison_label.config(fg="red", font=("Helvetica", 16))

def copy_hash_to_clipboard(hash_value):
    app.clipboard_clear()
    app.clipboard_append(hash_value)
    messagebox.showinfo("Copy to Clipboard", f"{hash_value} copied to clipboard")

# Set up the main application window
app = tk.Tk()
app.title("Integrity Checker")
app.geometry("600x650")
app.configure(bg="#f0f0f0")  # Set a light background color

# File selection
file_frame = ttk.Frame(app)
file_frame.pack(pady=10)
file_label = ttk.Label(file_frame, text="Select a file:", background="#f0f0f0", font=("Helvetica", 12))
file_label.pack(side=tk.LEFT)
file_entry = ttk.Entry(file_frame, width=40, font=("Helvetica", 12))
file_entry.pack(side=tk.LEFT, padx=10)
browse_button = ttk.Button(file_frame, text="Browse", command=browse_file)
browse_button.pack(side=tk.LEFT)

# Hint for file selection
hint_label = ttk.Label(app, text="Hint: Provide file for Integrity assessment.", background="#f0f0f0", foreground="blue", font=("Helvetica", 10))
hint_label.pack(pady=5)

# Compute hash
compute_button = ttk.Button(app, text="Generate Hashes", command=compute_hash)
compute_button.pack(pady=10)

# SHA256 hash result
sha256_frame = ttk.Frame(app)
sha256_frame.pack(pady=10)
sha256_label = ttk.Label(sha256_frame, text="SHA256:", background="#f0f0f0", font=("Helvetica", 12))
sha256_label.pack(side=tk.LEFT)
sha256_hash_result = tk.StringVar()
sha256_hash_entry = ttk.Entry(sha256_frame, textvariable=sha256_hash_result, width=40, font=("Helvetica", 12))
sha256_hash_entry.pack(side=tk.LEFT, padx=10)
sha256_copy_button = ttk.Button(sha256_frame, text="Copy", command=lambda: copy_hash_to_clipboard(sha256_hash_result.get()))
sha256_copy_button.pack(side=tk.LEFT)

# Hint for SHA256 result
sha256_hint_label = ttk.Label(app, text="Hint: Copy the SHA256 hash for record keeping.", background="#f0f0f0", foreground="blue", font=("Helvetica", 10))
sha256_hint_label.pack(pady=5)

# SHA1 hash result
sha1_frame = ttk.Frame(app)
sha1_frame.pack(pady=10)
sha1_label = ttk.Label(sha1_frame, text="SHA1:", background="#f0f0f0", font=("Helvetica", 12))
sha1_label.pack(side=tk.LEFT)
sha1_hash_result = tk.StringVar()
sha1_hash_entry = ttk.Entry(sha1_frame, textvariable=sha1_hash_result, width=40, font=("Helvetica", 12))
sha1_hash_entry.pack(side=tk.LEFT, padx=10)
sha1_copy_button = ttk.Button(sha1_frame, text="Copy", command=lambda: copy_hash_to_clipboard(sha1_hash_result.get()))
sha1_copy_button.pack(side=tk.LEFT)

# Hint for SHA1 result
sha1_hint_label = ttk.Label(app, text="Hint: Copy the SHA1 hash for record keeping.", background="#f0f0f0", foreground="blue", font=("Helvetica", 10))
sha1_hint_label.pack(pady=5)

# Compare hashes
compare_frame = ttk.Frame(app)
compare_frame.pack(pady=10)

# Old SHA256 hash comparison
old_sha256_label = ttk.Label(compare_frame, text="Enter old SHA256 hash for comparison:")
old_sha256_label.pack()
old_sha256_entry = ttk.Entry(compare_frame, width=40, font=("Helvetica", 12))
old_sha256_entry.pack(pady=5)
compare_sha256_button = ttk.Button(app, text="Compare SHA256", command=compare_sha256)
compare_sha256_button.pack(pady=5)
comparison_sha256_result = tk.StringVar()
sha256_comparison_label = ttk.Label(app, textvariable=comparison_sha256_result, background="#f0f0f0", font=("Helvetica", 12))
sha256_comparison_label.pack(pady=5)

# Hint for SHA256 comparison
sha256_compare_hint = ttk.Label(app, text="Hint: Enter the old SHA256 hash to compare.", background="#f0f0f0", foreground="blue", font=("Helvetica", 10))
sha256_compare_hint.pack(pady=5)

# Old SHA1 hash comparison
old_sha1_label = ttk.Label(compare_frame, text="Enter old SHA1 hash for comparison:")
old_sha1_label.pack()
old_sha1_entry = ttk.Entry(compare_frame, width=40, font=("Helvetica", 12))
old_sha1_entry.pack(pady=5)
compare_sha1_button = ttk.Button(app, text="Compare SHA1", command=compare_sha1)
compare_sha1_button.pack(pady=5)
comparison_sha1_result = tk.StringVar()
sha1_comparison_label = ttk.Label(app, textvariable=comparison_sha1_result, background="#f0f0f0", font=("Helvetica", 12))
sha1_comparison_label.pack(pady=5)

# Hint for SHA1 comparison
sha1_compare_hint = ttk.Label(app, text="Hint: Enter the old SHA1 hash to compare.", background="#f0f0f0", foreground="blue", font=("Helvetica", 10))
sha1_compare_hint.pack(pady=5)

# Text area for additional user input
text_area = tk.Text(app, height=5, font=("Helvetica", 12))
text_area.pack(pady=10)
text_area_hint = ttk.Label(app, text="Useable Text Area", background="#f0f0f0", foreground="blue", font=("Helvetica", 10))
text_area_hint.pack(pady=5)

# Run the application
app.mainloop()
