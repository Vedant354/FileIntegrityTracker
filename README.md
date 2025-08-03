# File_Integrity_Tracker
A Python-based File Integrity Tracking tool that detects unauthorized file changes using SHA-256 hashes. Logs modified, deleted, or new files for audit and security purposes. Designed for SOC/Blue Team scenarios to simulate real-world incident detection.
A simple and user-friendly desktop application built using **Python** and **Tkinter** that allows users to generate and compare cryptographic hash values (SHA-256 and SHA-1) of files, helping ensure **file integrity** and detect unauthorized modifications.

✅ Features

📁 Select any file from your system

🔐 Generate SHA-256 and SHA-1 hash values

📋 Copy hashes to clipboard

🔄 Compare newly generated hashes with old ones

🟢 Indicates if integrity is **maintained** or 🔴 if it is **lost**

📝 Usable text area for storing or pasting hash values


🖼️ Screenshots

> <img width="1534" height="969" alt="image" src="https://github.com/user-attachments/assets/d1d76231-3d14-4ca6-a956-f2bd5afa7b5b" />

🛠 Technologies Used

Python 3.x

Tkinter (for GUI)

hashlib (for generating hashes)



🔍 How It Works

1. Select a file using the **Browse** button.
2. Click on **Generate Hashes** to calculate the SHA256 and SHA1 values.
3. To compare:
   - Paste the original hash in the provided field.
   - Click **Compare**.
   - The result will tell whether the file's integrity is maintained or lost.

💻 Installation

1. Clone the repository
   ```bash
   git clone https://github.com/Vedant354/file-integrity-Tracker.git
   cd file-integrity-checker
