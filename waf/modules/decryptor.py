#modules/decryptor.py
from cryptography.fernet import Fernet
from datetime import datetime
import os
import glob


class LogDecryptor:
    def __init__(self, key_dir="."):
        self.key_dir = key_dir

    def find_keys(self):
        key_files = glob.glob(os.path.join(self.key_dir, "secret.key*"))
        keys = {}

        for key_file in key_files:
            try:
                with open(key_file, "rb") as f:
                    key = f.read()
                    keys[key_file] = key
            except:
                continue

        return keys

    def decrypt_logs(self, log_file, password=None):
        keys = self.find_keys()
        decrypted_logs = []

        if password and password != "admin123":  #REPLACE WITH HASH
            return []

        with open(log_file, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                for key_name, key in keys.items():
                    try:
                        cipher = Fernet(key)
                        decrypted = cipher.decrypt(line).decode()
                        decrypted_logs.append({
                            "key": key_name,
                            "log": decrypted
                        })
                        break
                    except:
                        continue

        return decrypted_logs