from cryptography.fernet import Fernet
import os
from datetime import datetime, timedelta
from typing import Optional
from typing import List, Dict, Any


class EncryptionManager:
    def __init__(self, key_rotation_days: int = 30):
        self.KEY_FILE = "secret.key"
        self.key_rotation_days = key_rotation_days
        self.last_rotation = datetime.now()
        self.current_key = self._load_or_generate_key()

    def _load_or_generate_key(self) -> bytes:
        """Генерация/загрузка ключа"""
        if os.path.exists(self.KEY_FILE):
            with open(self.KEY_FILE, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.KEY_FILE, "wb") as f:
                f.write(key)
            os.chmod(self.KEY_FILE, 0o400)
            return key

    def rotate_key(self) -> bool:
        """Ротация ключа"""
        new_key = Fernet.generate_key()

        #Сохраняем старый ключ
        backup_file = f"{self.KEY_FILE}.{self.last_rotation.strftime('%Y%m%d')}"
        with open(backup_file, "wb") as f:
            f.write(self.current_key)
            os.chmod(backup_file, 0o400)

        with open(self.KEY_FILE, "wb") as f:
            f.write(new_key)

        self.current_key = new_key
        self.last_rotation = datetime.now()
        return True

    def encrypt(self, data: str) -> bytes:
        cipher = Fernet(self.current_key)
        return cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data: bytes) -> Optional[str]:
        try:
            return self.cipher_suite.decrypt(encrypted_data).decode()
        except:
            return None

    def get_config(self) -> Dict[str, Any]:
        return {
            'key_rotation_days': self.key_rotation_days,
            'last_rotation': self.last_rotation.isoformat(),
            'next_rotation': (self.last_rotation + timedelta(days=self.key_rotation_days)).isoformat()
        }