import os
from typing import List, Dict, Any
from datetime import datetime


class AuditLogger:
    def __init__(self, encryption_manager):
        self.encryption_manager = encryption_manager
        self.log_file = "audit.log"

    def log(self, ip: str, method: str, param: str, value: str):
        """Логирование события атаки"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Ограничиваем длину значения и экранируем разделители
            safe_value = (value[:500] + '...') if len(value) > 500 else value
            safe_value = safe_value.replace('|', '_').replace('\n', ' ').replace('\r', ' ')

            log_entry = f"{timestamp} | IP: {ip} | Method: {method} | Param: {param} | Value: {safe_value}"
            encrypted_log = self.encryption_manager.encrypt(log_entry)
            with open(self.log_file, "ab") as f:
                f.write(encrypted_log + b"\n")
        except Exception as e:
            print(f"Logging error: {str(e)}")

    def get_logs(self, decrypt: bool = False) -> List[str]:
        """Чтение логов"""
        logs = []
        if not os.path.exists(self.log_file):
            return []

        with open(self.log_file, "rb") as f:
            for line in f:
                line = line.strip()
                if decrypt:
                    decrypted = self.encryption_manager.decrypt(line)
                    if decrypted:
                        logs.append(decrypted)
                else:
                    logs.append(line.decode('latin1'))
        return logs