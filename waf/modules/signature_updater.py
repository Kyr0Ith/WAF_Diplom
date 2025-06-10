import requests
import re
from .base_module import BaseModule

class Signature_updater(BaseModule):
    def __init__(self):
        super().__init__()
        self.priority = 4
        self.signature_update_url = ""

    def load_config(self, config):
        """Загрузка URL для обновления сигнатур"""
        super().load_config(config)
        if self.enabled:
            self.signature_update_url = config.get("signature_update_url", "")

    def update_signatures(self):
        """Обновление сигнатур из OWASP CRS"""
        try:
            response = requests.get(self.signature_update_url, timeout=10)
            if response.status_code == 200:
                rules = re.findall(r"SecRule ARGS|REQUEST_HEADERS \"(.*?)\"", response.text)
                return [f"({rule})" for rule in rules]
        except Exception as e:
            print(f"Ошибка загрузки сигнатур: {str(e)}")
            return []

    def process_request(self):
        """Не участвует в обработке запроса"""
        return None