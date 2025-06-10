from flask import request

class BaseModule:
    def __init__(self):
        self.enabled = False  #state of module
        self.priority = 0     #lower = higher priority

    def process_request(self):
        """
        Обработка запроса.
        Должна вернуть:
        - None: продолжить обработку
        - Response: остановить обработку и вернуть ответ
        """
        raise NotImplementedError("Метод process_request должен быть реализован в дочернем классе")

    def load_config(self, config):
        """Загрузка параметров из config.json"""
        self.enabled = config.get("enabled", False)