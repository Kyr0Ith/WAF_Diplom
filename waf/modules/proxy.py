import requests
import zlib
from flask import Response, abort, request
from urllib.parse import urlencode
import re


class ProxyHandler:
    def __init__(self, ip_blocker, sqli_detector, logger):
        self.ip_blocker = ip_blocker
        self.sqli_detector = sqli_detector
        self.logger = logger

    def normalize_input(self, data: str) -> str:
        """Нормализация входных данных"""
        # Упрощенная нормализация: удаление SQL-комментариев и приведение к нижнему регистру
        cleaned = re.sub(r'/\*.*?\*/|--.*?[\r\n]|#.*?[\r\n]', '', data)
        return cleaned.lower()

    def handle_request(self, path, request):
        client_ip = request.remote_addr

        # Проверка на блокировку IP
        if self.ip_blocker.is_blocked(client_ip):
            abort(403, description=f"IP blocked")

        # Проверка GET параметров
        for param, value in request.args.items():
            normalized = self.normalize_input(value)
            if self.sqli_detector.is_sqli(normalized):
                self.ip_blocker.block_ip(client_ip)
                self.logger.log(client_ip, "GET", param, value)
                abort(403, description="Blocked by SQLi Protection")

        # Проверка POST параметров
        if request.method == 'POST':
            for param, value in request.form.items():
                normalized = self.normalize_input(value)
                if self.sqli_detector.is_sqli(normalized):
                    self.ip_blocker.block_ip(client_ip)
                    self.logger.log(client_ip, "POST", param, value)
                    abort(403, description="Blocked by SQLi Protection")

        # Подготовка целевого URL
        query = urlencode(request.args)
        target_url = f"http://localhost:80/{path}?{query}" if query else f"http://localhost:80/{path}"

        # Заголовки: удаляем хоп-бай-хоп
        headers = {
            k: v for k, v in request.headers
            if k.lower() not in ['host', 'accept-encoding', 'connection']
        }
        headers["Accept-Encoding"] = "identity"

        # Проксирование запроса
        try:
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                timeout=10
            )
        except requests.exceptions.RequestException as e:
            abort(502)

        # Обработка сжатия
        content = resp.content
        content_encoding = resp.headers.get('Content-Encoding', '').lower()
        try:
            if content_encoding == 'gzip':
                content = zlib.decompress(content, 16 + zlib.MAX_WBITS)
            elif content_encoding == 'deflate':
                content = zlib.decompress(content)
        except zlib.error:
            pass

        # Фильтрация заголовков ответа
        excluded_headers = ['content-encoding', 'transfer-encoding', 'connection']
        filtered_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in excluded_headers
        }

        return Response(content, resp.status_code, filtered_headers)