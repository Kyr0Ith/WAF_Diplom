# app.py - Основное приложение
import glob

from cryptography.fernet import InvalidToken, Fernet
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, Response, session
from modules.sqli_detection import SQLiDetector
from modules.ip_blocking import IPBlocker
from modules.encryption import EncryptionManager
from modules.logging import AuditLogger
from modules.proxy import ProxyHandler
from modules.auth import login_required, USERNAME, PASSWORD
import threading
import os
import re

app = Flask(__name__)

# Инициализация модулей
encryption_manager = EncryptionManager()
audit_logger = AuditLogger(encryption_manager)
ip_blocker = IPBlocker()
sqli_detector = SQLiDetector()
proxy_handler = ProxyHandler(ip_blocker, sqli_detector, audit_logger)

# Загрузка начальных CRS правил
def load_crs_background():
    if not sqli_detector.crs_rules_loaded():
        sqli_detector.update_crs_rules()

threading.Thread(target=load_crs_background, daemon=True).start()


# ------------------------------
# Веб-интерфейс
# ------------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/modules')
def modules():
    return render_template('modules.html')


@app.route('/sqli_rules')
def sqli_rules():
    return render_template('sqli_rules.html')


@app.route('/ip_blocklist')
def ip_blocklist():
    blocked_ips = ip_blocker.get_blocked_ips()
    return render_template('ip_blocklist.html', blocked_ips=blocked_ips)


@app.route('/logs')
def logs():
    try:
        log_entries = audit_logger.get_logs(decrypt=True)
        # Ограничиваем количество логов для производительности
        return render_template('logs.html', logs=log_entries[-100:])  # Показываем только последние 100 записей
    except Exception as e:
        app.logger.error(f"Error loading logs: {str(e)}")
        return render_template('logs.html', logs=[])


@app.route('/settings')
def settings():
    return render_template('settings.html')




# ------------------------------
# API Endpoints
# ------------------------------




# Управление модулями
@app.route('/api/modules/status', methods=['GET'])
def get_modules_status():
    return jsonify({
        'sqli': sqli_detector.enabled,
        'ip_blocking': ip_blocker.enabled
    })


@app.route('/api/modules/toggle', methods=['POST'])
def toggle_module():
    data = request.get_json()
    module = data.get('module')
    state = data.get('state')

    if module == 'sqli':
        sqli_detector.enabled = state
    elif module == 'ip_blocking':
        ip_blocker.enabled = state
    else:
        return jsonify({'error': 'Invalid module'}), 400

    return jsonify({'success': True})

#test only, not used in ap
app.secret_key = 'your_secret_key_here'  #Replace for prod
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == USERNAME and password == PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect('/login')

# Управление правилами SQLi
@app.route('/api/sqli/rules', methods=['GET'])
def get_sqli_rules():
    return jsonify(sqli_detector.get_rules_report())


@app.route('/api/sqli/rules/custom', methods=['POST'])
def add_custom_rule():
    data = request.get_json()
    rule = data.get('rule')
    if not rule:
        return jsonify({'error': 'Rule is required'}), 400
    sqli_detector.add_custom_rule(rule)
    return jsonify({'success': True})


@app.route('/api/sqli/rules/custom/<int:index>', methods=['DELETE'])
def remove_custom_rule(index):
    sqli_detector.remove_custom_rule(index)
    return jsonify({'success': True})


@app.route('/api/sqli/rules/crs', methods=['PUT'])
def update_crs_rules():
    if sqli_detector.update_crs_rules():
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to update CRS rules'}), 500


# Управление блокировкой IP
@app.route('/api/ip_blocklist', methods=['GET'])
def get_blocked_ips():
    return jsonify(ip_blocker.get_blocked_ips())


@app.route('/api/ip_blocklist/<ip>', methods=['DELETE'])
def unblock_ip(ip):
    ip_blocker.unblock_ip(ip)
    return jsonify({'success': True})


# Логи
@app.route('/api/logs', methods=['GET'])
def get_logs_api():
    logs = audit_logger.get_logs(decrypt=True)
    return jsonify(logs)


MASTER_PASSWORD = os.environ.get("DECRYPTION_PASSWORD", "default_password")

@app.route('/decrypt_logs')
def decrypt_logs():
    return render_template('decrypt_logs.html')


@app.route('/api/logs/decrypt', methods=['POST'])
def decrypt_logs_api():
    # Убедимся, что запрос содержит JSON
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    try:
        data = request.get_json()
        password = data.get('password')

        # Проверка пароля
        if not password:
            return jsonify({'error': 'Missing password'}), 400

        if password != MASTER_PASSWORD:
            return jsonify({'error': 'Invalid decryption password'}), 401

        # Находим все ключи
        key_files = glob.glob("secret.key*")
        keys = []
        for key_file in key_files:
            try:
                with open(key_file, "rb") as f:
                    keys.append(f.read())
            except Exception as e:
                print(f"Error reading key file {key_file}: {str(e)}")
                continue

        # Расшифровка логов
        decrypted_logs = []
        log_file_path = "audit.log"

        if not os.path.exists(log_file_path):
            return jsonify({'error': 'Log file not found'}), 404

        try:
            with open(log_file_path, "rb") as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    # Пробуем все ключи
                    decrypted = None
                    for key in keys:
                        try:
                            cipher = Fernet(key)
                            decrypted = cipher.decrypt(line).decode('utf-8')
                            break
                        except InvalidToken:
                            continue
                        except Exception as e:
                            print(f"Decryption error on line {i}: {str(e)}")

                    if decrypted:
                        decrypted_logs.append(decrypted)
                    else:
                        print(f"Failed to decrypt line {i}")

            return jsonify({
                'success': True,
                'logs': decrypted_logs
            })

        except Exception as e:
            return jsonify({'error': f'File processing error: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# Настройки: ротация ключей
@app.route('/api/settings/rotate_key', methods=['POST'])
def rotate_key():
    if encryption_manager.rotate_key():
        return jsonify({'success': True, 'message': 'Key rotated'})
    return jsonify({'success': False, 'message': 'Key rotation not due yet'})


# Настройки: получение конфигурации шифрования
@app.route('/api/settings/encryption', methods=['GET'])
def get_encryption_settings():
    return jsonify(encryption_manager.get_config())


# Настройки: изменение интервала ротации
@app.route('/api/settings/rotation_interval', methods=['POST'])
def set_rotation_interval():
    data = request.get_json()
    days = data.get('days')
    if days is None:
        return jsonify({'error': 'Missing days parameter'}), 400

    try:
        encryption_manager.key_rotation_days = int(days)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ------------------------------
# Прокси-обработчик
# ------------------------------

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    return proxy_handler.handle_request(path, request)


# Запуск приложения
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)