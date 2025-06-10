# modules/sqli_detection.py
import re
import requests
from pathlib import Path
import json
from datetime import datetime
import os
from typing import List, Dict, Any


class SQLiDetector:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.builtin_patterns = self._load_builtin_patterns()
        self.custom_patterns = []
        self.crs_patterns = []
        self._compile_all_patterns()

        # Настройки CRS
        self.crs_update_url = "https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3/dev/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
        self.crs_local_file = Path("crs_sqli_rules.json")
        self.crs_fallback_file = Path("crs_fallback_rules.txt")

        # Загружаем CRS правила, если есть сохраненные
        if self.crs_local_file.exists():
            self._load_crs_rules()

    def _load_builtin_patterns(self) -> List[str]:
        """Надежные встроенные правила"""
        return [
            r"\b(?:union|select|insert|update|delete|drop|alter|create|truncate)\b",
            r"\b(?:and|or)\s+[\w]+\s*[=<>]+\s*[\w]+",
            r"\bwaitfor\s+delay\b",
            r"\bpg_sleep\b",
            r"\bversion\s*\(\s*\)",
            r"\bconcat\s*\(",
            r"\bgroup_concat\s*\(",
            r"\bif\s*\(",
            r"\bcase\s+when\b",
            r"\bexec\s*\(",
            r"\bxp_cmdshell\b",
            r"\bload_file\s*\(",
            r"\binto\s+(?:out|dump)file\b",
            r"\bselect\b.*?\bfrom\b",
            r"\binsert\b.*?\binto\b",
            r"\bupdate\b.*?\bset\b",
            r"\bdelete\b.*?\bfrom\b",
            r"\bdrop\b.*?\btable\b",
            r"\bunion\b.*?\bselect\b",
            r"\bor\b\s*\d+\s*=\s*\d+",
            r"';?\s*--\s*$",
            r"';?\s*/\*.*?\*/"
        ]

    def _load_crs_rules(self):
        """Загрузка CRS правил из локального файла"""
        try:
            with open(self.crs_local_file, 'r') as f:
                data = json.load(f)
                self.crs_patterns = data.get('rules', [])
                self._compile_all_patterns()
        except:
            self.crs_patterns = []

    def _compile_all_patterns(self):
        """Компиляция всех правил"""
        all_patterns = self.builtin_patterns + self.custom_patterns + self.crs_patterns
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in all_patterns]

    def crs_rules_loaded(self) -> bool:
        return len(self.crs_patterns) > 0

    def parse_crs_rules(self, content: str) -> List[str]:
        """Извлечение и упрощение правил CRS"""
        rules = []

        # Основные шаблоны для извлечения правил
        patterns = [
            r'SecRule[^\n]*?"@rx\s+([^"]+)"',
            r'SecRule[^\n]*?rx:"([^"]+)"',
            r'SecRule[^\n]*?@rx\s+([^\s"\']+)',
            r'SecRule[^\n]*?rx:([^\s"\']+)'
        ]

        # Извлекаем все совпадения
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Очистка и упрощение правила
                simplified = self.simplify_rule(match.strip())
                if simplified:
                    rules.append(simplified)

        return list(set(rules))

    def simplify_rule(self, rule: str) -> str:
        """Упрощение сложных правил для совместимости с Python re"""
        # Удаляем сложные и несовместимые конструкции
        simplified = rule

        # Удаляем модификаторы (?i) и подобные
        simplified = re.sub(r'\(\?[a-z-]+\)', '', simplified)

        # Удаляем lookahead/lookbehind (?=, ?!, ?<=, ?<!)
        simplified = re.sub(r'\(\?[=!][^)]+\)', '', simplified)

        # Удаляем именованные группы (?<name>...)
        simplified = re.sub(r'\(\?<[^>]+>', '(', simplified)

        # Заменяем сложные классы символов
        simplified = re.sub(r'\[\^[^\]]+\]', '[^]', simplified)

        # Удаляем экранирование там, где оно не нужно
        simplified = simplified.replace(r'\"', '"')
        simplified = simplified.replace(r"\'", "'")
        simplified = simplified.replace(r'\/', '/')

        # Фикс незакрытых скобок
        open_count = simplified.count('(')
        close_count = simplified.count(')')
        if open_count > close_count:
            simplified += ')' * (open_count - close_count)

        # Проверяем, что правило не слишком сложное
        if len(simplified) > 500:
            return None

        # Проверяем на явно несовместимые конструкции
        incompatible_patterns = [
            r'\\p\{', r'\\P\{', r'\[\[:', r'\(\?<', r'\(\?[=!]'
        ]
        for pattern in incompatible_patterns:
            if re.search(pattern, simplified):
                return None

        return simplified

    def load_fallback_rules(self) -> List[str]:
        """Загрузка резервных правил из файла"""
        if not self.crs_fallback_file.exists():
            return self.builtin_patterns.copy()

        try:
            with open(self.crs_fallback_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except:
            return self.builtin_patterns.copy()

    def update_crs_rules(self) -> bool:
        """Загрузка и обработка CRS правил"""
        try:
            # Пробуем загрузить из сети
            try:
                response = requests.get(self.crs_update_url, timeout=10)
                response.raise_for_status()
                crs_content = response.text
                print("Successfully downloaded CRS rules from GitHub")
            except Exception as e:
                print(f"Failed to download CRS rules: {str(e)}")
                crs_content = None

            # Если не удалось загрузить, используем резервные правила
            if not crs_content:
                self.crs_patterns = self.load_fallback_rules()
                self._compile_all_patterns()
                return True

            # Парсинг правил
            new_rules = self.parse_crs_rules(crs_content)

            # Фильтрация и валидация
            valid_rules = []
            for rule in new_rules:
                try:
                    # Проверяем, что правило компилируется
                    re.compile(rule)
                    valid_rules.append(rule)
                except Exception as e:
                    print(f"Skipping invalid pattern: {rule} - {str(e)}")

            # Если правил мало, добавляем резервные
            if len(valid_rules) < 15:
                print(f"Only {len(valid_rules)} valid rules found, adding fallback rules")
                fallback_rules = self.load_fallback_rules()
                valid_rules.extend(fallback_rules)
                valid_rules = list(set(valid_rules))  # Удаляем дубликаты

            self.crs_patterns = valid_rules
            self._compile_all_patterns()

            # Сохраняем
            with open(self.crs_local_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'rules': self.crs_patterns
                }, f)

            print(f"Successfully loaded {len(valid_rules)} CRS rules")
            return True
        except Exception as e:
            print(f"CRS update failed: {str(e)}")
            return False

    def sanitize_regex(self, pattern: str) -> str:
        """Создание безопасной версии сложного regex"""
        # Упрощаем сложные конструкции
        sanitized = re.sub(r'\(\?[^:)]*:', '(', pattern)  # Удаляем флаги внутри групп
        sanitized = re.sub(r'\\[pP]\{.*?\}', '', sanitized)  # Удаляем Unicode свойства
        sanitized = re.sub(r'\[\^.*?\]', '[^]', sanitized)  # Упрощаем негативные классы
        sanitized = re.sub(r'\(\??<[^>]+>', '(', sanitized)  # Удаляем именованные группы
        sanitized = re.sub(r'\(\?[=!]', '(', sanitized)  # Удаляем lookahead/lookbehind

        # Фикс незакрытых групп
        open_count = sanitized.count('(')
        close_count = sanitized.count(')')

        if open_count > close_count:
            sanitized += ')' * (open_count - close_count)

        # Удаляем несовместимые флаги
        sanitized = re.sub(r'\(\?[ims-]+\)', '', sanitized)

        return sanitized

    def add_custom_rule(self, rule: str):
        """Добавление пользовательского правила"""
        self.custom_patterns.append(rule)
        self._compile_all_patterns()

    def remove_custom_rule(self, index: int):
        """Удаление пользовательского правила по индексу"""
        if 0 <= index < len(self.custom_patterns):
            self.custom_patterns.pop(index)
            self._compile_all_patterns()

    def get_rules_report(self) -> Dict[str, Any]:
        """Отчет по всем правилам"""
        return {
            'builtin': {
                'count': len(self.builtin_patterns),
                'sample': self.builtin_patterns[:3] if self.builtin_patterns else []
            },
            'crs': {
                'count': len(self.crs_patterns),
                'sample': self.crs_patterns[:3] if self.crs_patterns else [],
                'last_update': self._get_crs_last_update()
            },
            'custom': {
                'count': len(self.custom_patterns),
                'rules': self.custom_patterns
            },
            'total_rules': len(self.builtin_patterns) + len(self.crs_patterns) + len(self.custom_patterns)
        }

    def _get_crs_last_update(self) -> str:
        """Получение времени последнего обновления CRS"""
        if self.crs_local_file.exists():
            with open(self.crs_local_file) as f:
                data = json.load(f)
                return data.get('timestamp', 'unknown')
        return 'never'

    def is_sqli(self, data: str) -> bool:
        """Проверка строки на SQLi"""
        if not self.enabled:
            return False
        for pattern in self.compiled_patterns:
            if pattern.search(data):
                return True
        return False