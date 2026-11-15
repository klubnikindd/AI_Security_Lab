import os
import re
import base64
import unicodedata
import logging
from pathlib import Path
from urllib.parse import urlparse
from mcp.server import MCPServer
from bs4 import BeautifulSoup, Comment, Tag

# 🔒 БЕЗОПАСНОСТЬ: Определяем разрешенную корневую директорию.
# Агент сможет читать только файлы внутри этой папки.
SAFE_WORKSPACE_DIR = Path(__file__).parent.resolve()

# 🔒 FAIL-CLOSED: Инициализация LLM Guard на уровне модуля (чтобы не грузить модель при каждом запросе)
try:
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MatchType
    
    # Инициализируем сканер один раз
    injection_scanner = PromptInjection(match_type=MatchType.FULL)
    LLM_GUARD_AVAILABLE = True
    logging.info("✅ LLM Guard успешно инициализирован.")
except ImportError:
    logging.critical("❌ КРИТИЧЕСКАЯ ОШИБКА: llm-guard не установлен! Чтение файлов будет заблокировано (Fail-Closed).")
    LLM_GUARD_AVAILABLE = False
    injection_scanner = None

mcp = MCPServer("Secure File Scanner")

def decode_base64_strings(text: str) -> str:
    """Находит строки, похожие на Base64, декодирует их и возвращает объединенный текст."""
    pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(pattern, text)
    
    decoded_parts = []
    for match in matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if decoded.strip():
                decoded_parts.append(decoded)
        except Exception as e:
            logging.debug(f"[Scanner] Ошибка декодирования Base64: {e}")
            continue 
            
    return text + ("\n" + "\n".join(decoded_parts) if decoded_parts else "")

def remove_zero_width_chars(text: str) -> str:
    """Удаляет невидимые Unicode-символы (Zero-Width, BOM)."""
    return ''.join(c for c in text if unicodedata.category(c) != 'Cf')

def strip_hidden_html(content: str) -> str:
    """Удаляет HTML-комментарии и скрытый текст (CSS color:white, display:none)."""
    soup = BeautifulSoup(content, "html.parser")
    
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    
    hidden_styles = ['display:none', 'visibility:hidden', 'font-size:0', 'color:white', 'color:#fff']
    for tag in soup.find_all(True):
        style = (tag.get('style') or '').replace(' ', '').lower()
        if any(hs in style for hs in hidden_styles):
            tag.decompose()
            
    return soup.get_text()

def remove_markdown_comments(text: str) -> str:
    """Удаляет Markdown-комментарии [//]: # (...)."""
    return re.sub(r'\[//\]:\s*#\s*\([^)]*\)', '', text)

def extract_suspicious_urls(text: str) -> list:
    """Возвращает список подозрительных URL (не whitelisted)."""
    allowed_domains = ['github.com', 'habr.com', 'ollama.com']
    urls = re.findall(r'https?://[^\s\)"\']+', text)
    
    suspicious = []
    for u in urls:
        try:
            # 🔒 ЗАЩИТА: Строгая проверка hostname (защита от github.com.evil.com)
            hostname = urlparse(u).hostname
            if not hostname:
                suspicious.append(u)
                continue
            
            # Проверяем точное совпадение домена или поддомена
            is_allowed = any(hostname == d or hostname.endswith(f".{d}") for d in allowed_domains)
            if not is_allowed:
                suspicious.append(u)
        except Exception:
            suspicious.append(u)
            
    return suspicious

@mcp.tool()
def secure_read_file(file_path: str) -> str:
    """
    Безопасно читает файл, применяя многоуровневую очистку
    и проверку через LLM Guard на наличие Prompt Injection.
    """
    # 1. FAIL-CLOSED: Проверка наличия ML-защиты
    if not LLM_GUARD_AVAILABLE:
        return "🚫 Ошибка безопасности: Система защиты (LLM Guard) недоступна. Чтение файла заблокировано."

    # 2. PATH TRAVERSAL: Проверка безопасного пути
    try:
        # .resolve() раскрывает ../ и симлинки в реальный путь
        target_path = Path(file_path).resolve()
        
        # Проверяем, находится ли файл внутри разрешенной директории
        if not target_path.is_relative_to(SAFE_WORKSPACE_DIR):
            logging.warning(f"⛔ Попытка Path Traversal! Запрошен: {file_path}")
            return "🚫 Ошибка безопасности: Доступ к файлам за пределами рабочей директории запрещен."
            
        if not target_path.is_file():
            return f"Ошибка: Файл '{file_path}' не найден."
            
        content = target_path.read_text(encoding="utf-8")
    except Exception as e:
        return f"Ошибка при чтении файла: {e}"

    # --- Слой 1: Санитизация ---
    content = strip_hidden_html(content)
    content = remove_markdown_comments(content)
    content = remove_zero_width_chars(content)
    content = decode_base64_strings(content)

    # --- Слой 2: Проверка на эксфильтрацию ---
    suspicious = extract_suspicious_urls(content)
    if suspicious:
        return f"🚨 БЛОКИРОВКА: Обнаружены подозрительные URL (возможная эксфильтрация): {suspicious}"

    # --- Слой 3: ML-анализ через LLM Guard ---
    try:
        _, is_valid, risk_score = injection_scanner.scan(content)
        
        if not is_valid:
            return f"🚨 БЛОКИРОВКА: Обнаружена угроза Prompt Injection (Risk: {risk_score}). Доступ запрещён."
            
    except Exception as e:
        # Если сканер упал во время работы - тоже блокируем (Fail-Closed)
        logging.error(f"Ошибка при работе сканера LLM Guard: {e}")
        return "🚫 Ошибка безопасности: Сбой модуля проверки LLM Guard. Доступ запрещен."

    return content

if __name__ == "__main__":
    mcp.run()