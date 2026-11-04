import os
import re
import base64
import unicodedata
from pathlib import Path
from mcp.server import MCPServer
from bs4 import BeautifulSoup, Comment, Tag

mcp = MCPServer("Secure File Scanner")

def decode_base64_strings(text: str) -> str:
    """Находит и декодирует Base64-строки."""
    pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    decoded_parts = []
    for match in re.findall(pattern, text):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if decoded.strip():
                decoded_parts.append(decoded)
        except Exception:
            pass
    return text + ("\n" + "\n".join(decoded_parts) if decoded_parts else "")

def remove_zero_width_chars(text: str) -> str:
    """Удаляет невидимые Unicode-символы (Zero-Width, BOM)."""
    # Категории Cf (Format) и Cs (Surrogate) содержат невидимые символы
    return ''.join(c for c in text if unicodedata.category(c) != 'Cf')

def strip_hidden_html(content: str) -> str:
    """Удаляет HTML-комментарии и скрытый текст (CSS color:white, display:none)."""
    soup = BeautifulSoup(content, "html.parser")
    
    # 1. Удаляем HTML-комментарии
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    
    # 2. Удаляем элементы со скрытым стилем
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
    return [u for u in urls if not any(d in u for d in allowed_domains)]

@mcp.tool()
def secure_read_file(file_path: str) -> str:
    """
    Безопасно читает файл, применяя многоуровневую очистку
    и проверку через LLM Guard на наличие Prompt Injection.
    """
    path = Path(os.path.abspath(file_path))
    
    if not path.is_file():
        return f"Ошибка: Файл '{path}' не найден."

    try:
        content = path.read_text(encoding="utf-8")
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
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType
        
        scanner = PromptInjection(match_type=MatchType.FULL)
        _, is_valid, risk_score = scanner.scan(content)
        
        if not is_valid:
            return f"🚨 БЛОКИРОВКА: Обнаружена угроза Prompt Injection (Risk: {risk_score}). Доступ запрещён."
            
    except ImportError:
        return "⚠️ llm-guard не установлен. Файл прочитан без ML-проверки."

    return content

if __name__ == "__main__":
    mcp.run()