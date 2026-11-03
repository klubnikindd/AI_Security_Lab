import os
from mcp.server import MCPServer
from pathlib import Path
from bs4 import BeautifulSoup, Comment

# В MCP 2.x FastMCP переименован в MCPServer
mcp = MCPServer("Secure File Scanner")

@mcp.tool()
def secure_read_file(file_path: str) -> str:
    """
    Безопасно читает файл, удаляя скрытые инструкции (HTML-комментарии)
    и проверяя текст на наличие Prompt Injection.
    """
    path = Path(os.path.abspath(file_path))
    
    print(f"[Scanner] Попытка прочитать файл: {path}")
    print(f"[Scanner] Текущая рабочая директория: {os.getcwd()}")

    if not path.is_file():
        return f"Ошибка: Файл '{path}' не найден."

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        return f"Ошибка при чтении файла: {e}"

    # 1. Извлекаем и удаляем HTML-комментарии
    soup = BeautifulSoup(content, "html.parser")
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    
    if comments:
        print(f"[Scanner] Обнаружены скрытые комментарии в {path}. Удаляем...")
        for comment in comments:
            comment.extract()
    
    clean_content = soup.get_text()

    # 2. Проверка на Prompt Injection
    try:
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType
        
        scanner = PromptInjection(match_type=MatchType.FULL)
        _, is_valid, risk_score = scanner.scan(clean_content)
        
        if not is_valid:
            return f"🚨 БЛОКИРОВКА: В файле '{path}' обнаружена угроза Prompt Injection (Risk: {risk_score}). Доступ запрещён."
            
    except ImportError:
        return "⚠️ Предупреждение: llm-guard не установлен. Файл прочитан без ML-проверки."

    return clean_content

if __name__ == "__main__":
    # В MCP 2.x run() по умолчанию использует stdio[reference:2]
    mcp.run()