# Модель угроз (Threat Model) — AI_Security_Lab

Таблица сопоставляет классы угроз из OWASP Top 10 for LLM со слоями защиты, реализованными в данном проекте.

| # | Угроза (Threat) | Вектор атаки (Vector) | Слой защиты (Mitigation) | Статус |
| :--- | :--- | :--- | :--- | :--- |
| T1 | Прямая промпт-инъекция (Direct Prompt Injection) | Пользовательский ввод | Input Guardrail (LLM Guard / DeBERTa) | ✅ Покрыто |
| T2 | Косвенная инъекция через RAG (Indirect Injection) | Отравленный документ в базе | Проверка чанков при индексации (RAG v2) | ✅ Покрыто |
| T3 | Утечка PII в ответе | Галлюцинация модели | Sensitive + Presidio + энтропийный анализ | ⚠️ Fail-open (см. STATUS) |
| T4 | Перефразированная утечка секретов | Обфускация вывода | LLM-судья (адаптивный вызов) | ⚠️ Инъектируем (см. STATUS) |
| T5 | Излишняя автономность агента (Excessive Agency) | Вызов инструментов агентом | Allowlist в `secure_agent.py` | ✅ Покрыто |
| T6 | Path Traversal через MCP-сервер | `../../etc/passwd` | Проверка путей в `secure_file_scanner.py` | 🔧 В процессе |
| T7 | DoS / брутфорс через флуд запросами | Множественные вызовы `/chat` | Rate Limiting | ⚠️ Только in-memory |