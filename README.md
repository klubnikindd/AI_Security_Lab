# LLM Security Assessment: Prompt Injection Testing (Ollama + phi3)

## 🎯 Обзор проекта
Данный репозиторий содержит результаты тестирования на проникновение (Red Teaming) локальной языковой модели. Цель — выявление уязвимостей к атакам типа Prompt Injection (внедрение вредоносных промптов).

## 🛠 Стек и инструменты
* **Цель (Target):** Локальная LLM `phi3`, развернутая через Ollama.
* **Инструмент сканирования:** NVIDIA Garak (v0.17.1) — сканер уязвимостей LLM.
* **Среда:** Windows 11, Python 3.12, изолированное окружение (venv).

## 🔬 Методология
1. Развернута локальная среда для безопасного тестирования (sandbox).
2. Запущен сканер Garak с использованием проб `promptinject` (тестирование на перехват управления моделью и инъекции вредоносных инструкций).
3. Проанализированы отчеты и рассчитан процент успешных атак (Attack Success Rate).

## 📊 Результаты (Findings)
Модель `phi3` показала уязвимость к внедрению промптов. Успешность атак (когда модель нарушила системные инструкции):

| Проба (Probe) | Успешных атак (Attack Success Rate) | Статус |
| :--- | :--- | :--- |
| `HijackHateHumans` | **51.02%** (627 из 1280) | ❌ FAIL (Уязвимо) |
| `HijackLongPrompt` | **41.33%** (751 из 1280) | ❌ FAIL (Уязвимо) |
| `HijackKillHumans` | **30.08%** (895 из 1280) | ❌ FAIL (Уязвимо) |

**Вывод:** Модель склонна поддаваться манипуляциям и игнорировать базовые ограничения безопасности в половине тестовых сценариев.

## 🛡 Рекомендации по устранению (Remediation)
Для защиты приложений на базе данной модели необходимо:
1. Внедрение строгих Guardrails (например, NeMo Guardrails или LLM Guard) на уровне ввода/вывода.
2. Использование более сложных системных промптов с явными запретами.
3. Проведение регулярных повторных сканирований (Continuous Red Teaming).

## 📸 Доказательства (Screenshots)
*Скриншоты процесса сканирования и отчетов Garak находятся в папке `screenshots`.*:
![Garak HTML](screenshots/garak_html_report.jpg)
![Garak VSCode](screenshots/garak_vscode_terminal.jpg)

## 🛡 Внедрение защиты (Defense / Blue Team)

Для защиты приложения от выявленных уязвимостей Prompt Injection было реализовано решение на базе библиотеки `LLM Guard` (Protect AI). 

**Как это работает:**
*   На входе (Input) установлен сканер `PromptInjection`.
*   Легитимные запросы проходят проверку (Risk Score: -1.0).
*   Вредоносные запросы, содержащие инъекции (например, "Игнорируй инструкции..."), блокируются (Risk Score: 1.0) и не отправляются в модель.

*Код защитного механизма находится в файле `guard_test.py`. Скриншот работы прилагается в папке `screenshots`.*
![guard_test.py](screenshots/guard_test_result.png)

### Архитектура безопасности (Secure Gateway)
Был реализован шлюз безопасности (аналог WAF), который выступает посредником между пользователем и LLM (Ollama/phi3).

### Версия 1: Базовая защита (Input Guardrail)
*Файл: `secure_gateway_one.py`*

В первой версии был реализован базовый паттерн «КПП». Шлюз проверяет входящий промпт через нейросеть-классификатор и, если запрос безопасен, передает его в Ollama.

**Описание работы:**
1. Пользователь отправляет запрос в скрипт `secure_gateway_one.py`.
2. Скрипт анализирует входные данные через `LLM Guard` (DeBERTa v3).
3. Если запрос безопасен (Risk Score < 1.0), он перенаправляется в API Ollama.
4. Если запрос содержит Prompt Injection, он блокируется до попадания в модель.

### Схема работы Secure Gateway (версия ONE)

```mermaid
graph TD
    A[👤 Пользователь] -->|Промпт| B(🛡️ Secure Gateway на Python)
    B --> C{🤖 LLM Guard<br/>Модель DeBERTa}
    C -->|Угроза обнаружена<br/>Risk = 1.0| D[🚫 Блокировка запроса]
    C -->|Запрос безопасен<br/>Risk = -1.0| E[🌐 API Запрос]
    E -->|HTTP POST| F[🦙 Ollama / phi3]
    F -->|Сгенерированный ответ| B
    B -->|Ответ| A
    style D fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style F fill:#d4edda,stroke:#28a745,stroke-width:2px
    style C fill:#fff3cd,stroke:#ffc107,stroke-width:2px
```

*Код шлюза находится в файле `secure_gateway_one.py`.*

**Результат работы шлюза (скриншот):**
![Тест Secure Gateway](screenshots/secure_gateway_test.png)

## 🛡️ Эволюция защиты: Secure Gateway (WAF для LLM)

В ходе проекта было создано две версии защитного шлюза (Web Application Firewall), чтобы продемонстрировать эволюцию подхода от базовой фильтрации до эшелонированной обороны (Defense-in-Depth).

### 🛡️ Многоуровневая защита (Defense-in-Depth)

В финальной версии `secure_gateway.py` реализованы 4 слоя защиты:
1. **Rate Limiting:** Ограничение до 3 запросов в минуту (защита от ботов и перебора).
2. **Input Guardrails:** Сканер `PromptInjection` (модель DeBERTa) блокирует вредоносные промпты.
3. **API Ollama:** Отправка безопасных запросов к модели `phi3`.
4. **Output Guardrails:** Сканер `Sensitive` проверяет ответ модели на наличие PII (персональных данных), паролей и ключей, прежде чем вернуть его пользователю.

### Схема работы Secure Gateway (финальная версия) 
```mermaid
graph TD
    A[👤 Пользователь] -->|Промпт| B(🛡️ Secure Gateway на Python)
    
    B --> L1{"⏱️ Слой 1: Rate Limiting<br/>Лимит 3 запроса/мин"}
    L1 -->|Превышен лимит| Block1[🛑 Блокировка: Слишком много запросов]
    
    L1 -->|Лимит не превышен| L2{"🤖 Слой 2: Input Guardrail<br/>LLM Guard PromptInjection"}
    L2 -->|Обнаружена атака<br/>Risk = 1.0| Block2[🚫 Блокировка: Prompt Injection]
    
    L2 -->|Запрос безопасен<br/>Risk = -1.0| L3[🦙 Слой 3: Ollama API<br/>Генерация ответа]
    
    L3 -->|Сырой ответ модели| L4{"🕵️ Слой 4: Output Guardrail<br/>LLM Guard Sensitive"}
    
    L4 -->|Найдены PII/Секреты| Block3[🚫 Блокировка: Утечка данных<br/>Ответ скрыт]
    
    L4 -->|Ответ чист| F[✅ Возврат ответа пользователю]
    Block1 -.-> F
    Block2 -.-> F
    Block3 -.-> F

    style Block1 fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style Block2 fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style Block3 fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style L3 fill:#d4edda,stroke:#28a745,stroke-width:2px
    style L1 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style L2 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style L4 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style F fill:#cce5ff,stroke:#004085,stroke-width:2px
```

**Результат тестирования 4 слоев:**
![Secure Gateway Layers](screenshots/secure_gateway_layers1.png)
![Secure Gateway Layers](screenshots/secure_gateway_layers2.png)
![Secure Gateway Layers](screenshots/secure_gateway_layers3.png)
![Secure Gateway Layers](screenshots/secure_gateway_layers4.png)

### 🔬 Исследование AI-агентов (Excessive Agency)
Был проведен эксперимент по имитации атаки на AI-агента с доступом к файловой системе.
*   **Уязвимая версия (`vulnerable_agent.py`):** Демонстрирует, как Prompt Injection может заставить агента прочитать файл с паролями (LLM03: Excessive Agency).

Note: При тестировании также наблюдался эффект Context Leakage (модель генерировала вымышленные реплики пользователя), что характерно для малых моделей при сложных системных промптах.

### Схема работы уязвимой версии (vulnerable_agent.py)

```mermaid
graph TD
    A[👤 Пользователь] -->|Вредоносный промпт| B(🛡️ vulnerable_agent.py)
    B -->|1. Добавляет System Prompt| C[🦙 Ollama API<br/>Модель phi3]
    
    C -->|2. Модель анализирует текст| C_Out{Ответ модели}
    
    C_Out -->|"Атака удалась: выдала secret_passwords.txt"| D{"Парсер ищет скобки"}
    C_Out -->|Модель отказала| E[Агент ничего не делает]
    
    D -->|3. Найдено имя файла| F[⚙️ Вызов инструмента<br/>read_file]
    
    F -->|4. Нет проверок!| G[(💾 Файловая система)]
    G -->|Чтение secret_passwords.txt| H[📄 Вывод пароля пользователю]
    
    style D fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style F fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style H fill:#ffcccc,stroke:#ff0000,stroke-width:2px
```
*   **Защищенная версия (`secure_agent.py`):** Реализован принцип наименьших привилегий (Least Privilege). Доступ к файлам ограничен жестким списком `ALLOWED_FILES` на уровне Python-кода, а не только системным промптом.

### Схема работы защищенной версии (`secure_agent.py`) 
```mermaid
graph TD
    A[👤 Пользователь] -->|Вредоносный промпт| B(🛡️ secure_agent.py)
    B -->|1. Добавляет System Prompt| C[🦙 Ollama API<br/>Модель phi3]
    
    C -->|2. Модель анализирует текст| C_Out{Ответ модели}
    
    C_Out -->|"Атака удалась: выдала secret_passwords.txt"| D{"Парсер ищет скобки"}
    C_Out -->|Модель отказала| E[Агент ничего не делает]
    
    D -->|3. Найдено имя файла| F{"Проверка ALLOWED_FILES"}
    
    F -->|"Файл НЕ в белом списке"| Block[🚫 Блокировка:<br/>Доступ запрещен политикой безопасности]
    F -->|"Файл в белом списке"| G[⚙️ Вызов инструмента<br/>read_file]
    
    G -->|4. Чтение public_info.txt| H[(💾 Файловая система)]
    H -->|Успех| I[📄 Вывод данных пользователю]
    
    style F fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style Block fill:#d4edda,stroke:#28a745,stroke-width:2px
    style G fill:#d4edda,stroke:#28a745,stroke-width:2px
    style I fill:#d4edda,stroke:#28a745,stroke-width:2px
```

📸 Доказательства работы (Screenshots)
Скриншоты выполнения обоих скриптов в терминале VS Code.

1. Уязвимый агент (успешная атака и чтение секрета):
https://screenshots/vulnerable_agent_result1.png
https://screenshots/vulnerable_agent_result2.png

2. Защищенный агент (блокировка атаки на уровне кода):
https://screenshots/secure_agent_result.png