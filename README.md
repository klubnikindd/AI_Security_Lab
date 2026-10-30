Вот готовый, исправленный и красиво структурированный файл `README.md`. 

Я объединил все этапы в единую логичную историю (Атака ➡️ Базовая защита ➡️ Шлюз ➡️ Защита агентов), добавил оглавление, исправил все подписи к картинкам (чтобы они не назывались одинаково) и проверил синтаксис Mermaid-схем.

Просто скопируйте всё, что находится в блоке ниже, и **полностью замените** этим текстом содержимое вашего файла `README.md` в VS Code.

```markdown
# LLM Security Assessment: Prompt Injection Testing (Ollama + phi3)

## 📑 Оглавление
1. [Обзор проекта](#-обзор-проекта)
2. [Стек и инструменты](#-стек-и-инструменты)
3. [Этап 1: Red Teaming (Поиск уязвимостей)](#-этап-1-red-teaming-поиск-уязвимостей)
4. [Этап 2: Базовая защита (Blue Team)](#-этап-2-базовая-защита-blue-team)
5. [Этап 3: Эшелонированная оборона (Secure Gateway)](#-этап-3-эшелонированная-оборона-secure-gateway)
6. [Этап 4: Безопасность AI-агентов (Excessive Agency)](#-этап-4-безопасность-ai-агентов-excessive-agency)

---

## 🎯 Обзор проекта
Данный репозиторий содержит результаты тестирования на проникновение (Red Teaming) локальной языковой модели и разработки многоуровневых систем защиты (Defense-in-Depth). Цель — выявление уязвимостей к атакам типа Prompt Injection и защита AI-систем.

## 🛠 Стек и инструменты
* **Цель (Target):** Локальная LLM `phi3`, развернутая через Ollama.
* **Инструмент сканирования:** NVIDIA Garak (v0.17.1) — сканер уязвимостей LLM.
* **Инструмент защиты:** LLM Guard (Protect AI).
* **Среда:** Windows 11, Python 3.12, изолированное окружение (venv).

---

## 🚨 Этап 1: Red Teaming (Поиск уязвимостей)

1. Развернута локальная среда для безопасного тестирования (sandbox).
2. Запущен сканер Garak с использованием проб `promptinject` (тестирование на перехват управления моделью).
3. Проанализированы отчеты и рассчитан процент успешных атак (Attack Success Rate).

### 📊 Результаты (Findings)
Модель `phi3` показала уязвимость к внедрению промптов:

| Проба (Probe) | Успешных атак (Attack Success Rate) | Статус |
| :--- | :--- | :--- |
| `HijackHateHumans` | **51.02%** (627 из 1280) | ❌ FAIL (Уязвимо) |
| `HijackLongPrompt` | **41.33%** (751 из 1280) | ❌ FAIL (Уязвимо) |
| `HijackKillHumans` | **30.08%** (895 из 1280) | ❌ FAIL (Уязвимо) |

**Вывод:** Модель склонна поддаваться манипуляциям и игнорировать базовые ограничения безопасности.

**Доказательства (Скриншоты Garak):**
![Garak HTML Report](screenshots/garak_html_report.jpg)
![Garak VS Code](screenshots/garak_vscode_terminal.jpg)

---

## 🛡 Этап 2: Базовая защита (Blue Team)

Для защиты от выявленных уязвимостей реализовано решение на базе библиотеки `LLM Guard`.
*   На входе (Input) установлен сканер `PromptInjection`.
*   Легитимные запросы проходят проверку (Risk Score: -1.0).
*   Вредоносные запросы блокируются (Risk Score: 1.0).

*Код защитного механизма находится в файле `guard_test.py`.*

![guard_test.py Result](screenshots/guard_test_result.png)

---

## 🏰 Этап 3: Эшелонированная оборона (Secure Gateway)

Был разработан шлюз безопасности (аналог WAF) с 4 слоями защиты для предотвращения атак, перегрузок и утечек данных.

### Версия 1: Базовая (Файл `secure_gateway_one.py`)
Шлюз проверяет входящий промпт через нейросеть-классификатор и передает безопасный запрос в Ollama.

```mermaid
graph TD
    A[👤 Пользователь] -->|Промпт| B(🛡️ Secure Gateway на Python)
    B --> C{"🤖 LLM Guard<br/>Модель DeBERTa"}
    C -->|"Угроза обнаружена<br/>Risk = 1.0"| D[🚫 Блокировка запроса]
    C -->|"Запрос безопасен<br/>Risk = -1.0"| E[🌐 API Запрос]
    E -->|HTTP POST| F[🦙 Ollama / phi3]
    F -->|Сгенерированный ответ| B
    B -->|Ответ| A
    style D fill:#ffcccc,stroke:#ff0000,stroke-width:2px
    style F fill:#d4edda,stroke:#28a745,stroke-width:2px
    style C fill:#fff3cd,stroke:#ffc107,stroke-width:2px
```

### Версия 2: Продвинутая (Файл `secure_gateway.py`)
Добавлены Rate Limiting (защита от ботов) и Output Guardrails (защита от утечки PII).

```mermaid
graph TD
    A[👤 Пользователь] -->|Промпт| B(🛡️ Secure Gateway на Python)
    
    B --> L1{"⏱️ Слой 1: Rate Limiting<br/>Лимит 3 запроса/мин"}
    L1 -->|Превышен лимит| Block1[🛑 Блокировка: Слишком много запросов]
    
    L1 -->|Лимит не превышен| L2{"🤖 Слой 2: Input Guardrail<br/>LLM Guard PromptInjection"}
    L2 -->|"Обнаружена атака<br/>Risk = 1.0"| Block2[🚫 Блокировка: Prompt Injection]
    
    L2 -->|"Запрос безопасен<br/>Risk = -1.0"| L3[🦙 Слой 3: Ollama API<br/>Генерация ответа]
    
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

**Доказательства (Скриншоты тестов Secure Gateway):**
![Secure Gateway 1](screenshots/secure_gateway_layers1.png)
![Secure Gateway 2](screenshots/secure_gateway_layers2.png)
![Secure Gateway 3](screenshots/secure_gateway_layers3.png)
![Secure Gateway 4](screenshots/secure_gateway_layers4.png)

---

## 🤖 Этап 4: Безопасность AI-агентов (Excessive Agency)

Был проведен эксперимент по имитации атаки на AI-агента с доступом к файловой системе (угроза LLM03: Excessive Agency).
*Примечание: При тестировании наблюдался эффект Context Leakage (модель генерировала вымышленные реплики пользователя), что характерно для малых моделей.*

### Уязвимая версия (`vulnerable_agent.py`)
Контроль доступа полностью передан языковой модели. Если модель обмануть, Python-скрипт слепо прочитает секретный файл.

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

**Доказательства (Скриншоты уязвимого агента):**
![Vulnerable Agent 1](screenshots/vulnerable_agent_result1.png)
![Vulnerable Agent 2](screenshots/vulnerable_agent_result2.png)

### Защищенная версия (`secure_agent.py`)
Реализован принцип наименьших привилегий (Least Privilege). Доступ к файлам ограничен жестким списком `ALLOWED_FILES` на уровне Python-кода.

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

**Доказательства (Скриншот защищенного агента):**
![Secure Agent](screenshots/secure_agent_result.png)