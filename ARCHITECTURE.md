# 🏗 Архитектура проекта

## Общая схема

```mermaid
graph TD
    User["👤 Пользователь"]
    
    subgraph Stack["🐳 Docker Network: ai_security_lab_monitoring"]
        direction TB
        
        subgraph GW["🛡️ secure_gateway — FastAPI :8000"]
            direction TB
            L1{"1. Rate Limiting"}
            L2{"2. Input Guardrail<br/>PromptInjection"}
            L4_1{"4.1 Sensitive<br/>Presidio + NER"}
            L4_2{"4.2 RED_FLAG<br/>Эвристика"}
            L4_3{"4.3 Entropy<br/>Поиск секретов"}
            L4_4{"4.4 LLM Judge<br/>llama3.1 (Adaptive)"}
        end
        
        subgraph EXP["📈 ollama_exporter — FastAPI"]
            PX["Прозрачный прокси<br/>+ сбор токен-метрик"]
        end
        
        Ollama["🦙 ollama_server<br/>phi3 + llama3.1:8b"]
        
        Prom["📈 Prometheus :9090"]
        Graf["📊 Grafana :3000"]
    end
    
    User -->|"POST /chat"| L1
    L1 -->|"OK"| L2
    L2 -->|"safe"| PX
    PX -->|"forward"| Ollama
    Ollama -->|"response"| PX
    PX -->|"response + metrics"| L4_1
    L4_1 -->|"safe"| L4_2
    L4_2 -->|"safe"| L4_3
    L4_3 -->|"safe"| L4_4
    L4_4 -->|"approved"| User
    
    L1 -.->|"429"| User
    L2 -.->|"400"| User
    L4_1 -.->|"403"| User
    L4_2 -.->|"403"| User
    L4_3 -.->|"403"| User
    L4_4 -.->|"403"| User

    Prom -.->|"scrape /metrics"| GW
    Prom -.->|"scrape /metrics"| PX
    Graf -.->|"query"| Prom
    
    style Ollama fill:#d4edda,stroke:#28a745,stroke-width:2px
    style L4_4 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style L2 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style L4_1 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style L4_2 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style L4_3 fill:#fff3cd,stroke:#ffc107,stroke-width:2px
    style Prom fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style Graf fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
```

## Описание компонентов

| Компонент | Порт | Роль |
| :--- | :--- | :--- |
| **secure_gateway** | 8000 | FastAPI-шлюз с 6 слоями защиты |
| **ollama_exporter** | 8000 (внутр.) | Кастомный прозрачный прокси, считает токены и скорость генерации |
| **ollama_server** | 11434 | Локальные LLM: `phi3` (основная) и `llama3.1:8b` (судья) |
| **prometheus** | 9090 | Сбор метрик с gateway и exporter |
| **grafana** | 3000 | Визуализация: дашборды Security и Performance |

## Поток запроса (Defense-in-Depth)

1. **Пользователь** отправляет `POST /chat` с промптом.
2. **Слой 1: Rate Limiting.** In-memory sliding window (3 запроса/мин). Если лимит превышен — `429 Too Many Requests`.
3. **Слой 2: Input Guardrail.** Сканер `PromptInjection` (модель DeBERTa) проверяет вход. Если риск > 0.5 — `400 Bad Request`.
4. **Слой 3: Генерация (Ollama).** Запрос уходит в `ollama-exporter`, который проксирует его в `ollama:11434` (модель `phi3`). Экспортер извлекает метрики (`eval_count`, `eval_duration`) и обновляет `ollama_tokens_per_second`.
5. **Слой 4.1: Sensitive (LLM Guard + Presidio).** Проверка на PII (email, карты, имена). Если найдено — `403 Forbidden`.
6. **Слой 4.2: RED_FLAG.** Быстрая эвристика на слова-маркеры (`password`, `secret`, `.env`). Если найдено — `403 Forbidden`.
7. **Слой 4.3: Entropy.** Поиск высокоэнтропийных строк (API-ключи) с контекстным окном. Если найдено — `403 Forbidden`.
8. **Слой 4.4: LLM Judge (Adaptive).** Если входной риск был > 0.5 (серая зона), вызывается `llama3.1`, которая семантически оценивает ответ. Если небезопасно — `403 Forbidden`. Если риск был низким, судья пропускается (`[judge_skipped]`) для экономии GPU.
9. **Ответ** возвращается пользователю.

## Наблюдаемость (Observability)

- **Gateway** экспортирует метрики бизнес-логики:
  - `gateway_requests_total`, `gateway_input_blocked_total`, `gateway_output_blocked_total`
  - `gateway_judge_blocked_total`, `gateway_judge_skipped_total`
  - `gateway_red_flag_blocked_total`, `gateway_entropy_blocked_total`, `gateway_sensitive_blocked_total`
  - `gateway_rate_limited_total`
- **Exporter** экспортирует метрики моделей:
  - `ollama_requests_total{model}`, `ollama_generated_tokens_total{model}`
  - `ollama_tokens_per_second{model}`, `ollama_request_duration_seconds`
- **Prometheus** скрейпит оба эндпоинта каждые 5 секунд.
- **Grafana** визуализирует данные на двух дашбордах: Security и Performance.

## Дополнительные research-артефакты

Помимо основного стека, в репозитории есть отдельные исследования, не входящие в `docker-compose.yml`:

```mermaid
graph TB
    subgraph MCP["🔒 MCP Secure File Scanner"]
        A1["🤖 Cline (AI Agent)"] -->|"tool call"| SC["secure_read_file<br/>санитизация + LLM Guard"]
        SC -->|"safe"| FS["📁 Файловая система"]
        SC -->|"injection"| BA["🚨 Блок"]
    end
    
    subgraph RAG["📚 Secure RAG v2 (LangChain + ChromaDB)"]
        Q["👤 Пользователь"] -->|"query"| IS["Input Guard"]
        IS -->|"safe"| DB["🗄 ChromaDB"]
        DB -->|"chunks"| CG["Context Guard"]
        CG -->|"safe"| LLM["🦙 phi3"]
        LLM -->|"response"| OS["Output Guard"]
        OS -->|"safe"| Q
    end
    
    style BA fill:#ffcccc,stroke:#ff0000,stroke-width:2px
```

- **MCP Secure File Scanner** (`secure_file_scanner.py`) — защита AI-агента от Indirect Prompt Injection при чтении файлов. Отчёт: [AGENT_ATTACK_REPORT.md](AGENT_ATTACK_REPORT.md).
- **Secure RAG v2** (`secure_rag_v2.py`) — защита RAG-системы от Data Poisoning на этапе индексации и от Indirect Injection на этапе retrieval.