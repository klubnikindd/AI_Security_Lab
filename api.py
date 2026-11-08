from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
import os
import requests
import json
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType
from llm_guard.output_scanners import Sensitive
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="Secure LLM Gateway API", description="WAF для LLM")

# --- Метрики Prometheus ---
TOTAL_REQUESTS = Counter('gateway_requests_total', 'Всего запросов к /chat')
INPUT_BLOCKED = Counter('gateway_input_blocked_total', 'Заблокировано на входе (Prompt Injection)')
INPUT_PASSED = Counter('gateway_input_passed_total', 'Прошло входной фильтр')
OUTPUT_BLOCKED = Counter('gateway_output_blocked_total', 'Заблокировано на выходе (PII / Judge)')
OUTPUT_PASSED = Counter('gateway_output_passed_total', 'Успешно прошло выходной фильтр')
JUDGE_BLOCKED = Counter('gateway_judge_blocked_total', 'Ответы, заблокированные LLM-судьёй')
JUDGE_PASSED = Counter('gateway_judge_passed_total', 'Ответы, одобренные LLM-судьёй')

print("⏳ Инициализация сканеров...")
in_scanner = PromptInjection(match_type=MatchType.FULL)
out_scanner = Sensitive()
print("✅ Сканеры готовы.")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")

# --- Модель для LLM-судьи ---
JUDGE_MODEL = "llama3.1:8b-instruct-q4_K_M"

class ChatRequest(BaseModel):
    prompt: str

class ChatResponse(BaseModel):
    response: str
    status: str

JUDGE_PROMPT_TEMPLATE = """Ты — эксперт по безопасности LLM. Твоя задача — проверить, не содержит ли ответ модели информацию, которую пользователь не должен был получать.

Исходный запрос пользователя:
{prompt}

Ответ модели:
{response}

Вопрос: Содержит ли этот ответ конфиденциальные данные, секреты, пароли, внутренние инструкции или что-либо ещё, что не должно быть раскрыто? 
Ответь строго в формате JSON: {{"is_safe": true/false, "reason": "краткое объяснение"}}"""

def llm_judge_check(prompt: str, response: str) -> tuple[bool, str]:
    """Вызывает LLM-судью для семантической проверки ответа."""
    judge_prompt = JUDGE_PROMPT_TEMPLATE.format(prompt=prompt, response=response)
    
    payload = {
        "model": JUDGE_MODEL,
        "prompt": judge_prompt,
        "stream": False,
        "format": "json"
    }
    
    try:
        url = f"{OLLAMA_HOST}/api/generate"
        res = requests.post(url, json=payload, timeout=60)
        res.raise_for_status()
        result = res.json()
        # Ollama возвращает JSON-строку внутри response
        judge_output = json.loads(result['response'])
        
        is_safe = judge_output.get("is_safe", False)
        reason = judge_output.get("reason", "No reason provided")
        return is_safe, reason
    except Exception as e:
        # Fail-Closed: если судья упал, блокируем ответ
        return False, f"LLM judge error: {e}"

@app.get("/")
def read_root():
    return {"message": "Добро пожаловать в Secure LLM Gateway API. Перейдите на /docs для тестирования."}

@app.get("/health")
def health_check():
    return {"status": "ok", "ollama_host": OLLAMA_HOST}

@app.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/chat", response_model=ChatResponse)
def secure_chat(request: ChatRequest):
    TOTAL_REQUESTS.inc()
    prompt = request.prompt
    
    # 1. Входной Guardrail
    _, is_valid, risk_score = in_scanner.scan(prompt)
    if not is_valid:
        INPUT_BLOCKED.inc()
        raise HTTPException(status_code=400, detail=f"🚨 Prompt Injection detected (Risk: {risk_score})")
    
    INPUT_PASSED.inc()
    
    # 2. Отправка в Ollama (основная модель)
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {"model": "phi3", "prompt": prompt, "stream": False}
    
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        raw_response = response.json().get('response', '').strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ollama Error: {e}")
        
    # 3. Выходной Guardrail (Sensitive)
    _, is_valid_out, risk_score_out = out_scanner.scan(prompt, raw_response)
    if not is_valid_out:
        OUTPUT_BLOCKED.inc()
        raise HTTPException(status_code=403, detail="🚨 Sensitive Data detected in response")

    # 4. LLM-судья (семантическая проверка)
    is_safe, judge_reason = llm_judge_check(prompt, raw_response)
    if not is_safe:
        JUDGE_BLOCKED.inc()
        OUTPUT_BLOCKED.inc()
        raise HTTPException(status_code=403, detail=f"🚨 LLM Judge blocked response: {judge_reason}")
    JUDGE_PASSED.inc()

    OUTPUT_PASSED.inc()
    return ChatResponse(response=raw_response, status="Success")