from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import requests
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType
from llm_guard.output_scanners import Sensitive

app = FastAPI(title="Secure LLM Gateway API", description="WAF для LLM")

print("⏳ Инициализация сканеров...")
in_scanner = PromptInjection(match_type=MatchType.FULL)
out_scanner = Sensitive()
print("✅ Сканеры готовы.")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

class ChatRequest(BaseModel):
    prompt: str

class ChatResponse(BaseModel):
    response: str
    status: str

@app.get("/")
def read_root():
    return {"message": "Добро пожаловать в Secure LLM Gateway API. Перейдите на /docs для тестирования."}

@app.get("/health")
def health_check():
    return {"status": "ok", "ollama_host": OLLAMA_HOST}

@app.post("/chat", response_model=ChatResponse)
def secure_chat(request: ChatRequest):
    prompt = request.prompt
    
    # 1. Входной Guardrail
    _, is_valid, risk_score = in_scanner.scan(prompt)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"🚨 Prompt Injection detected (Risk: {risk_score})")
    
    # 2. Отправка в Ollama
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {"model": "phi3", "prompt": prompt, "stream": False}
    
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        raw_response = response.json().get('response', '').strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ollama Error: {e}")
        
    # 3. Выходной Guardrail
    _, is_valid_out, risk_score_out = out_scanner.scan(prompt, raw_response)
    if not is_valid_out:
        raise HTTPException(status_code=403, detail="🚨 Sensitive Data detected in response")

    return ChatResponse(response=raw_response, status="Success")