import os
import requests
from pathlib import Path
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DOCS_DIR = "knowledge_base"

# Инициализируем сканер
print("⏳ Инициализация сканера Prompt Injection...")
scanner = PromptInjection(match_type=MatchType.FULL)
print("✅ Сканер готов.")

def load_documents():
    docs = {}
    path = Path(DOCS_DIR)
    if path.exists():
        for file in path.glob("*.txt"):
            docs[file.name] = file.read_text(encoding="utf-8")
    return docs

def search_documents(query, docs):
    query_words = query.lower().split()
    results = []
    for name, content in docs.items():
        if any(word in content.lower() for word in query_words if len(word) > 3):
            results.append((name, content))
    return results

def ask_llm(prompt):
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {"model": "phi3", "prompt": prompt, "stream": False}
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get('response', '').strip()
    except Exception as e:
        return f"Ошибка Ollama: {e}"

def secure_rag_query(user_question):
    print(f"\n👤 Вопрос: {user_question}")
    
    docs = load_documents()
    found = search_documents(user_question, docs)
    
    if not found:
        return "По вашему запросу ничего не найдено."
    
    # --- ЗАЩИТА: Проверяем каждый найденный документ ---
    safe_contexts = []
    for name, content in found:
        print(f"🔍 Проверка документа '{name}'...")
        _, is_valid, risk_score = scanner.scan(content)
        
        if not is_valid:
            print(f"🚨 БЛОКИРОВКА: Документ '{name}' отравлен! (Risk: {risk_score}). Пропускаем.")
        else:
            safe_contexts.append(f"Документ '{name}':\n{content}")
    
    if not safe_contexts:
        return "❌ Все найденные документы заблокированы системой безопасности."

    # Формируем контекст только из безопасных документов
    context = "\n\n".join(safe_contexts)
    
    prompt = f"""Ты — полезный ассистент. Используй следующий контекст, чтобы ответить на вопрос пользователя.

Контекст:
{context}

Вопрос: {user_question}
Ответ:"""
    
    return ask_llm(prompt)

if __name__ == "__main__":
    print("--- ТЕСТ ЗАЩИЩЕННОЙ RAG-СИСТЕМЫ ---")
    answer = secure_rag_query("Расскажи мне о продукте X")
    print(f"\n🤖 Ответ LLM:\n{answer}")