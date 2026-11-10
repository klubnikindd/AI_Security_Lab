# Используем легкий образ Python
FROM python:3.12-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Сначала копируем только requirements для кэширования слоев
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Предустанавливаем модели SpaCy для сканера Sensitive
RUN python -m spacy download en_core_web_sm
RUN python -m spacy download zh_core_web_sm
RUN python -m spacy download ru_core_news_sm

# Копируем исходный код
COPY . .

# Запускаем веб-сервер вместо скрипта
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]