FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/generate_demo_data.py
RUN chmod +x scripts/start.sh
EXPOSE 8000
CMD ["sh", "scripts/start.sh"]
