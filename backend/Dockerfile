FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ .
RUN python scripts/generate_demo_data.py
RUN chmod +x scripts/start.sh
EXPOSE 8000
CMD ["sh", "scripts/start.sh"]
