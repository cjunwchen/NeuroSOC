# Shimmed agent image — same agent.py, now exposed as an HTTP+SSE service.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt fastapi "uvicorn[standard]"
COPY agent.py .
COPY shim.py .
EXPOSE 9200
CMD ["uvicorn", "shim:app", "--host", "0.0.0.0", "--port", "9200"]
