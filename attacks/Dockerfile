FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests==2.32.3
COPY run_attacks.py .
ENTRYPOINT ["python", "run_attacks.py", "--target", "http://10.13.1.10:8000"]
