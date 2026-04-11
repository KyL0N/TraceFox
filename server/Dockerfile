FROM python:3.11-slim
WORKDIR /app
COPY tracefox_protocol.py metrics_forwarder.py ./
CMD ["python3", "-u", "metrics_forwarder.py"]
