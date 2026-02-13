FROM python:3.12-slim

WORKDIR /app
COPY agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY agent /app/agent
CMD ["python", "-m", "agent.app.agent_main"]
