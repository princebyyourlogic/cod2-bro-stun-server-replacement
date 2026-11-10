FROM python:3.12-slim
WORKDIR /app
COPY codstun /app/codstun
COPY LICENSE /app/LICENSE
USER 65534:65534
ENTRYPOINT ["python", "-m", "codstun"]
