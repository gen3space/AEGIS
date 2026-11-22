FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml requirements.txt README.md ./
COPY aegis ./aegis

RUN pip install --no-cache-dir -e .

EXPOSE 8765
ENV AEGIS_BIND_HOST=0.0.0.0
ENV AEGIS_BIND_PORT=8765

CMD ["aegis"]
