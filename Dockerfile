FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --system --uid 10001 --create-home aegistrail
USER aegistrail

EXPOSE 8000
ENTRYPOINT ["aegistrail"]
CMD ["serve-metrics", "--reports-dir", "/data", "--host", "0.0.0.0", "--port", "8000"]
