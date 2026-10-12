FROM python:3.12-slim

# run as a non-root user for a smaller attack surface
RUN useradd --create-home appuser
WORKDIR /home/appuser/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

USER appuser
ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000

CMD ["gunicorn", "--chdir", "src", "--bind", "0.0.0.0:8000", "app:app"]
