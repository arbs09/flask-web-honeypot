FROM python:3.13-rc-slim-bookworm
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 80
ENV API_KEY=default_key
CMD ["python", "app.py"]