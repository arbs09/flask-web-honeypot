FROM python:3.9
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
RUN git clone https://github.com/arbs09/flask-web-honeypot.git .
EXPOSE 80
CMD [ "python", "app.py"]
