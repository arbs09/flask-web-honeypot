FROM python:3.9
WORKDIR /app
RUN git clone https://github.com/arbs09/flask-web-honeypot.git .
COPY requirements.txt ./
RUN pip install -r requirements.txt
EXPOSE 80
CMD [ "python", "app.py"]
