FROM python:3.9
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
RUN git clone https://github.com/your-username/repository-name.git .
EXPOSE 80
CMD [ "python", "app.py"]