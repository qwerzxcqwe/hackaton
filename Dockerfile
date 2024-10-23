FROM python:3.11-slim-buster
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python3","main.py"]