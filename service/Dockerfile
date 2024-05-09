# Use a suitable base-image.
FROM python:3.10.9-slim

# Copy our service
COPY src/ /src/
COPY main.py /

RUN pip install -r src/requirements.txt

CMD gunicorn --bind 0.0.0.0:5000 main:app
