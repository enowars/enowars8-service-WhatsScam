# Use a suitable base-image.
FROM python:3.10.9-slim

# Copy our service
COPY src/ /src/
COPY main.py /
COPY gunicorn.conf.py /
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

RUN pip install -r src/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libc-dev \
        libgmp-dev && \
    rm -rf /var/lib/apt/lists/*

RUN gcc -o src/key_gen src/key_gen.c -lgmp

#CMD gunicorn --bind 0.0.0.0:9696 main:app

# Run the service
ENTRYPOINT ["/entrypoint.sh"]


