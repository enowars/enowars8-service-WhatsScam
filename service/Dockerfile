# Use a suitable base-image.
FROM python:3.10.9-slim

# Copy our service
COPY src/ /src/
COPY main.py /
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

RUN pip install -r src/requirements.txt

# Run the service
ENTRYPOINT ["/entrypoint.sh"]


