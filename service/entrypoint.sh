#!/bin/bash

# Start first
gunicorn --bind 0.0.0.0:9696 main:app &

# Start second
#python src/cleanup.py &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?