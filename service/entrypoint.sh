#!/bin/bash

# Start first
gunicorn -c gunicorn.conf.py main:app &

# Start second
python src/cleanup.py &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?