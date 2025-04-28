#!/bin/bash
#export TIME_ZONE='Asia/Kolkata'
# Prod Server
export DJANGO_DEBUG=0
. venv/bin/activate && gunicorn -b 127.0.0.1:8000 archerysecurity.wsgi:application --workers=1 --threads=10 --timeout=1800
