#!/bin/bash

# Ensure pip is available
python3 -m ensurepip --upgrade

# Upgrade pip
python3 -m pip install --upgrade pip

# Install dependencies from requirements.txt
python3 -m pip install -r requirements.txt

# Create static directory if it doesn't exist
mkdir -p /vercel/path0/static

# Collect static files
python3 manage.py collectstatic --noinput

# Apply database migrations
python3 manage.py makemigrations
python3 manage.py migrate
