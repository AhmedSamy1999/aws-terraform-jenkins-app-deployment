#!/bin/bash

cd /home/ubuntu

# Update system packages
yes | sudo apt update
yes | sudo apt install -y python3 python3-pip git

# Clone the GitHub repo
git clone https://github.com/AhmedSamy1999/python-mysql-db.git
sleep 10

cd python-mysql-db


pip3 install --break-system-packages -r requirements.txt

echo "${rds_endpoint}" > /home/ubuntu/db_config.txt

echo 'Waiting 5 seconds before starting app...'
sleep 5

# Start the app in the background
setsid python3 -u app.py > /home/ubuntu/flask.log 2>&1 &
sleep 5 

curl http://zyhosttest/create_table

