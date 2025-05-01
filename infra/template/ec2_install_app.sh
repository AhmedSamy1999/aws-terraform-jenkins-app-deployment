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
sleep 10
echo "${rds_endpoint}" | sudo tee /home/ubuntu/python-mysql-db/db_config.txt > /dev/null


echo 'Waiting 5 seconds before starting app...'
sleep 30

# Start the app in the background
setsid python3 -u app.py &

sleep 5 

curl https://zyhosttest.online/create_table

