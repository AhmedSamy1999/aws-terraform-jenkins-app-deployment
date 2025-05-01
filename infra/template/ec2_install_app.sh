#! /bin/bash
cd /home/ubuntu
yes | sudo apt update
yes | sudo apt install -y python3 python3-pip git

git clone https://github.com/AhmedSamy1999/python-mysql-db.git
sleep 10

cd python-mysql-db
sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


# Replace the placeholder RDS host in app.py with actual endpoint
sed -i "s/host='.*'/host='${rds_endpoint}'/" app.py

echo 'Waiting for 30 seconds before running the app.py'
setsid python3 -u app.py &
sleep 30



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

# Replace only the host in pymysql.connect(...) line (not app.run!)
sed -i "/pymysql\.connect/s/host='[^']*'/host='${rds_endpoint}'/" app.py

echo 'Waiting 5 seconds before starting app...'
sleep 5

# Start the app in the background
setsid python3 -u app.py > /home/ubuntu/flask.log 2>&1 &
sleep 5 

curl http://zyhosttest/create-table

