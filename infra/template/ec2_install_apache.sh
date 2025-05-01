#! /bin/bash
cd /home/ubuntu
yes | sudo apt update
yes | sudo apt install -y python3 python3-pip git

git clone https://github.com/rahulwagh/python-mysql-db-proj-1.git
sleep 10

cd python-mysql-db
pip3 install -r requirements.txt

# Replace the placeholder RDS host in app.py with actual endpoint
sed -i "s/host='.*'/host='${rds_endpoint}'/" app.py

echo 'Waiting for 30 seconds before running the app.py'
setsid python3 -u app.py &
sleep 30
