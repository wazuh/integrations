#!/bin/bash
BASE="/home/vagrant/wazuh-ai-tool"
echo "Stopping old processes..."
pkill -f uvicorn || true
pkill -f http.server || true
pkill -f "python3 app.py" || true
sleep 2
echo "Starting backend..."
cd $BASE/backend || exit
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
echo "Starting frontend..."
cd $BASE/frontend || exit
python3 -m http.server 3000 &
echo "-----------------------------------"
echo "UI: http://192.168.56.57:3000"
echo "API: http://192.168.56.57:8000"
echo "-----------------------------------"
wait
