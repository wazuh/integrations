#!/bin/bash
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Extract server config using python safely
HOST=$(python3 -c '
import yaml
try:
    with open("'$BASE'/config") as f:
        config = yaml.safe_load(f)
    print(config.get("server", {}).get("host", "localhost"))
except:
    print("localhost")
')

B_PORT=$(python3 -c '
import yaml
try:
    with open("'$BASE'/config") as f:
        config = yaml.safe_load(f)
    print(config.get("server", {}).get("backend_port", "8000"))
except:
    print("8000")
')

F_PORT=$(python3 -c '
import yaml
try:
    with open("'$BASE'/config") as f:
        config = yaml.safe_load(f)
    print(config.get("server", {}).get("frontend_port", "3000"))
except:
    print("3000")
')

echo "Stopping old processes..."
pkill -f uvicorn || true
pkill -f http.server || true
pkill -f "python3 app.py" || true
sleep 2

echo "Starting backend on $HOST:$B_PORT..."
cd $BASE/backend || exit
uvicorn main:app --host $HOST --port $B_PORT --reload &

echo "Starting frontend on $HOST:$F_PORT..."
cd $BASE/frontend || exit
python3 -m http.server $F_PORT --bind $HOST &

echo "-----------------------------------"
echo "UI: http://$HOST:$F_PORT"
echo "API: http://$HOST:$B_PORT"
echo "-----------------------------------"
wait
