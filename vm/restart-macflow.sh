#!/bin/bash
cd /opt/macflow
nohup python3 backend/main.py > /var/log/macflow.log 2>&1 &
sleep 2
netstat -tlnp | grep 18080
echo "MACFlow restarted PID=$!"
