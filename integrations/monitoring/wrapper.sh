#!/bin/bash
# 1. Monitoring script execution
/opt/scripts/monitoring.py 

# 2. Notification channels
/opt/scripts/slack_notifier.py
/opt/scripts/email_notifier.py
