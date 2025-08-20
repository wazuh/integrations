#!/usr/bin/env python3

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

from requests.auth import HTTPBasicAuth
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
import urllib3
import logging

#configuration

SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 25
SENDER_EMAIL = 'noreply@test.xyz'  #SENDER EMAIL ADDRESS
RECEIVER_EMAIL = 'socsupport@test.xyz' #RECEIVER EMAIL ADDRESS

logging.basicConfig(filename='/var/ossec/logs/custom-email_integration.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=logging.DEBUG)

try:
    # Reading configuration parameters
    logging.info("Reading config parameters")
    alert_file = open(sys.argv[1])

except Exception as e:
    logging.error("Failed to read config parameters: %s", str(e))

try:
    # Read the alert file
    logging.info("Reading the alert file")
    alert_json = json.loads(alert_file.read())
    alert_file.close()
except Exception as e:
    logging.error("Failed to read the alert file: %s", str(e)) 

try:
    #Extract issue fields
    logging.info("Extracting the issue fields")
    timestamp = alert_json['timestamp']
    location = alert_json['location']
    alert_level = alert_json['rule']['level']
    rule_id = alert_json['rule']['id']
    description = alert_json['rule']['description']
    agent_id = alert_json['agent']['id']
    rule_level = alert_json['rule']['level']
    agent_name = alert_json['agent']['name']
except Exception as e:
    logging.error("Failed extracting the issue fields: %s", str(e))

# Generate request
try:
    logging.info("Creating the email message")
    data = f"""🚨 Wazuh SOC Alert Notification.
{timestamp}

Received From: {location}
Rule: {rule_id}(level {rule_level}) -> {description}

Agent: {agent_name}({agent_id})

END OF NOTIFICATION"""

    message = MIMEMultipart()
    message['From'] = SENDER_EMAIL
    message['To'] = RECEIVER_EMAIL
    message['Subject'] = 'Wazuh SOC Alert Notification'
    message.attach(MIMEText(data, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.send_message(message)
    logging.info("Email sent successfully!")
except Exception as e:
    logging.error("Failed to send email: %s", str(e))

sys.exit(0)

