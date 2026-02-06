#!/var/ossec/framework/python/bin/python3

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import json
import time
import requests
from requests.auth import HTTPBasicAuth



pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
f = open('/var/ossec/logs/newLog.log','a+')
f.write("\n#file opened")
arguments = sys.argv
f.write("\n->List of arguments:")
for arg in arguments:
    f.write(arg + " | ")


f.write("\n->Arguments of script assigned to variables")
alert_file_location = sys.argv[1]
apikey = sys.argv[2]
apiurl = sys.argv[3]
f.write("\n->Loading alert data: ")
alert_file = open(alert_file_location)
json_alert = json.loads(alert_file.read())
f.write(json.dumps(json_alert))
alert_file.close()



def query_api(proposal, apikey, apiurl):
  headers = {
        'Authorization': 'Bearer ' + apikey,
        'Content-Type': 'application/json',
    }

  json_data = {
        'model': 'gpt-3.5-turbo',
        'messages': [
            {
                'role': 'user',
                'content': 'Considering the following information as a critical alert received from Wazuh SIEM, investigate the problem, describe the issue, provide recommendations and next actions to solve it: ' + proposal,
            },
        ],
    }
  f.write("\n#Creating query: ")
  f.write(json.dumps(json_data))
  response = requests.post(apiurl, headers=headers, json=json_data)

  if response.status_code == 200:

      new_json = {}
      new_json = response.json()["choices"][0]["message"]["content"]
      json_response = new_json

      data = json_response
      return data
  else:
      alert_output = {}
      alert_output["custom-chatgpt"] = {}
      alert_output["integration"] = "custom-chatgpt"
      json_response = response.json()
      f.write("\n# Error: The chatgpt encountered an error: ")
      f.write(json.dumps(json_response))
      alert_output["custom-chatgpt"]["error"] = response.status_code
      alert_output["custom-chatgpt"]["description"] = json_response["error"]["message"]
      send_event(alert_output)
      exit(0)


def request_chatgpt_info(alert, apikey, apiurl):
    try:
        f.write("\n->Starting proposal for chatgpt: ")
        alert_output = {}
        proposal = ""
        
        proposal = proposal + " Description: "+ alert["rule"]["description"]
        proposal = proposal + "; Name of the agent of origin of the alert: "+ alert["agent"]["name"]
        
        if "data" in alert:
            #check for available fields from windows alerts
            if "win" in alert["data"]:
                if "system" in alert["data"]["win"]:
                    if "message" in alert["data"]["win"]["system"]:
                        proposal = proposal + "; Enhance the answer with the information of the Windows event message: "+ alert["data"]["win"]["system"]["message"]
            #check for available fields from linux alerts
            if "srcip" in alert["data"]:
                proposal = proposal + "; Source ip: "+ alert["data"]["srcip"]
            if "srcuser" in alert["data"]:
                proposal = proposal + "; Source user: "+ alert["data"]["srcuser"]
            if "dstuser" in alert["data"]:
                proposal = proposal + "; Destination user: "+ alert["data"]["srcip"]
            if "shell" in alert["data"]:
                proposal = proposal + "; Shell from user: "+ alert["data"]["shell"]
            if "home" in alert["data"]:
                proposal = proposal + "; Home directory from user: "+ alert["data"]["home"]
            #check for available fields from vulnerabilities
            if "vulnerability" in alert["data"]:
                if "rationale" in alert["data"]["vulnerability"]:
                    proposal = proposal + "; Vulnerability explanation: "+ alert["data"]["vulnerability"]["rationale"]
                if "reference" in alert["data"]["vulnerability"]:
                    proposal = proposal + "; Urls with additional information: "+ alert["data"]["vulnerability"]["reference"]
            if "integration" in alert["data"]:
                if alert["data"]["integration"] == "custom-chatgpt":
                    f.write("stopped due to information coming from chatgpt")
                    exit(0) 
        if "full_log" in alert:
            proposal = proposal + "; and use this information to enhance the investigation: "+ alert["full_log"]

        f.write(proposal)
        data = query_api(proposal, apikey, apiurl)
        alert_output["custom-chatgpt"] = {}
        alert_output["integration"] = "custom-chatgpt"
        alert_output["custom-chatgpt"]["origin"] = {}
        alert_output["custom-chatgpt"]["origin"]["alert_id"] = alert["id"]
        alert_output["custom-chatgpt"]["origin"]["rule"] = alert["rule"]["id"]
        alert_output["custom-chatgpt"]["origin"]["description"] = alert["rule"]["description"]
        alert_output["custom-chatgpt"]["answer"] = {}
        alert_output["custom-chatgpt"]["answer"] = data

        f.write("\n# Answer received from Chatgpt: ")
        f.write(json.dumps(alert_output))
    except Exception as e:
        f.write(f'\n#Error: {e}')

    return(alert_output)


def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:custom-chatgpt:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->custom-chatgpt:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    f.write("\n>>Message sent to socket: ")
    f.write(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
    
####Main execution    

msg = request_chatgpt_info(json_alert,apikey,apiurl)
if msg:
    send_event(msg, json_alert["agent"])

