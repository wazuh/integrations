#!/var/ossec/framework/python/bin/python3
"""
Wazuh → Microsoft Teams Integration (Workflows)
Author: Jakub Zieliński (github.com/jayzielinski)
License: MIT
"""

import sys, json, requests, logging
from datetime import datetime

LOG_FILE    = '/var/ossec/logs/integrations.log'
USER_AGENT  = 'Wazuh-Teams-Integration/2.0'

class Integration:
    def __init__(self, alert_file, webhook_url, level):
        self.alert_file = alert_file
        self.webhook_url = webhook_url
        self.level = level
        self._setup_logging()

    def _setup_logging(self):
        # Setup logging to both file and stdout with INFO level
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('wazuh-teams')

    def _validate(self):
        # Validate input parameters for alert file, webhook URL, and level
        if not self.alert_file.endswith('.alert'):
            self.logger.error(f"Invalid alert file: {self.alert_file}")
            return False
        if not isinstance(self.level, int):
            self.logger.error(f"Invalid level: {self.level}")
            return False
        return True

    def _load_alert(self):
        # Load alert data from JSON alert file
        try:
            with open(self.alert_file) as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Cannot load alert JSON: {e}")
            return {}

    def _priority(self, alert):
        # Determine alert priority text, color, and level based on alert rule level
        l = alert.get('rule', {}).get('level', 0)
        if l >= 12: return {"txt":"CRITICAL","clr":"Attention", "lvl": l}
        if l >= 7:  return {"txt":"HIGH","clr":"Warning", "lvl": l}
        if l >= 4:  return {"txt":"MEDIUM","clr":"Good", "lvl": l}
        return {"txt":"LOW","clr":"Accent", "lvl": l}

    def _make_card(self, alert):
        # Create the Microsoft Teams Adaptive Card payload for the alert
        pr          = self._priority(alert)
        rule        = alert.get('rule', {})
        agent       = alert.get('agent', {})
        att = {
            "type":"message",
            "attachments":[{
                "contentType":"application/vnd.microsoft.card.adaptive",
                "content":{
                    "$schema":"http://adaptivecards.io/schemas/adaptive-card.json",
                    "type":"AdaptiveCard","version":"1.4",
                    "body":[
                        {"type":"TextBlock",
                         "text":f"{pr['txt']} WAZUH ALERT",
                         "weight":"Bolder","size":"Large","color":pr['clr']},
                        {"type":"FactSet","facts":[
                            {"title":"Level","value":f"{pr['txt']} ({pr['lvl']})"},
                            {"title":"Rule ID","value":str(rule.get('id','N/A'))},
                            {"title":"Description","value":rule.get('description','Brak')},
                            {"title":"Agent","value":f"{agent.get('name','?')} ({agent.get('ip','?')})"},
                            {"title":"Timestamp","value":self._format_time(alert.get('timestamp',''))}
                        ]},
                        {"type":"TextBlock",
                         "text":alert.get('full_log','(N/A)'),
                         "wrap": True,
                         "spacing": "Small",
                         "isSubtle": True,
                         "fontType": "Monospace"}
                    ],
                    "actions":[{"type":"Action.OpenUrl",
                                "title":"Dashboard",
                                "url":f"https://10.169.173.20/app/threat-hunting#/overview/?tab=general&tabView=events&_a=(filters:!(),query:(language:kuery,query:''))&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))&agentId={agent.get('id','')}"}]
                }
            }]
        }
        return att

    def _format_time(self, ts):
        # Parse the timestamp string with timezone info (e.g. '+0200')
        # and convert it to the local time of the machine where this script runs.
        # This way, the alert time shown will always reflect the local time zone
        # of the server executing the script, regardless of where the alert originated.
        # If parsing fails, return the original timestamp string unchanged.
        try:
            # Fix timezone format from +0200 to +02:00 for ISO compliance
            ts_fixed = ts[:-2] + ':' + ts[-2:] if ts and len(ts) > 5 else ts
            dt = datetime.fromisoformat(ts_fixed)
            local_dt = dt.astimezone()  # Convert to local timezone of the host machine
            return local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            self.logger.error(f"Time formatting error: {e}")
            return ts

    def _send(self, card):
        # Send the Adaptive Card JSON payload to Microsoft Teams via webhook
        headers = {'Content-Type':'application/json','User-Agent':USER_AGENT}    
        # Wazuh may pass the URL XML-escaped, so decode it back
        url = (self.webhook_url or "").replace("&amp;", "&")

        #self.logger.info(f"Webhook URL received (raw): {self.webhook_url}")
        #self.logger.info(f"Webhook URL used (decoded): {url}")

        try:
            resp = requests.post(url,json=card,headers=headers,timeout=30)
            if resp.status_code in (200,202):
                self.logger.info(f"Sent ok (status {resp.status_code})")
                print("Message sent successfully")
                return True
            self.logger.error(f"Send failed: {resp.status_code} {resp.text}")
        except Exception as e:
            self.logger.error(f"Exception: {e}")
        return False

    def run(self):
        # Main execution: validate inputs, load alert, create card and send it
        if not self._validate(): sys.exit(1)
        alert = self._load_alert()
        card  = self._make_card(alert)
        if not self._send(card): sys.exit(1)
        sys.exit(0)

def parse_args(argv):
    # Parse command line arguments: alert file, webhook URL, and alert level
    alert_file=None; webhook=None; level=None
    for arg in argv[1:]:
        if arg.startswith('/tmp/') and arg.endswith('.alert'):
            alert_file = arg
        elif arg.startswith('http'):
            webhook = arg
        else:
            try:
                level = int(arg)
            except:
                pass
    return alert_file, webhook, level

def main():
    # Entry point: parse args and start integration
    af, wh, lv = parse_args(sys.argv)
    if not all([af,wh,lv is not None]):
        print("Usage: custom-teams.py <alert_file.alert> <webhook_url> <level>")
        sys.exit(1)
    Integration(af,wh,lv).run()

if __name__=="__main__":
    main()

