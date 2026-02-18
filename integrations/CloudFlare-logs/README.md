# Cloudflare Logs Integration
## Description
The python script will fetch the logs cloudflare and dumps on the file /var/ossec/logs/cloudflare.log. The file /var/ossec/logs/cloudflare.last keeps the track of last fetch time and on the next fetch It will fetch the logs by reading the cloudflare.last file.You can place the file whereever you want.

### Example
Writing the script on location /var/ossec/integrations/cloudflare-logs.py
~~~
vim /var/ossec/integrations/cloudflare-logs.py 
~~~
Place the code on the file. <br/>
Replace XXXXXX on both **ZONE_ID and** **API_TOKEN** with the correct **ZONE_ID** and **API_TOKEN**

Change the permission of the file using the command
```
chmod 750 /var/ossec/integrations/cloudflare-logs.py
chown root:wazuh /var/ossec/integrations/cloudflare-logs.py
```
Now Open the ossec.conf file and write the wodle to fetch the logs every hour
```
<wodle name="command">
  <disabled>no</disabled>
  <tag>Cloudflare</tag>
  <command>/bin/bash /var/ossec/integrations/cloudflare-logs.py</command>
  <interval>1h</interval>
</wodle>
```

```
<localfile>
  <location>/var/ossec/logs/cloudflare.log</location>
  <log_format>json</log_format>
</localfile>
```
Now Create the Custom rules named cloudflare.<br />
_The logs received will be in json format so we don't need to create a decoder for it_ <br />
_The decoder are created based on the log fields fetched (ZoneID and ClientRequestHost). You can change the field name based on the available fields on the logs_ <br />
```
<group name="cloudflare,">
  <rule id="100024" level="3">
    <decoded_as>json</decoded_as>
    <field name="ZoneID">\.+</field>
    <description>test</description>
  </rule>
    <rule id="100025" level="5">
    <if_sid>100024</if_sid>
    <field name="ClientRequestHost">\.+</field>
    <description>test</description>
  </rule>
</group>
```
Save the configuration and restart the wazuh manager
