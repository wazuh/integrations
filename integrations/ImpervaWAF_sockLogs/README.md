# Imperva WAF Logs Integration
## Description
This integration is a modification of the described in this blog https://wazuh.com/blog/integrating-imperva-cloud-web-application-firewall-cwaf/, the modification is applied to the output, instead of using an output file, we added a python module to sent the data to the Wazuh socket


### Python mod 
```
 Send to Wazuh Socket
    """
    def handle_log_decrypted_content(self, filename, decrypted_file):
        # Convert the decrypted file from bytes to a UTF-8 string for processing
        decrypted_file = decrypted_file.decode('utf-8')
        try:
            # Import the necessary socket components for UNIX domain communication
            from socket import AF_UNIX, SOCK_DGRAM, socket

            # Define the path to the Wazuh Manager's local socket for log ingestion
            SOCKET_ADDR = '/var/ossec/queue/sockets/queue'

            # Create a new socket object for sending datagram messages over UNIX sockets
            sock = socket(AF_UNIX, SOCK_DGRAM)

            # Connect the socket to the Wazuh Manager's socket path
            sock.connect(SOCKET_ADDR)

            # Iterate over each line in the decrypted file (split by newline)
            for line in decrypted_file.strip().splitlines():
                # Only process non-empty lines
                if line:
                    # Send the log line (encoded in bytes) to Wazuh's socket
                    sock.send(line.encode())

            # Close the socket once all lines have been sent
            sock.close()

            # Log a success message indicating logs were sent to Wazuh
            self.logger.info("Logs sent successfully to Wazuh socket")

        except Exception as e:
            # If an error occurs, log the error details for troubleshooting
            self.logger.error("Error sending logs to Wazuh socket: %s", str(e))
```



### Example
Add the following folder `incapsula-logs-downloader` to `/var/ossec/wodles/`
Confiure the credentials of the imperva instance in incapsula-logs-downloader/script/config/Settings.Config
```
[SETTINGS]
IMPERVA_API_ID=xxxxxxxx
IMPERVA_API_KEY=xxxxxxxxx-xxxxxx-xxxx-xxxxxx-xxxxxxx
IMPERVA_API_URL=https://logs1.incapsula.com/xxxxxxxxxxx_xxxxxxxxx/
IMPERVA_INCOMING_DIR=
IMPERVA_PROCESS_DIR=
IMPERVA_ARCHIVE_DIR=
IMPERVA_USE_PROXY=
IMPERVA_PROXY_SERVER=
IMPERVA_USE_CUSTOM_CA_FILE=
IMPERVA_CUSTOM_CA_FILE=
IMPERVA_SYSLOG_ENABLE=
IMPERVA_SYSLOG_CUSTOM=
IMPERVA_SYSLOG_ADDRESS=
IMPERVA_SYSLOG_PORT=
IMPERVA_SYSLOG_PROTO=
IMPERVA_SYSLOG_SECURE=
IMPERVA_SYSLOG_SENDER_HOSTNAME=
IMPERVA_SPLUNK_HEC=
IMPERVA_SPLUNK_HEC_IP=
IMPERVA_SPLUNK_HEC_PORT=
IMPERVA_SPLUNK_HEC_TOKEN=
IMPERVA_SPLUNK_HEC_SRC_HOSTNAME=
IMPERVA_SPLUNK_HEC_INDEX=
IMPERVA_SPLUNK_HEC_SOURCE=
IMPERVA_SPLUNK_HEC_SOURCETYPE=
```

Configure in ossec.conf the wodle to fetch the logs every time defined in `<interval>`
```

    <wodle name="command">
      <disabled>no</disabled>
      <tag>imperva-integration-waf</tag>
      <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/incapsula-logs-downloader/script/LogsDownloader.py -c /var/ossec/wodles/incapsula-logs-downloader/script/config/</command>
      <interval>10m</interval>
      <ignore_output>yes</ignore_output>
      <run_on_start>yes</run_on_start>
      <timeout>0</timeout>
    </wodle>


```

Save the configuration and restart the wazuh manager

In the mentioned blog you have some rules for WAF events.
