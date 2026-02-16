# CrowdStrike Falcon Integration

## Description
This integration allows Wazuh to retrieve detection events from the CrowdStrike Falcon platform using the CrowdStrike API. The script fetches detection summaries and their details within a specified time interval and sends them directly to the Wazuh manager via its internal socket. This method provides real-time or near real-time ingestion of CrowdStrike security events into Wazuh for analysis and alerting.

## Requirements
-   Access to the CrowdStrike Falcon platform.
-   CrowdStrike API credentials (Client ID and Client Secret) with appropriate permissions to access detection APIs.
-   Python 3 installed on the Wazuh manager.
-   `crowdstrike-falconpy` Python library installed. You can install it using:
    ```bash
    python3 -m pip install crowdstrike-falconpy
    ```

## Configurations:

###   CrowdStrike API Credentials

1.  Log in to your CrowdStrike Falcon console.
2.  Navigate to **API Clients and Keys** (usually found under the Platform or API Clients section in the settings).
3.  If you don't have an existing API client, create a new one.
4.  Ensure the API client has the necessary permissions to read detection data. This typically involves permissions related to "Detections" or "Events".
5.  Take note of the **Client ID** and **Client Secret** of the API client.

###   Wazuh manager

1.  **Copy the script:** Copy the `your_script_name.py` (rename your provided script to a more descriptive name like `crowdstrike_falcon.py`) to the `/var/ossec/integrations/` folder on your Wazuh manager.

    ```bash
    cp your_script_name.py /var/ossec/integrations/crowdstrike_falcon.py
    ```

2.  **Set script parameters:** Edit the `/var/ossec/integrations/crowdstrike_falcon.py` file and replace the placeholder values for the following variables with your actual CrowdStrike credentials and configuration:

    -   `CLIENT_ID`: Your CrowdStrike API Client ID.
    -   `CLIENT_SECRET`: Your CrowdStrike API Client Secret.
    -   `SOCKET_ADDR`: The path to the Wazuh socket, which is usually `/var/ossec/queue/sockets/queue`.
    -   `LOG_FILE`: The path to the log file where script activity will be logged, usually `/var/ossec/logs/integrations.log`.
    -   `LABEL`: A label to identify the events originating from this integration (default is "crowdstrike"). You can also define this as an environment variable to set the label.

3.  **Set ownership and permissions:** Change the ownership and permissions of the script file:

    ```bash
    chown root:wazuh /var/ossec/integrations/crowdstrike_falcon.py
    chmod 750 /var/ossec/integrations/crowdstrike_falcon.py
    ```

4.  **Configure Wazuh to run the script:** Add the following `<wodle>` configuration block to the `/var/ossec/etc/ossec.conf` local configuration file to schedule the execution of the script:

    ```xml
    <wodle name="command">
      <disabled>no</disabled>
      <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/crowdstrike_falcon.py</command>
      <interval>$(INTEGRATION_INTERVAL)</interval>
      <ignore_output>yes</ignore_output>
      <run_on_start>yes</run_on_start>
      <timeout>0</timeout>
    </wodle>
    ```

    **Note:**

    -   Replace `$(INTEGRATION_INTERVAL)` with the desired interval; a positive number that should contain a suffix character indicating a time unit, such as, s (seconds), m (minutes), h (hours), d (days), M (months).

5.  **Create Wazuh rules (optional but recommended):** Create a custom rules file (e.g., `/var/ossec/etc/rules/crowdstrike_rules.xml`) to parse and generate alerts from the CrowdStrike events. You will need to define rules that match the structure of the JSON events sent by the script. Example of a basic rule:

    ```xml
    <group name="crowdstrike">
      <rule id="100100" level="5">
        <decoded_as>json</decoded_as>
        <location>crowdstrike</location>
        <description>CrowdStrike Falcon Alert.</description>
      </rule>
    </group>
    ```

    Adjust the rule based on the actual fields in the CrowdStrike events you want to monitor.

##   Logs

The script logs its activity to `/var/ossec/logs/integrations.log`. Check this file for any errors or information about the script's execution. CrowdStrike Falcon detection events will be processed by Wazuh and can be viewed in the Wazuh dashboard.
