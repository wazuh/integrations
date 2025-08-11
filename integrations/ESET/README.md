### ESET-Wazuh Integration

-----

#### **Table of Contents**

  * [Introduction](https://www.google.com/search?q=%23introduction)
  * [Prerequisites](https://www.google.com/search?q=%23prerequisites)
  * [Installation and Configuration](https://www.google.com/search?q=%23installation-and-configuration)
      * [Initial ESET Configuration](https://www.google.com/search?q=%23initial-eset-configuration)
      * [Installing and Configuring the Integration](https://www.google.com/search?q=%23installing-and-configuring-the-integration)
  * [Integration Steps](https://www.google.com/search?q=%23integration-steps)
  * [Integration Testing](https://www.google.com/search?q=%23integration-testing)
  * [Sources](https://www.google.com/search?q=%23sources)

-----

#### **Introduction**

This document provides a comprehensive guide for integrating the ESET PROTECT Platform with Wazuh. By combining these two powerful solutions, security teams can centralize detection data from ESET PROTECT, ESET Inspect, and ESET Cloud Office Security into their Wazuh instance. This centralized approach to security event monitoring enhances overall threat detection and response capabilities.

The integration operates using an API-based method. A dedicated application pulls detection data from the ESET Public API at user-defined intervals, saving this information to a local log file on the Wazuh manager machine. This process provides Wazuh with a continuous stream of ESET security events for analysis and alerting.

#### **Prerequisites**

Before starting the integration, ensure the following requirements are met:

  * An **ESET Connect API user account** must be created in the **ESET Protect Hub** with the necessary permissions for the integration.
  * A functional **Wazuh** installation with the **manager**, **indexer**, and **dashboard** components.
  * **Docker** and **Docker Compose** installed on the Wazuh manager machine.

#### **Installation and Configuration**

**1. Initial ESET Configuration**

To allow the integration application to authenticate and pull data, you must create an API user with the correct permissions. This user should be managed through the **ESET Protect Hub**, not the ESET PROTECT platform console directly.

When creating the new API user, it is essential to grant it the proper permissions for integrations. Ensure the `Integrations` permission is enabled.

**2. Installing and Configuring the Integration**

The integration is handled by a dedicated application available on GitHub. Follow these steps to set it up.

**a) Download the Integration Application**
From the server console where Wazuh is running, clone the ESET integration app repository. This requires `sudo` privileges to run commands as the root user.

```bash
git clone --branch 1.2.1 https://github.com/eset/ESET-Integration-Wazuh.git /var/ossec/integrations/ESET-Integration-Wazuh
```

**b) Copy Custom Wazuh Rules**
The `eset_local_rules.xml` file contains custom rules that help Wazuh identify and interpret ESET detections. These rules map most of the detections to the MITRE ATT\&CK framework. Copy this file to the Wazuh rules directory:

```bash
cp /var/ossec/integrations/ESET-Integration-Wazuh/eset_local_rules.xml /var/ossec/etc/rules
```

**c) Create the Log File**
Create an empty log file where the ESET detections will be stored:

```bash
touch /var/log/eset_integration.log
```

**d) Configure Wazuh to Ingest the Logs**
Edit the `/var/ossec/etc/ossec.conf` file to add a new `localfile` block. This tells the Wazuh manager to read the newly created log file.

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/eset_integration.log</location>
  </localfile>
</ossec_config>
```

**e) Configure the Integration with the .env file**
The `.env` file stores the connection parameters for the ESET API. Create the file and edit it to include your ESET instance details and API user credentials.

```bash
touch /var/ossec/integrations/ESET-Integration-Wazuh/.env
```

The variables to configure are listed below. Configure each one according to your environment.

  * `EP_INSTANCE`: Set to `yes` to enable the integration with ESET PROTECT.
  * `EI_INSTANCE`: Set to `yes` to enable the integration with ESET Inspect.
  * `ECOS_INSTANCE`: Set to `yes` to enable the integration with ESET Cloud Office Security.
  * `INTERVAL`: The time interval (in minutes) at which the application will poll ESET for new detections. The minimum allowed value is 3.
  * `INSTANCE_REGION`: The region of your ESET instance. This value depends on where your ESET Protect Hub is located (e.g., `us`, `eu`, `ca`, `de`, `jpn`).
  * `USERNAME_INTEGRATION`: The email address of the ESET Connect API user you created.
  * `PASSWORD_INTEGRATION`: The password for the ESET Connect API user.

#### **Integration Steps**

1.  **Download the application** with `git clone`.
2.  **Copy the custom rules file** to `/var/ossec/etc/rules`.
3.  **Create the log file** with `touch`.
4.  **Add the `localfile` configuration** to `ossec.conf`.
5.  **Restart the Wazuh manager** to apply the changes.
6.  **Create and configure the `.env` file** with your credentials and settings.
7.  **Run the integration app** using Docker Compose.

    ```bash
    docker compose --file /var/ossec/integrations/ESET-Integration-Wazuh/docker-compose.yml up -d
    ```

#### **Integration Testing**

To verify the integration is working, you can check the logs of the running container or the Wazuh dashboard.

1. Check Docker logs:
   * Find the container name with `docker ps`.
   * View the logs with `docker logs -f <docker container name>`.
2. Check the log file:
    * Use the `tail` command to see the latest detections.

      ```bash
      tail -n 100 /var/log/eset_integration.log
      ```

3. Filter the Wazuh dashboard:
   * In the Wazuh dashboard, click **Add filter**.
   * Set **Field** to `rule.groups`, **Operator** to `is`, and **Value** to `eset`.
   * Click **Save**. This will display all the ESET logs that are being received and processed.
