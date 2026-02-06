# integrations-oracle

This project provides a script to fetch messages from Oracle Cloud Streaming and send them to the Wazuh analysisd queue for further processing and monitoring.

## Features

- Fetch messages from Oracle Cloud Streaming.
- Process and format messages for Wazuh.
- Send messages to the Wazuh analysisd queue.
- Acknowledge processed messages.
- Handle connection and message errors with custom exceptions.

## Prerequisites

- Python 3.x
- Oracle Cloud SDK for Python (`oci`)
- Wazuh manager running
- Logstash

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/integrations-oracle.git
    cd integrations-oracle
    ```

2. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Move the script to the Wazuh wodles directory**:
    ```sh
    sudo mkdir -p /var/ossec/wodles/oracle
    sudo cp -r * /var/ossec/wodles/oracle/
    ```

## Configuration

1. **Create a credentials file**:
    - Create a file named `config` with your Oracle Cloud credentials.
    - Example:
        ```ini
        [DEFAULT]
        user=ocid1.user.oc1..example
        fingerprint=2f:31:ae:1a:5f:e4:a5:5b:6a:15:9c:8a:1c:7f:1d:53
        key_file=/path/to/your/private_key.pem
        tenancy=ocid1.tenancy.oc1.region.example
        region=us-ashburn-1
        ```

2. **Set script arguments**:
    - The script accepts the following arguments:
        - `-sid` or `--streamid`: Stream ID to fetch messages from.
        - `-c` or `--credentials_file`: Path to the credentials file.
        - `-l` or `--log_level`: Log level (default: INFO). Choose one of DEBUG, INFO, WARNING, ERROR.
        - `-p`, `--path`: Path to local file for writing events. If not specified, events will be sent to analysisd

## Usage

1. **Run the script**:
    ```sh
    /var/ossec/wodles/oracle/oracle.py -sid <stream_id> -c /path/to/config -l 1
    ```

## How It Works

1. **Initialize the Oracle Streaming Client**:
    - The script initializes the Oracle Streaming client using the credentials file and profile name.

2. **Fetch Messages**:
    - The script fetches messages from the specified Oracle Cloud stream.
    - A counter keeps track of the total number of messages to be fetched.

3. **Process and Send Messages**:
    - The script formats each fetched message for Wazuh.
    - The formatted messages are sent to the Wazuh analysisd queue.
    - A counter increments for each processed message.

4. **Acknowledge Processed Messages**:
    - The script logs the acknowledgment of each processed message.
    - Custom exceptions handle connection and message errors.

## Example

To fetch messages from an Oracle Cloud stream and send them to Wazuh, run the following command:

```bash
/var/ossec/wodles/oracle/oracle.py -sid ocid1.stream.oc1.region.example -c /path/to/config -l DEBUG
```

## Rule example

```bash
<group name="Oracle,">
<rule id="111001" level="3">
  <decoded_as>json</decoded_as>
  <location>Oracle$</location>
  <description>Oracle event message received.</description>
</rule>
</group>
```

## Logstash filter

A filter is necessary in order to index, you might not encounter the error but it is a good option to include it. This should be included at the end. 
```bash
filter {
 if [data][data] {
   ruby {
     code => '
       data_obj = event.get("[data][data]")
       if data_obj.is_a?(Hash)
         event.set("[data][data]", data_obj.to_s)
         data_obj.each { |k, v| event.set("[data][#{k}]", v) if v }

         if data_obj["additionalDetails"] && data_obj["additionalDetails"].is_a?(Hash)
           data_obj["additionalDetails"].each { |k, v| event.set("[data][#{k}]", v) if v }
         end

         if data_obj["problemAdditionalDetails"] && data_obj["problemAdditionalDetails"].is_a?(Hash)
           data_obj["problemAdditionalDetails"].each { |k, v| event.set("[data][#{k}]", v) if v }
         end
       end
     '
   }
 }
}
```

