# Armis Ruleset

This repository contains a basic Armis ruleset for Wazuh. The ruleset is designed to integrate Armis data into Wazuh.

## How it works?

The ruleset includes predefined rules to analyze and correlate events.

When Wazuh receives logs containing Armis data, the rules evaluate it to identify potential threats. Alerts are generated if any of this rule matches, enabling security teams to take immediate action.

It's primarily based on detecting and alerting on different events, depending on their criticality.

## Installation

1. Clone this repository or download the ruleset files.
2. Copy the rules file to the appropriate Wazuh rules directory:

    ```bash
    cp <ruleset file> /var/ossec/etc/ruleset/rules/armis_rules.xml

    ```

3. Restart the Wazuh manager to apply the changes:

    ```bash
    systemctl restart wazuh-manager

    ```


You can also implement it throught the Wazuh Dashboard menu:

    Server Management > Rules > Add new rules file

## Usage

- The ruleset will automatically process incoming data and generate alerts based on Armis' logs.
- Review the Wazuh alerts to monitor and respond to detected threats.

