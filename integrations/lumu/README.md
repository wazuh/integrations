# Lumu Ruleset

This repository contains the base Lumu ruleset for Wazuh. The ruleset is designed to integrate Lumu threat intelligence data into Wazuh.

## How it works?

The ruleset includes predefined decoders and rules to analyze and correlate events from Lumu's threat intelligence feeds.

When Wazuh receives logs containing Lumu data, the decoders parse the information, and the rules evaluate it to identify potential threats. Alerts are generated if any of this rule matches, enabling security teams to take immediate action.

It detects the following events:

    1. A new Incident is Created.
    2. An Incident is Closed.
    3. An Incident is Assigned.
    4. An Update in a existing Incident. 

## Installation

1. Clone this repository or download the ruleset files.
2. Copy the rules file to the appropriate Wazuh rules directory:

    ```bash
    cp -r ./lumu /var/ossec/etc/ruleset/rules/lumu_rules.xml

    ```

3. Copy the decoder fil to the appropriate Wazuh decoders directory:

    ```bash
    cp -r ./lumu /var/ossec/etc/ruleset/decoders/lumu_decoder.xml

    ```

4. Restart the Wazuh manager to apply the changes:

    ```bash
    systemctl restart wazuh-manager

    ```


You can also implement it throught the Wazuh Dashboard menu:

    Server Management > Rules > Add new rules file
    Server Management > Decoders > Add new decoders file

## Usage

- The ruleset will automatically process incoming data and generate alerts based on Lumu's logs.
- Review the Wazuh alerts to monitor and respond to detected threats.

