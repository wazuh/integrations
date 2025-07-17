# Wazuh Integrations Repository

This public repository contains integrations for third-party solutions, Wazuh rulesets, active responses, Security Configuration Assessment (SCA) policies, threat intelligence feeds, and custom dashboards. 

**Disclaimer:**
The integrations and content within this repository are primarily community-contributed and are provided "as is" without warranty of any kind, express or implied. Users are responsible for evaluating the security, quality, and compatibility of any code or configurations they choose to utilize from this repository. The maintainers and associated company do not guarantee the absence of vulnerabilities, errors, or suitability for any particular purpose.

## Repository Structure

The repository is organized into an integrations folder. Each integration resides in its own dedicated directory within this folder. An integration can be for any operating system, device, or third-party solution. Each integration's directory can contain a full set of relevant content (e.g., ruleset, active response, SCA, threat intel, dashboards) or only a subset, depending on the specific needs of that integration (e.g., only a ruleset, or just an SCA and a custom dashboard). 

```
integrations/
├── <integration_name_1>/
│   ├── ruleset/
│   │   ├── rules/
│   │   └── decoders/
│   ├── active-response/
│   ├── sca/
│   ├── threat-intel/
│   ├── dashboards/
│   └── README.md
├── <integration_name_2>/
│   ├── ruleset/
│   │   ├── rules/
│   │   └── decoders/
│   ├── active-response/
│   ├── sca/
│   ├── threat-intel/
│   ├── dashboards/
│   └── README.md
└── ...

```

## Directory Definitions:

`<integration-name>`: Each top-level directory within integrations/ represents a specific third-party solution or integration point. Should be lowercase and separted by underscore `_`.

`ruleset/`: Contains Wazuh rules and decoders.

`rules/`: XML files defining Wazuh rules.

`decoders/`: XML files defining Wazuh decoders.

`active-response/`: Scripts or configurations for Wazuh active responses.

`sca/`: Files defining Wazuh Security Configuration Assessment (SCA) policies.

`threat-intel/`: Configurations or data related to integrating threat intelligence feeds.

`dashboards/`: JSON files for custom Wazuh dashboards.

`README.md`: Provides specific details and instructions for the individual integration.


