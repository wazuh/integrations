# Contributing to Wazuh Integrations

Thank you for considering contributing to the Wazuh Integrations repository! Your contributions help expand the capabilities of Wazuh for the community.

Before submitting your contribution, please review these guidelines.

## How to Contribute a New Integration

To contribute a new integration, follow these steps:

1.  **Fork the Repository**: Start by forking this repository to your GitHub account.
2.  **Create a New Branch**: Create a new branch for your integration.
3.  **Create Your Integration Directory**:
    * Inside the `integrations/` folder, create a new directory for your integration.
    * **Integration directory names must be lowercase and underscore_separated** (e.g., `misp_integration`, `fortigate_firewall`).
    * This directory will house all files related to your integration.
4.  **Populate Your Integration Directory**:
    * Include all necessary Wazuh components (rules, decoders, active responses, SCA policies, threat intelligence configurations, dashboards). Refer to the main `README.md` for the expected sub-folder structure (`ruleset/`, `active-response/`, `sca/`, `threat-intel/`, `dashboards/`).
    * If your integration requires **images** (e.g., screenshots for configuration steps), create an `images/` subdirectory within your integration's main folder (e.g., `integrations/<your-integration-name>/images/`). Reference these images in your `README.md` relative to the `images/` folder.
    * Include any other necessary files, such as Python scripts or configuration files, directly in the integration's main directory or a logical subdirectory if needed.
5.  **Create the Integration's `README.md`**: Each integration **must** include its own `README.md` file within its directory. This `README.md` should clearly explain the integration and its setup.

## Integration `README.md` Structure

The `README.md` for every new integration must follow this standardized structure to ensure consistency and ease of use for the community.

### Required Sections and Content:

Use the following template for your `README.md`:

```markdown
# [INTEGRATION_NAME]-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing [THIRD_PARTY_SOLUTION_NAME]](#installing-third_party_solution_name)
    * [Initial [THIRD_PARTY_SOLUTION_NAME] Configuration](#initial-third_party_solution_name-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

Provide a brief overview of what this integration does, its purpose, and how it benefits Wazuh users. Explain the value proposition.

---

### Prerequisites

List all necessary prerequisites for setting up this integration. This may include:
* Specific versions of Wazuh Server or Agents.
* Specific versions of the third-party solution.
* Required software, libraries, or dependencies (e.g., Python modules).
* Necessary network access or firewall rules.
* Required user permissions or API keys.

---

### Installation and Configuration

#### Installing [THIRD_PARTY_SOLUTION_NAME]

Provide clear, step-by-step instructions on how to install the third-party solution if it's not assumed to be pre-existing. Include relevant links to official documentation.

#### Initial [THIRD_PARTY_SOLUTION_NAME] Configuration

Detail the necessary configuration steps within the third-party solution to prepare it for integration with Wazuh. This might include:
* Enabling specific features or APIs.
* Creating API keys or service accounts.
* Setting up logging or data export mechanisms.
* **Include screenshots where helpful, placed in the `images/` directory within your integration folder and linked here.**

#### Installing Wazuh (if applicable)

If the integration has specific Wazuh installation requirements beyond standard setup, detail them here. Otherwise, you can state that a standard Wazuh installation is assumed and provide a link to the official Wazuh documentation.

#### Initial Wazuh Configuration (if applicable)

Explain any initial Wazuh Server/Indexer or Agent configurations required before deploying the integration's files. This could involve enabling modules or specific settings.

#### Using the Integration Files

Provide precise instructions on how to deploy and configure the specific files provided within your integration's directory.
* **Rules and Decoders**: Where to place `.xml` files (e.g., `/var/ossec/etc/rules/`, `/var/ossec/etc/decoders/`), and how to reference them in `ossec.conf`.
* **Active Response Scripts**: Where to place scripts (e.g., `/var/ossec/active-response/bin/`) and how to configure them in `ossec.conf`.
* **SCA Policies**: Where to place `.yml` files (e.g., `/var/ossec/etc/shared/default/`) and how to configure them.
* **Threat Intelligence**: How to integrate feed configurations.
* **Dashboards**: Instructions on importing the `.json` dashboard files into OpenSearch Dashboards or Kibana.
* **Any Other Custom Files**: Explain the purpose and placement of any other files you've included.
* **Remember to restart Wazuh services** (e.g., `systemctl restart wazuh-manager`) after configuration changes.

---

### Integration Steps

Detail the complete workflow for making the integration functional, from end to end. This section bridges the gap between configuration and active operation.
* How data flows from the third-party solution to Wazuh.
* Any specific commands to run or actions to perform to trigger the integration.
* Examples of expected logs or events generated.

---

### Integration Testing

Describe clear steps on how to verify that the integration is working as expected.
* Provide example scenarios or commands to trigger an event in the third-party solution that should be detected by Wazuh.
* Show how to check Wazuh logs (`/var/ossec/logs/archives/archives.log`, `/var/ossec/logs/ossec.log`) for expected alerts or events.
* Demonstrate how to view results in the Wazuh dashboard.
* Include expected output examples (e.g., a specific alert ID or log snippet).

---

### Sources

List any official documentation, blog posts, or resources that were used as references for building this integration. Provide links where possible.


## Submitting Your Pull Request

Once your integration is ready and adheres to the above guidelines:

Commit Your Changes: Commit your changes with a clear and concise commit message.

Push to Your Fork: Push your branch to your forked repository on GitHub.

Open a Pull Request: Go to the original Wazuh Integrations repository on GitHub and open a new Pull Request from your branch.

Provide a Clear Description: In your Pull Request description, briefly explain what your integration does and ensure it meets the outlined requirements.

Address Feedback: Be prepared to address any feedback or review comments from the maintainers.

We appreciate your contributions!