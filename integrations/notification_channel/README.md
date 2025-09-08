# Opensearch Notification Channel-Wazuh 

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)


---

### Introduction

Alerting is a key component of Wazuh’s security monitoring and incident response capabilities. By integrating the OpenSearch Alerting plugin, users can define monitors, triggers, and notification channels to receive timely alerts when specific conditions are met.

This document provides step-by-step guidance on configuring notification channels in Wazuh with the OpenSearch Alerting plugin. It covers two commonly used notification methods: Email (via SMTP) and Discord (via webhooks).

The Mail section explains how to set up an SMTP server, configure email senders, and create an email notification channel.

The Discord section demonstrates how to create a webhook in Discord, configure it as a notification channel in Wazuh, and work around formatting issues in test messages to ensure alerts are delivered successfully.

By following this guide, you will be able to configure and validate notification channels, ensuring that important alerts are delivered promptly to your chosen communication platforms.

---

### Prerequisites

* A Wazuh Deployment.
* A Running SMTP server.
* A mail account with two-factor authentication.
* A Discord server.


---

