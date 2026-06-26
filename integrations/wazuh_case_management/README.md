# Wazuh Case Management — Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing the Plugin](#installing-the-plugin)
    * [Initial Wazuh Configuration](#initial-wazuh-configuration)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

The **Wazuh Case Management** plugin is an OpenSearch Dashboards plugin that adds a full incident-response and case-management workflow natively inside the Wazuh Dashboard. Security analysts can create cases, link Wazuh alerts to them, track observables (IPs, hashes, URLs) and flag indicators of compromise (IOCs), manage work through a Kanban board, and measure response performance via an analytics dashboard.

Key capabilities:

- **Case lifecycle management** — create, assign, prioritize, and close security incident cases.
- **Alert linking** — search and attach existing Wazuh alerts directly to a case.
- **Observables & IOC tracking** — document artefacts and flag them as IOCs.
- **Kanban board** — drag-and-drop workflow visualization across Open / In-Progress / Resolved / Closed columns.
- **Activity timeline** — full audit trail of every case change with timestamps and actor.
- **Analytics dashboard** — MTTR, case-load, severity breakdowns, and SLA insights.
- **Webhook notifications** — configurable outbound webhooks on case events.

---

### Prerequisites

- **Wazuh** 4.14.5 or later (Wazuh Manager + Wazuh Dashboard).
- **OpenSearch Dashboards** 2.19.5 (bundled with Wazuh Dashboard 4.14.5).
- **Node.js** v18.x and **Yarn** 1.x (for building from source).
- Network connectivity between the Wazuh Dashboard host and the OpenSearch cluster.
- A user account with permissions to create and manage OpenSearch indices (`wazuh-case-management-*`).

---

### Installation and Configuration

#### Installing the Plugin

**Option A — Install from the pre-built zip**

```bash
# Copy the release zip to the Wazuh Dashboard host
scp wazuh-case-management-1.0.0.zip user@dashboard-host:/tmp/

# Install
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
  install file:///tmp/wazuh-case-management-1.0.0.zip

# Restart the service
sudo systemctl restart wazuh-dashboard
```

**Option B — Build and install from source**

```bash
# Prerequisites: Node 18, Yarn
git clone https://github.com/wazuh/wazuh-dashboard.git
cd wazuh-dashboard
git checkout 4.14.5

# Copy the plugin into the plugins directory
cp -r /path/to/wazuh_case_management plugins/wazuh-case-management

# Bootstrap dependencies
yarn osd bootstrap

# Build the plugin
cd plugins/wazuh-case-management
yarn build

# Install the generated zip
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
  install file://$(pwd)/build/wazuh-case-management-*.zip

sudo systemctl restart wazuh-dashboard
```

#### Initial Wazuh Configuration

No changes to the Wazuh Manager configuration are required. The plugin communicates directly with the underlying OpenSearch cluster using the Dashboard's built-in HTTP client. It will automatically create two indices on first startup:

| Index | Purpose |
|---|---|
| `wazuh-case-management-cases` | Stores all case data |
| `wazuh-case-management-counters` | Atomic counter for sequential case IDs |

Ensure the OpenSearch user configured in `opensearch_dashboards.yml` has at minimum the following privileges on the `wazuh-case-management-*` index pattern:

```
indices_allow: ["read", "write", "create_index", "delete", "manage"]
```

#### Using the Integration Files

The plugin source is organized as a standard OpenSearch Dashboards plugin:

```
wazuh_case_management/
├── common/          # Shared types, constants, and index definitions
├── public/          # React frontend (components, pages, styles, services)
│   ├── components/  # Reusable UI components (KanbanBoard, Timeline, IOC section …)
│   └── pages/       # Full page views (CaseList, CaseDetail, Dashboard, Monitor …)
├── server/          # Node.js backend routes and OpenSearch services
│   ├── routes/      # REST API handlers (cases, alerts, comments, webhooks …)
│   └── services/    # OpenSearch query helpers
├── opensearch_dashboards.json
├── package.json
└── tsconfig.json
```

---

### Integration Steps

1. **Install the plugin** using one of the methods above.
2. **Restart** the Wazuh Dashboard service.
3. **Open** the Wazuh Dashboard and navigate to the **Case Management** application from the left-hand navigation or the Wazuh app selector.
4. **Create a case** — click *Create Case*, fill in the title, description, assignee, severity, and priority.
5. **Link alerts** — from the case detail page, click *Link Alert* and search for existing Wazuh alerts by rule ID, agent, or keyword.
6. **Add observables** — document relevant artefacts (IPs, hashes, domains, URLs) and mark IOCs as needed.
7. **Track work** — use the Kanban board to move cases across workflow stages.
8. **Close the case** — set the status to *Resolved* or *Closed*. The plugin automatically calculates MTTR for analytics.
9. *(Optional)* Configure **webhook notifications** in *Settings* to push case events to external SOAR/ticketing platforms.

---

### Integration Testing

After installation, navigate to `https://<dashboard-host>/app/wazuh-case-management` in a browser and confirm the Case Management application loads. Create a test case, link a Wazuh alert, and verify it appears in the case detail page.

---

### Sources

- [Wazuh Documentation](https://documentation.wazuh.com)
- [OpenSearch Dashboards Plugin Development Guide](https://opensearch.org/docs/latest/dashboards/extension-points/)
- [Wazuh GitHub Repository](https://github.com/wazuh/wazuh)
