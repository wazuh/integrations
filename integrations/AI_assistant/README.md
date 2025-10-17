# AI Assistant-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Architecture](#architecture)
* [Installation and Configuration](#installation-and-configuration)
    * [OpenSearch MCP Server](#opensearch-mcp-server)
    * [MCP-LLM Gateway](#mcp-llm-gateway)
    * [Wazuh environment](#wazuh-environment)
* [Samples questions](#samples-questions)
* [Recommendations & next steps](#recommendations--next-steps)
* [Important notes](#important-notes)
* [Sources](#sources)

---

### Introduction

A real-time chatbot for alert analysis on Wazuh. Ask natural-language questions to investigate threats, explain alerts, and get security recommendations.

The AI Assistant runs queries against Wazuh indices (e.g., `wazuh-alerts`, `wazuh-states-vulnerabilities`) through an MCP Server and a Gateway, which translate natural-language questions into OpenSearch queries and return concise, actionable insights. Results are displayed in the Wazuh Dashboard.

---

### Architecture

<img width="3200" height="1400" alt="wazuh-mcpserver" src="https://github.com/user-attachments/assets/d2fb527b-bece-4de8-823e-df366f5fa0f2" />

The integration uses OpenSearch ML Commons with an external MCP server. Instead of calling a traditional ML model endpoint, the ML Commons HTTP Connector points to the MCP-LLM Gateway. The Gateway orchestrates the LLM, applies the system prompt, and proxies tool calls to the MCP server.

#### Components
* **Wazuh environment (4.13, built on OpenSearch 2.9.2)**: Includes OpenSearch Dashboards with Dashboard Assistant, ML Commons (HTTP connector) is configured in the same environment. The environment collects, analyzes and stores normalized security data in Wazuh indices (e.g., wazuh-alerts, wazuh-states-vulnerabilities). ML Commons forwards Assistant requests to the Gateway
* **MCP-LLM Gateway (FastAPI + LangChain)**: Runs the agent logic (Claude on Bedrock or OpenAI), applies the system prompt, and proxies tool calls as the MCP client.
* **OpenSearch MCP server**: Hosts MCP tools that query Wazuh indices.


#### Connection flow
1. The user asks a natural-language question in OpenSearch Dashboards (Assistant UI).
2. ML Commons (HTTP connector) forwards the request to the MCP-LLM Gateway (`/analyze`).
3. The Gateway (FastAPI + LangChain) runs the agent logic, applies the system prompt, performs the LLM call (Claude on Bedrock or OpenAI), and selects which tools to invoke.
4. The Gateway serves as the MCP client and proxies tool requests to the OpenSearch MCP server.
5. The MCP server executes the tool(s) and queries the Wazuh indices (wazuh-alerts-*, wazuh-states-vulnerabilities-*).
6. The MCP server returns structured results to the Gateway.
7. The Gateway agent analyzes the tool outputs, generates a concise summary, and formats the final answer (including total_hits, summary, key findings, and recommendations).
8. The Gateway returns the final answer to ML Commons, which relays it to the Assistant UI in OpenSearch Dashboards for the user to view.

---

### Prerequisites

- Wazuh v4.13 (built on OpenSearch 2.9.2)
- Deployment: single-host or distributed setup. The MCP-LLM Gateway and MCP Server can run on the same host or on separate hosts.
- Resources: minimum 2 vCPU / 4 GB RAM, recommended 4 vCPU / 16 GB RAM.
- Active subscription to an external LLM service (OpenAI or AWS Bedrock)
- Network connectivity between all components (see **Required Ports**)

> **Tested on Ubuntu 24.04 LTS**

#### Required Ports
The following table lists the default ports required for this proof of concept. You can change these values if needed, but the ports must remain open between the listed components for the system to work.

| Component         | Port | Protocol | Purpose |
|-------------------|------|-----------|----------|
| MCP-LLM Gateway   | 9912 | TCP       | Receives HTTP requests from ML Commons (/analyze), runs agent logic, communicates with the LLM and the MCP server |
| MCP Server        | 9900 | TCP       | Exposes the MCP Server. It receives tool calls from the Gateway. The MCP server performs the corresponding queries against the Wazuh Indexer, and returns structured results back to the Gateway. |
| Wazuh Indexer     | 9200 | TCP       | Wazuh Indexer REST API |



---

### Installation and Configuration
---

### OpenSearch MCP Server

<details>
  <summary><b>1. Create the directory structure</b></summary>


  ```bash
sudo mkdir -p /opt/mcp_server-env
sudo mkdir -p /var/log/mcp_server
sudo mkdir -p /etc/mcp-server
```

MCP Server will use the following directories:

- `/opt/mcp_server-env/` — Python virtual environment and packages
- `/etc/mcp-server/` — Configuration files (environment/credentials)
- `/var/log/mcp_server/` — Log files

The config directory `/etc/mcp-server/` will contain `mcp-server.env`, which defines the connection to the Wazuh Indexer.

</details> 

<details>
  <summary><b>2. Create a dedicated service account</b></summary>
   
Create a dedicated system user so that the service runs with minimal privileges:

  ```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcpserver || true
```
</details> 

<details>
  <summary><b>3. Set ownership and permissions</b></summary>
   
Apply ownership and permissions to the configuration `/etc/mcp-server/` and log directories `/var/log/mcp_server/`. 

  ```bash
sudo chown -R root:root /etc/mcp-server
sudo chmod 750 /etc/mcp-server
sudo touch /etc/mcp-server/mcp-server.env
sudo chmod 640 /etc/mcp-server/mcp-server.env
sudo chown -R mcpserver:mcpserver /var/log/mcp_server
sudo chmod 750 /var/log/mcp_server
```

This also creates an empty `/etc/mcp-server/mcp-server.env` file. You will edit it later to define the Wazuh Indexer connection.

</details> 

<details>
  <summary><b>4. Set up the Python virtual environment</b></summary>

  ```bash
sudo apt-get update
sudo apt-get install -y python3-venv
python3 -m venv /opt/mcp_server-env
source /opt/mcp_server-env/bin/activate
pip install --upgrade pip

```

This isolates MCP Server dependencies from the system Python.

</details> 

</details> 

<details>
  <summary><b>5. Install the MCP Server package</b></summary>


  ```bash
pip install opensearch-mcp-server-py
```

Install the MCP Server package inside the virtual environment at  `/opt/mcp_server-env/`

</details> 

<details>
  <summary><b>6. Create the systemd service unit</b></summary>

Create the service file:

  ```bash
sudo nano /etc/systemd/system/mcp-server.service

```

mcp-server.service:

  ```bash
[Unit]
Description=OpenSearch MCP Server
After=network.target


[Service]
User=mcpserver
Group=mcpserver
WorkingDirectory=/opt/mcp_server-env
EnvironmentFile=/etc/mcp-server/mcp-server.env
ExecStart=/opt/mcp_server-env/bin/python -m mcp_server_opensearch --transport stream --host 0.0.0.0 --port 9900
Restart=always
RestartSec=10
TimeoutStopSec=15
StandardOutput=append:/var/log/mcp_server/mcp-server.log
StandardError=append:/var/log/mcp_server/mcp-server.log


[Install]
WantedBy=multi-user.target
```

Reload systemd and enable the service:

  ```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-server

```

</details> 


<details>
  <summary><b>7. Configure environment variables</b></summary>
   
Open `/etc/mcp-server/mcp-server.env` and add the connection details for the Wazuh Indexer:

  ```bash
sudo nano /etc/mcp-server/mcp-server.env

```

Copy and paste the contents of the [`mcp-server.env`](config/mcp-server/mcp-server.env) file.

</details> 


<details>
  <summary><b>8. Start the service</b></summary>

  ```bash
sudo systemctl start mcp-server
```

Check status:

  ```bash
systemctl status mcp-server
```

</details> 

<details>
  <summary><b>9. View logs</b></summary

Log files:

  ```bash
tail -f /var/log/mcp_server/mcp-server.log
```

</details> 


<details>
  <summary><b>10. Apply future changes</b></summary

To apply future changes, whenever you edit `/etc/mcp-server/mcp-server.env`, restart:

  ```bash
To apply future changes, whenever you edit `/etc/mcp-server/mcp-server.env`, restart:
```

</details> 

---
### MCP-LLM Gateway


<details>
  <summary><b>1. Create the directory structure</b></summary>


  ```bash
sudo mkdir -p /opt/mcp_llm_gateway-env
sudo mkdir -p /var/log/mcp_llm_gateway
sudo mkdir -p /etc/mcp-llm-gateway
```

MCP-LLM Gateway will use the following directories:

- `/opt/mcp_server-env/` — Python virtual environment and packages
- `/etc/mcp-llm-gateway/` — Configuration files (.env and .prompt)
- `/var/log/mcp_llm_gateway/` — Log files

</details> 


<details>
  <summary><b>2. Create a dedicated service account</b></summary>

Create a dedicated system user so that the service runs with minimal privileges:

  ```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcpgateway || true
```

</details> 

<details>
  <summary><b>3. Set ownership and permissions</b></summary>

Apply ownership and permissions to the configuration `/etc/mcp-llm-gateway/` and log directories `/var/log/mcp_llm_gateway/`. 

  ```bash
sudo chown root:mcpgateway /etc/mcp-llm-gateway
sudo chmod 750 /etc/mcp-llm-gateway
sudo touch /etc/mcp-llm-gateway/mcp-llm-gateway.env
sudo touch /etc/mcp-llm-gateway/mcp-llm-gateway.prompt
sudo chown root:mcpgateway /etc/mcp-llm-gateway/mcp-llm-gateway.env
sudo chown root:mcpgateway /etc/mcp-llm-gateway/mcp-llm-gateway.prompt
sudo chmod 640 /etc/mcp-llm-gateway/mcp-llm-gateway.env
sudo chmod 640 /etc/mcp-llm-gateway/mcp-llm-gateway.prompt
sudo chown -R mcpgateway:mcpgateway /var/log/mcp_llm_gateway
sudo chmod 750 /var/log/mcp_llm_gateway

```

This also creates empty `.env` and  `.prompt` files. You will edit them later to define the Wazuh Indexer connection and the system prompt used by the LLM.

</details> 

<details>
  <summary><b>4. Set up the Python virtual environment</b></summary>

  ```bash
sudo apt-get update
sudo apt-get install -y python3-venv
python3 -m venv /opt/mcp_llm_gateway-env
source /opt/mcp_llm_gateway-env/bin/activate
pip install --upgrade pip
```

This isolates MCP-LLM Gateway dependencies from the system Python.

</details> 


<details>
  <summary><b>5. Install dependencies</b></summary>

  ```bash
python -m pip install --upgrade \
  "fastapi>=0.110" "uvicorn[standard]>=0.29" "pydantic>=2.6" \
  "langchain>=0.2.6" "langchain-openai>=0.1.7" "langchain-mcp-adapters>=0.1.9" \
  "langchain-aws>=0.1.6" "boto3>=1.34"
```

</details> 

<details>
  <summary><b>6. Create the gateway script</b></summary>

  Create the MCP script inside the virtual environment at  `/opt/mcp_llm_gateway-env/`

  ```bash
sudo nano /opt/mcp_llm_gateway-env/mcp_llm_gateway.py
```

Copy and paste the contents of the [`mcp_llm_gateway.py`](config/mcp-llm-gateway/mcp_llm_gateway.py) file.

</details> 

<details>
  <summary><b>7. Configure environment variables</b></summary>

Edit `/etc/mcp-llm-gateway/mcp-llm-gateway.env`:

  ```bash
sudo nano /etc/mcp-llm-gateway/mcp-llm-gateway.env
```

Copy and paste the contents of the [`mcp-llm-gateway.env`](config/mcp-llm-gateway/mcp-llm-gateway.env) file.

Note: Only one LLM provider can be active at a time. To use Claude (Bedrock), keep the AWS variables and leave the OpenAI section commented. To use OpenAI, comment the AWS variables and uncomment the OpenAI section.

</details> 

<details>
  <summary><b>8. Configure the system prompt</b></summary>

   This file defines the behavioral rules and policies that guide how the LLM responds to user queries.

If you need to adjust how the assistant interprets security questions or interacts with Wazuh data, you can edit this file.

Edit the prompt configuration file `/etc/mcp-llm-gateway/mcp-llm-gateway.prompt`:

  ```bash
sudo nano /etc/mcp-llm-gateway/mcp-llm-gateway.prompt
```
Starter content (you can refine later):

Copy and paste the contents of the [`mcp-llm-gateway.prompt`](config/mcp-llm-gateway/mcp-llm-gateway.prompt) file.

</details> 


<details>
  <summary><b>9. Create the systemd service unit</b></summary>

Create the service file:

  ```bash
sudo nano /etc/systemd/system/mcp-llm-gateway.service
```

`mcp-llm-gateway.service`:

  ```bash
[Unit]
Description=MCP LLM Gateway
After=network.target


[Service]
User=mcpgateway
Group=mcpgateway
WorkingDirectory=/opt/mcp_llm_gateway-env
EnvironmentFile=/etc/mcp-llm-gateway/mcp-llm-gateway.env
ExecStart=/opt/mcp_llm_gateway-env/bin/python /opt/mcp_llm_gateway-env/mcp_llm_gateway.py
ReadOnlyPaths=
ReadWritePaths=/etc/mcp-llm-gateway /var/log/mcp_llm_gateway
Restart=always
RestartSec=10
TimeoutStopSec=15
StandardOutput=append:/var/log/mcp_llm_gateway/mcp-llm-gateway.log
StandardError=append:/var/log/mcp_llm_gateway/mcp-llm-gateway.log


[Install]
WantedBy=multi-user.target
```
Reload systemd and enable the service:

  ```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-llm-gateway
```

</details> 


<details>
  <summary><b>10. Start the service</b></summary>

  ```bash
sudo systemctl start mcp-llm-gateway

```

Check status:
  ```bash
systemctl status mcp-llm-gateway
```
</details> 

<details>
  <summary><b>11. Run a health check</b></summary>

Verify Gateway, LLM, and MCP connectivity. 

Run the following command to confirm all components are operational:

  

  ```bash
curl -s http://<MCP_LLM_GATEWAY_HOST-IP>:9912/health | jq

```

If everything is working properly, you will see a response similar to the following:
  ```bash
{
  "summary": "All components operational.",
  "status": {
    "gateway": "ok",
    "llm": "ok",
    "mcp": "ok"
  },
  "details": {
    "mcp_tools_count": 8
  },
  "provider": "claude_bedrock",
  "model": "anthropic.claude-3-sonnet-20240229-v1:0",
  "mcp_url": "http://10.128.0.27:9900/sse"
}

```
</details> 


<details>
  <summary><b>12. View logs</b></summary>

Log files:

Run the following command to confirm all components are operational:

  

  ```bash
tail -f /var/log/mcp_llm_gateway/mcp-llm-gateway.log
```
</details> 


<details>
  <summary><b>13. Apply future changes</b></summary>

To apply future changes, whenever you edit `mcp-llm-gateway.prompt` or `mcp_llm_gateway.py`, restart:


  ```bash
sudo systemctl restart  mcp-llm-gateway
```
</details> 

---
### Wazuh environment


<details>
  <summary><b>1. Install the OpenSearch Dashboards plugin in the Wazuh Dashboard</b></summary>



  ```bash
curl https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.19.2/opensearch-dashboards-2.19.2-linux-x64.tar.gz -o opensearch-dashboards.tar.gz

tar -xvzf opensearch-dashboards.tar.gz

cp -r opensearch-dashboards-2.19.2/plugins/assistantDashboards/ /usr/share/wazuh-dashboard/plugins/

cp -r opensearch-dashboards-2.19.2/plugins/mlCommonsDashboards/ /usr/share/wazuh-dashboard/plugins/
chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/plugins/mlCommonsDashboards/

chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/plugins/assistantDashboards/
chmod -R 750 /usr/share/wazuh-dashboard/plugins/mlCommonsDashboards/
chmod -R 750 /usr/share/wazuh-dashboard/plugins/assistantDashboards/

ls -la /usr/share/wazuh-dashboard/plugins/ | grep -E "(assistant|ml)"
echo "assistant.chat.enabled: true" >> /etc/wazuh-dashboard/opensearch_dashboards.yml

systemctl restart wazuh-dashboard
systemctl status wazuh-dashboard

```
</details> 

<details>
  <summary><b>2. Cluster settings</b></summary>
   
In the Wazuh Dashboard go `☰` > `Indexer management` > `Dev tools`


  ```json
PUT /_cluster/settings
{
  "persistent": {
    "plugins.ml_commons.agent_framework_enabled": true
  }
}
```

Output:
  ```json
{
  "acknowledged": true,
  "persistent": {
    "plugins": {
      "ml_commons": {
        "agent_framework_enabled": "true"
      }
    }
  },
  "transient": {}
}

```


  ```json
PUT /_cluster/settings
{
  "persistent" : {
    "plugins.ml_commons.only_run_on_ml_node":"false"
  }
}

```

Output:
  ```json
{
  "acknowledged": true,
  "persistent": {
    "plugins": {
      "ml_commons": {
        "only_run_on_ml_node": "false"
      }
    }
  },
  "transient": {}
}

```

Replace with the IP of the MCP-LLM Gateway:

  ```json
PUT /_cluster/settings
{
    "persistent": {
        "plugins.ml_commons.connector.private_ip_enabled": true,
        "plugins.ml_commons.trusted_connector_endpoints_regex": [
          "^https://runtime\\.sagemaker\\..*[a-z0-9-]\\.amazonaws\\.com/.*$",
          "^https://api\\.openai\\.com/.*$",
          "^https://api\\.cohere\\.ai/.*$",
          "^https://bedrock-runtime\\..*[a-z0-9-]\\.amazonaws\\.com/.*$",
         "^http://10\\.128\\.0\\.10:9912/.*$"
        ]
    }
}


```

Output:
  ```json
{
  "acknowledged": true,
  "persistent": {
    "plugins": {
      "ml_commons": {
        "connector": {
          "private_ip_enabled": "true"
        },
        "trusted_connector_endpoints_regex": [
          """^https://runtime\.sagemaker\..*[a-z0-9-]\.amazonaws\.com/.*$""",
          """^https://api\.openai\.com/.*$""",
          """^https://api\.cohere\.ai/.*$""",
          """^https://bedrock-runtime\..*[a-z0-9-]\.amazonaws\.com/.*$""",
          """^http://10\.128\.0\.10:9912/.*$"""
        ]
      }
    }
  },
  "transient": {}
}


```

</details> 


<details>
  <summary><b>3. Register remote model</b></summary>
   
Replace:
-  `<MCP_LLM_GATEWAY_HOST-IP>` with the IP where your MCP-LLM Gateway listens (default port `9912`).
-  `<GATEWAY_API_KEY>` with the value of `GATEWAY_API_KEY` you set in `/etc/mcp-llm-gateway/mcp-llm-gateway.env` (default value is `secret`).

Notes:
-  If your gateway uses TLS, change the endpoint to `https://<MCP_LLM_GATEWAY_HOST-IP>:9912/analyze` and make sure the certificate is trusted by the Indexer.
-  You can adjust request_timeout if your LLM calls need more time.

  ```json
POST _plugins/_ml/models/_register
{
  "name": "mcp-llm-gateway-model",
  "function_name": "remote",
  "description": "Remote model: OpenSearch → MCP+LLM Gateway",
  "connector": {
    "name": "mcp-llm-gateway-connector",
    "version": 1,
    "protocol": "http",
    "parameters": {
     "endpoint": "http://<MCP_LLM_GATEWAY_HOST-IP>:9912/analyze"
    },
    "credential": {
     "api_key": "secret"
    },
    "actions": [
      {
        "action_type": "predict",
        "method": "POST",
        "url": "${parameters.endpoint}",
        "headers": {
          "Content-Type": "application/json",
          "X-API-Key": "${credential.api_key}"
        },
        "request_body": "{ \"parameters\": { \"prompt\": \"${parameters.prompt}\" } }",
       "request_timeout": "120s"
      }
    ]
  }
}

```
Output:
 ```json
{
  "task_id": "LA-ZL5kBGGL3sSynHOI9",
  "status": "CREATED",
  "model_id": "LQ-ZL5kBGGL3sSynHeLw"
}

```
</details> 



<details>
  <summary><b>4. Deploy the model</b></summary>

Replace `<model_id>` with the `model_id` you obtained in the previous step

  ```json
POST _plugins/_ml/models/<model_id>/_deploy
```

Output:
 ```json

{
  "task_id": "MA-ZL5kBGGL3sSynx-LT",
  "task_type": "DEPLOY_MODEL",
  "status": "COMPLETED"
}

```
</details> 


<details>
  <summary><b>5. Create an agent</b></summary>

Replace `<model_id>` with the  `model_id`

  ```json
POST _plugins/_ml/agents/_register
{
  "name": "mcp-os-agent",
  "type": "conversational",
  "app_type": "os_chat",
  "description": "Conversational agent that delegates to MCP+LLM gateway; MCP tool-calls happen in the gateway.",
  "llm": {
   "model_id": "<model_id>",
    "parameters": {
      "prompt": "${parameters.question}",
      "response_filter": "$.output.message",
      "max_iteration": 1,
      "stop_when_no_tool_found": true,
      "message_history_limit": 10
    }
  },
  "memory": { "type": "conversation_index" },
  "tools": [
    { "type": "SearchIndexTool", "name": "placeholder_noop" }
  ]
}

```

Output:
 ```json
{
 "agent_id": "Mg-bL5kBGGL3sSynxOIj"
}
```
</details> 



<details>
  <summary><b>6. Set agent as root</b></summary>

Configure the agent id  used by OpenSearch Assistant.

If you run a multi-node Wazuh Indexer cluster, execute this once against any healthy node. Run the request with super-admin privileges.

Replace `<WAZUH_INDEXER_IP>` with the IP or hostname of your Wazuh Indexer node, and replace `<agent_id>` with the `agent_id` obtained in the previous step.

In the Wazuh Indexer, run:

  ```bash
DIR="/etc/wazuh-indexer/certs"


curl --cacert $DIR/root-ca.pem --cert $DIR/admin.pem --key $DIR/admin-key.pem -XPUT https://WAZUH_INDEXER_IP:9200/.plugins-ml-config/_doc/os_chat -H 'Content-Type: application/json' -d '{"type": "os_chat_root_agent","configuration": {"agent_id": "<agent_id>"}}'
```

Output:
 ```json
[root@ip-10-0-0-165 bin]# DIR="/etc/wazuh-indexer/certs"
[root@ip-10-0-0-165 bin]# curl --cacert $DIR/root-ca.pem --cert $DIR/admin.pem --key $DIR/admin-key.pem \
> -XPUT https://10.0.0.165:9200/.plugins-ml-config/_doc/os_chat -H 'Content-Type: application/json' -d '{
>   "type": "os_chat_root_agent",
>   "configuration": {
>     "agent_id": "Mg-bL5kBGGL3sSynxOIj"
>   }
> }'
{"_index":".plugins-ml-config","_id":"os_chat","_version":4,"result":"updated","_shards":{"total":4,"successful":4,"failed":0},"_seq_no":4,"_primary_term":2}[root@ip-10-0-0-165 bin]#

```
</details> 



<details>
  <summary><b>7. Test the agent</b></summary>

Replace `<agent_id>` with the `agent_id`.

  ```json
POST /_plugins/_ml/agents/<agent_id>/_execute
{
  "parameters": {
"question": "Hello",
    "verbose": true
  }
}
```

Output:
 ```json
{
  "inference_results": [
    {
      "output": [
        {
          "name": "memory_id",
          "result": "SKH8wZkBtkHUMBWIV4XL"
        },
        {
          "name": "parent_interaction_id",
          "result": "SaH8wZkBtkHUMBWIV4Xk"
        },
        {
          "name": "response",
          "result": """Hello! I can help with cybersecurity questions and analyze alerts and vulnerabilities from your Wazuh environment.
Examples of queries:
- Analyze the most important alerts in my environment
- Analyze the alerts from the last X minutes
- Analyze brute force attack alerts
- Please analyze the alert with the rule ID X
- Which endpoints are affected by this CVE-XXXX-XXXXX
- List critical CVEs"""
        }
      ]
    }
  ]
}
```
</details> 


<details>
  <summary><b>8. Personalize the Dashboard Assistant UI</b></summary>

To hide any reference to the OpenSearch Assistant chat interface and display a custom Dashboard Assistant, create a small script. 

Install the brotli utility. If it not already installed on your system

  ```bash
sudo apt-get update
sudo apt-get install -y brotli
```

Create a script file:
 ```bash
sudo nano dashboard-assistant-ui.sh
```

Copy and paste the contents of the [`dashboard-assistant-ui.sh`](config/dashboard/dashboard-assistant-ui.sh) file.

Make the script executable:

 ```bash
sudo chmod +x dashboard-assistant-ui.sh
```

Run the script:

 ```bash
sudo bash ./dashboard-assistant-ui.sh
```

Restart the Wazuh Dashboard service:

 ```bash
sudo systemctl restart wazuh-dashboard
```

After restart, the UI will display Dashboard Assistant instead of OpenSearch Assistant.

To launch the Dashboard Assistant, click the chat icon  in the top-right corner of the Wazuh Dashboard interface.

If the change is not visible, try signing out and logging in again to the Wazuh Dashboard.

<img width="1909" height="965" alt="Dashboard-assistant" src="https://github.com/user-attachments/assets/b595fbb8-9c70-403b-9b60-6c4118db0e53" />

<img width="904" height="550" alt="dashboard-assistant-zoom" src="https://github.com/user-attachments/assets/dc2e15b9-233f-4eae-9cba-e1f0d5a63e9b" />

</details> 

---
### Samples questions

Use these to validate end-to-end behavior and the reporting format:
-  Analyze the most important alerts in my environment
-  Analyze brute force attack alerts
-  Please analyze the alerts: "sshd: brute force trying to get access to the system. Non existent user."
-  Please analyze the alert with the rule ID XXX
-  Which endpoints are affected by this CVE-XXXX-XXXXX
-  Analyze the alerts from the last X minutes


<img width="1902" height="959" alt="2-Analyze brute force attack alerts" src="https://github.com/user-attachments/assets/cf59d312-5e96-449a-b3a5-0d27ec21daef" />

<img width="1902" height="959" alt="5-Which endpoints are affected by this CVE-2023-47038 " src="https://github.com/user-attachments/assets/ffec956f-e991-491c-9d09-cdb5caa9ceed" />

<img width="1902" height="959" alt="4-Please analyze the alert with the rule ID 553" src="https://github.com/user-attachments/assets/6cba0760-6912-4a06-b6f8-ff8e6c49895c" />


---

### Recommendations & next steps

- Refine and test the system prompt to maximize token efficiency and response quality.
- Conduct testing with a variety of queries specific to defined use cases
- Monitor the gateway/service logs for tool-use errors, timeouts, or missing fields.

---

### Important notes

- Always cross-verify AI-generated advice before taking action in production.
- This AI Assistant, with conversational tooling, is a starting point and should be continuously improved as use cases and requirements evolve.


---

### Sources
- [Introducing MCP in OpenSearch](https://github.com/opensearch-project/project-website/blob/c896713b6e1e25add756d6e20583cb88fa05c558/_posts/2025-05-05-Introducing-MCP-in-OpenSearch.md#section-12-standalone-opensearch-mcp-server)
- [Build a Chatbot with OpenSearch](https://docs.opensearch.org/latest/tutorials/gen-ai/chatbots/build-chatbot/)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io/docs/getting-started/intro)
