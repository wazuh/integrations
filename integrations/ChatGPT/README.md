# ChatGPT integration

## Description
Some clients have requested a way to obtain an analysis of their alerts with ChatGPT (and even with their own implementation of AI), so we are going to use a script to sent a prompt and obtain information using the API of openAI.

## Requirements
- Access to the required AI implmementation
- A key to contact their API
- Understanding of the structure of the answer

# Configurations:

1. Add the rules from `custom-chatgpt.xml`
2. On the `ossec.conf` file from the wazuh-manager server, add the following lines:
```
<integration>
  <name>custom-chatgpt</name>
  <level>15</level>  <!-- Replace this number with the desired limit for your alerts, current example is level 15 and above-->
  <hook_url>https://api.openai.com/v1/chat/completions</hook_url>  <!--If needed, replace this url with the url of your implementation-->
  <api_key>dummyKey</api_key>  <!-- Replace this with your key-->
  <alert_format>json</alert_format>
</integration>
```

3. On the wazuh-manager server, add this file on the following path: `/var/ossec/integrations/`

4. provide the following permissions: `chown root:wazuh /var/ossec/integrations/custom-chatgpt && chmod 750 /var/ossec/integrations/custom-chatgpt`

5. If you want to check step by step what is happening in the integration, you can use the command: tail -f /var/ossec/logs/newLog.log  (the current script is configured to have this option enabled to let you test the integration. When it is working, we can remove this log implementation)

# Considerations

1. If you want to add more fields to the prompt, you can add them to the variable `proposal` on the function `request_chatgpt_info()`. Just check that you are following the structure of the fields defined on the alert that will be analyzed.

2. The script expects an answer with the following structure, if the structure changes, the script must be modified to understand the information received:
```
{
  "id": "chatcmpl-abc123xyz789",
  "object": "chat.completion",
  "created": 1718201234,
  "model": "gpt-3.5-turbo-0125",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "### 🔍 Investigation Report – Wazuh SIEM Alert\n\n---\n\n### 📌 Description of the Issue\n- **Vulnerability:** CVE-2023-47359  ..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 220,
    "completion_tokens": 420,
    "total_tokens": 640
  }
}
```

3. If you are using openAI, you should check if the model `gpt-3.5-turbo` is the one that you expect to use. Here you can find a list of available models:  
https://platform.openai.com/docs/pricing#other-models

4. On openAI's implementation, we send the prompt to the following endpoind. This must be modified if you expect to use a different implementation of AI.  
https://platform.openai.com/docs/api-reference/completions/create

5. As described on their documentation, if you need to test the connection to the API, you can use thefollowing command:
```
curl https://api.openai.com/v1/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer addTheKeyHere" \
  -d '{
    "model": "gpt-3.5-turbo",
    "prompt": "Say this is a test",
    "max_tokens": 7,
    "temperature": 0
  }'
  ```

# References
https://platform.openai.com/docs/api-reference/completions/create

https://platform.openai.com/docs/pricing#other-models
