import requests
from config import WAZUH_API_URL, API_USERNAME, API_PASSWORD

requests.packages.urllib3.disable_warnings()

def get_token():
    try:
        url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"

        res = requests.post(
            url,
            auth=(API_USERNAME, API_PASSWORD),
            verify=False
        )

        return res.text.strip()
    except:
        return None


def check_api():
    token = get_token()

    if not token:
        return "API AUTH FAILED"

    try:
        headers = {"Authorization": f"Bearer {token}"}

        res = requests.get(
            f"{WAZUH_API_URL}/",
            headers=headers,
            verify=False
        )

        return res.text
    except:
        return "API CONNECTION FAILED"
