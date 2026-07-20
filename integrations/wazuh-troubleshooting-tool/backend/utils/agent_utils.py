import re
from executor import run_command

AGENT_CONTROL = "/var/ossec/bin/agent_control"


def list_agents():
    """Raw `agent_control -l` output - one line per registered agent."""
    return run_command(f"{AGENT_CONTROL} -l") or ""


def find_agent_line(identifier):
    """Return the specific output line for one agent (matched by name or ID), or None if not found."""
    if not identifier:
        return None
    for line in list_agents().splitlines():
        if identifier.lower() in line.lower():
            return line
    return None


def is_agent_active(identifier):
    """
    True/False if the agent was found and we can read its state.
    None means the identifier wasn't found in the agent list at all.
    """
    line = find_agent_line(identifier)
    if line is None:
        return None
    return "active" in line.lower()


def list_active_agents():
    """
    Parse `agent_control -l` down to just the active agents, as
    [{"id": "001", "name": "some-agent", "raw": "<original line>"}].

    Agent 000 is always excluded - it's the manager's own local agent, not
    a real endpoint, so it's never a valid candidate for a restart test.
    """
    active = []
    for line in list_agents().splitlines():
        if "active" not in line.lower():
            continue
        id_match = re.search(r"ID:\s*(\S+)", line)
        # Stop at whichever comes first: a comma, the next "IP:" field, or a
        # run of 2+ spaces (agent_control's output isn't always comma-separated).
        name_match = re.search(r"Name:\s*(.+?)(?:,|\s+IP:|\s{2,}|$)", line)
        if not id_match:
            continue
        agent_id = id_match.group(1).strip(",")
        if agent_id == "000":
            continue
        active.append({
            "id": agent_id,
            "name": name_match.group(1).strip() if name_match else "unknown",
            "raw": line.strip(),
        })
    return active


def restart_agent(agent_id):
    """
    Remotely restart one agent by ID:  agent_control -R -u <agent_id>
    Only works if the agent is currently Active - it will not bring a
    disconnected agent back online.
    """
    return run_command(f"{AGENT_CONTROL} -R -u {agent_id}") or ""


def restart_all_agents():
    """Remotely restart every currently active agent:  agent_control -R -a"""
    return run_command(f"{AGENT_CONTROL} -R -a") or ""
