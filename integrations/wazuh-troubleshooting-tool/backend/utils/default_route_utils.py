from executor import run_command

DASHBOARD_CONFIG_PATH = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
EXPECTED_DEFAULT_ROUTE = "/app/wz-home"


def get_default_route():
    """Raw configured line for uiSettings.overrides.defaultRoute, or '' if not set."""
    return run_command(
        f"grep 'uiSettings.overrides.defaultRoute' {DASHBOARD_CONFIG_PATH}"
    ) or ""


def is_default_route_ok(raw=None):
    """
    After an upgrade, opensearch_dashboards.yml can be left over from the
    previous version and miss (or keep a stale) defaultRoute override. When
    that happens the dashboard serves an "Application Not Found" error
    instead of the home page.
    """
    raw = get_default_route() if raw is None else raw
    return EXPECTED_DEFAULT_ROUTE in raw


def set_default_route():
    """Set uiSettings.overrides.defaultRoute in opensearch_dashboards.yml. Caller restarts wazuh-dashboard afterward."""
    setting = f"uiSettings.overrides.defaultRoute: {EXPECTED_DEFAULT_ROUTE}"

    has_key = (run_command(
        f"grep -q 'uiSettings.overrides.defaultRoute' {DASHBOARD_CONFIG_PATH} "
        "&& echo yes || echo no"
    ) or "no").strip()

    if has_key == "yes":
        run_command(
            "sed -i 's|uiSettings.overrides.defaultRoute:.*|{}|' {}".format(
                setting, DASHBOARD_CONFIG_PATH
            )
        )
    else:
        run_command(f"echo '{setting}' >> {DASHBOARD_CONFIG_PATH}")

    return get_default_route()
