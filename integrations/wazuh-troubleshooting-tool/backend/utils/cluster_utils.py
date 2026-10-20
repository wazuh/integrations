from utils.api_utils import indexer_api_get_json, indexer_api_put

# Known cluster-wide settings that silently block writes/index creation
# cluster-wide, regardless of any single index's own health. This is the
# exact setting that caused the reindex data-loss incident - a blocked
# create_index looked completely invisible to a plain _cluster/health check.
KNOWN_WRITE_BLOCKS = ("cluster.blocks.read_only", "cluster.blocks.read_only_allow_delete", "cluster.blocks.create_index")


def get_cluster_health():
    """Returns (parsed_json_or_None, raw_text)."""
    return indexer_api_get_json("/_cluster/health")


def get_cluster_status():
    health, _ = get_cluster_health()
    return health.get("status") if health else None


def is_cluster_green():
    return get_cluster_status() == "green"


def get_cluster_settings():
    """Returns (parsed_json_or_None, raw_text) for persistent + transient cluster settings."""
    return indexer_api_get_json("/_cluster/settings")


def get_write_blocks():
    """
    Check for the known cluster-wide blocks that silently prevent writes or
    new index creation (e.g. a stale cluster.blocks.create_index from a
    prior incident). Returns {"blocks": {name: value, ...}} for whichever
    are actually set to something truthy, or {"error": raw} if the
    settings endpoint itself couldn't be reached.
    """
    settings, raw = get_cluster_settings()
    if settings is None:
        return {"error": raw}

    found = {}
    for scope in ("persistent", "transient"):
        scoped = settings.get(scope, {})
        for name in KNOWN_WRITE_BLOCKS:
            value = _dotted_get(scoped, name)
            if value is not None and str(value).lower() not in ("false", "none", ""):
                found[name] = value
    return {"blocks": found}


def clear_write_blocks(block_names):
    """Clear the given cluster.blocks.* settings (in both scopes, since either could hold it)."""
    reset = {name: None for name in block_names}
    body = {"persistent": reset, "transient": reset}
    return indexer_api_put("/_cluster/settings", body)


def _dotted_get(d, dotted_key):
    """d may have the key as one flat dotted string OR nested - OpenSearch's
    settings API can return either shape depending on the OpenSearch version."""
    if dotted_key in d:
        return d[dotted_key]
    node = d
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node
