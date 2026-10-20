from utils.api_utils import indexer_api_get, indexer_api_get_json, indexer_api_post_json

DEFAULT_MAX_SHARDS_PER_NODE = 1000  # OpenSearch/Elasticsearch default cluster.max_shards_per_node


def get_node_count():
    """
    Live node count from _cat/nodes rather than parsed out of a config.yml
    on disk - that file's path/format isn't consistent across every
    install type (single-node OVA, multi-node cluster, Docker, etc.), the
    cluster itself always knows how many nodes it has.
    """
    raw = indexer_api_get("/_cat/nodes?h=name") or ""
    names = [l.strip() for l in raw.splitlines() if l.strip()]
    return len(names), names


def get_total_shard_count():
    """(active_shards + unassigned_shards) from _cluster/health. Returns (None, raw) on failure."""
    health, raw = indexer_api_get_json("/_cluster/health")
    if not health:
        return None, raw
    return health.get("active_shards", 0) + health.get("unassigned_shards", 0), raw


def get_shard_limit(node_count=None):
    node_count = node_count if node_count is not None else get_node_count()[0]
    return DEFAULT_MAX_SHARDS_PER_NODE * max(node_count, 1)


def get_shard_capacity_percent():
    """Percent of the cluster's total shard capacity currently in use, or None if unreachable."""
    node_count, _ = get_node_count()
    total, _ = get_total_shard_count()
    if total is None:
        return None
    limit = get_shard_limit(node_count)
    return round((total / limit) * 100, 1) if limit else 0


def is_near_shard_limit(threshold_percent=90):
    percent = get_shard_capacity_percent()
    return percent is not None and percent >= threshold_percent


def get_unassigned_shards():
    """List every currently-unassigned shard: index, shard #, prirep, reason code."""
    raw = indexer_api_get("/_cat/shards?h=index,shard,prirep,state,unassigned.reason") or ""
    rows = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3] == "UNASSIGNED":
            rows.append({
                "index": parts[0], "shard": parts[1], "prirep": parts[2],
                "reason": parts[4] if len(parts) > 4 else "unknown",
            })
    return rows


def explain_allocation(index, shard, primary=False):
    """Raw _cluster/allocation/explain result for one specific unassigned shard."""
    body = {"index": index, "shard": int(shard), "primary": primary}
    data, raw = indexer_api_post_json("/_cluster/allocation/explain", body)
    return data or {"error": raw}
