from utils.api_utils import indexer_api_put


def recommend_replica_count(node_count):
    """0 replicas for a single node (nowhere to put a copy); 1 for 2+ nodes."""
    return 0 if node_count <= 1 else 1


def set_replica_count(index_pattern, replicas):
    """
    Update number_of_replicas on an existing index/pattern. This is a
    dynamic setting - it applies to existing indices immediately, no
    reindex required (reindexing is a separate procedure for field-mapping
    conflicts - see utils/reindex_utils.py).
    """
    body = {"index": {"number_of_replicas": replicas}}
    return indexer_api_put(f"/{index_pattern}/_settings", body)
