import json

from utils.api_utils import indexer_api_post, indexer_api_delete


def _step_ok(raw):
    """
    Did this indexer API call actually succeed? A non-2xx/error response, an
    unparsable body, or a _reindex response with non-empty "failures" all
    count as failed - checking only "truthy response text" previously let a
    blocked/failed step through, and the next step would run anyway.
    """
    if not raw:
        return False
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    if "error" in data:
        return False
    if data.get("failures"):
        return False
    return True


def reindex_for_mapping_conflict(index_name):
    """
    1. reindex <index>          -> <index>-backup
    2. delete original <index>
    3. reindex <index>-backup   -> <index>   (recreated with a clean mapping)
    4. delete <index>-backup

    Each step only runs if the previous one actually succeeded. This matters
    because delete_original and delete_backup are irreversible - if step 1
    (the backup) silently failed (e.g. index creation blocked cluster-wide)
    and step 2 ran anyway, the original would be gone with no copy to
    restore from. Stops and reports exactly which step failed instead.
    """
    backup_name = f"{index_name}-backup"
    steps = {}

    steps["backup"] = indexer_api_post(
        "/_reindex", {"source": {"index": index_name}, "dest": {"index": backup_name}}
    )
    if not _step_ok(steps["backup"]):
        steps["aborted_after"] = "backup"
        return steps

    steps["delete_original"] = indexer_api_delete(f"/{index_name}")
    if not _step_ok(steps["delete_original"]):
        steps["aborted_after"] = "delete_original"
        return steps

    steps["restore"] = indexer_api_post(
        "/_reindex", {"source": {"index": backup_name}, "dest": {"index": index_name}}
    )
    if not _step_ok(steps["restore"]):
        steps["aborted_after"] = "restore"
        return steps

    steps["delete_backup"] = indexer_api_delete(f"/{backup_name}")
    return steps
