"""
Use case: 'Filebeat Mapping Issue' - field-mapping / index-template
conflicts between what the Wazuh Indexer expects and what's actually being
written (illegal_argument_exception, mapper_parsing_exception, a dashboard
"N of M shards failed" popup, etc).

Handed off to from use_cases/filebeat_error.py when the Filebeat log or
`filebeat test output` output matches a known mapping-error signature, but
also reachable directly as its own card.

Diagnostic sequence, based on real support cases:
    1. Check whether the Wazuh Indexer actually has the default "wazuh"
       index template registered, and that it's the canonical one (correct
       index_patterns / settings) rather than missing or overridden by a
       stray custom template.
    2. If a specific field was named in the error, check that field's type
       in the live template.
    3. If it's missing/wrong, reinstall the canonical wazuh-template.json
       and push it with `filebeat setup --index-management`.
    4. Offer to reindex any already-affected index (backup, delete,
       restore, delete backup) so the fix also applies retroactively -
       reinstalling the template alone only affects indices created after
       the fix.
"""

from executor import run_command
from utils.api_utils import indexer_api_get, indexer_api_get_json, indexer_api_delete
from utils.index_utils import check_most_recent_index
from utils.reindex_utils import reindex_for_mapping_conflict
from utils.ai_utils import ai_explain

WAZUH_TEMPLATE_URL = "https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/elasticsearch/7.x/wazuh-template.json"
EXPECTED_INDEX_PATTERNS = {"wazuh-alerts-4.x-*", "wazuh-archives-4.x-*"}
WAZUH_COMMUNITY_URL = "https://wazuh.com/community/"

UNCLEAR_TEMPLATE_SYSTEM_PROMPT = (
    "You are a Wazuh Indexer (OpenSearch) troubleshooting expert. You'll be given the live "
    "'wazuh' index template (or its absence) and the list of registered templates. In 3-4 "
    "short sentences: state the most likely root cause of a field-mapping conflict and the "
    "single most useful next command or config fix. Be specific to what's actually in the "
    "data - don't give generic advice."
)


def _dotted_get(d, dotted_key):
    node = d
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def mapping_issue_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    response = {"display": "", "ask": [], "done": False, "context": context}
    choice = (user_choice or "").strip().lower()

    # START
    if not context:
        response["display"] = (
            "Let's check whether this is a Wazuh Indexer field-mapping/index-template issue "
            "rather than a Filebeat connectivity problem - this is what causes errors like "
            "'illegal_argument_exception', 'mapper_parsing_exception', or a dashboard "
            "'N of M shards failed' popup.\n\n"
            "How would you like to check this?\n\n"
            "  Auto   - We perform all checks automatically.\n"
            "  Manual - We provide the commands, and you run them and share the output."
        )
        response["ask"] = ["Auto", "Manual"]
        context["stage"] = "method"
        return response

    stage = context.get("stage")

    if stage == "method":
        if "manual" in choice:
            response["display"] = (
                "Run these against the indexer (Indexer Management > Dev Tools, or curl):\n\n"
                "    GET /_template/wazuh\n"
                "    GET /_cat/templates\n\n"
                "Does the 'wazuh' template exist, and does /_cat/templates show it covering "
                f"{sorted(EXPECTED_INDEX_PATTERNS)}?"
            )
            response["ask"] = ["Yes, it looks correct", "No / missing / different"]
            context["stage"] = "manual_result"
            return response
        return _check_template(response, context)

    if stage == "manual_result":
        if "yes" in choice:
            return _ask_field_name(response, context)
        return _offer_template_fix(response, context, reason="You reported the template is missing or incorrect.")

    if stage == "field_name_wait":
        return _check_field_type(response, context, user_choice)

    if stage == "field_type_decision":
        if "fix" in choice or "needs" in choice:
            return _offer_template_fix(
                response, context,
                reason=f"'{context.get('mapping_field')}' needs its type corrected in the template.",
            )
        return _no_specific_field(response, context)

    if stage == "fix_template":
        if "auto" in choice:
            return _auto_fix_template(response, context)
        if "manual" in choice:
            response["display"] = _manual_template_fix_instructions()
            response["ask"] = ["Done"]
            context["stage"] = "fix_template_manual_wait"
            return response
        response["ask"] = ["Auto", "Manual"]
        return response

    if stage == "fix_template_manual_wait":
        response["display"] = "Template reinstalled (per your report). This only affects new indices going forward."
        return _offer_reindex(response, context)

    if stage == "reindex_method":
        return _handle_reindex_method(response, context, choice)

    if stage == "reindex_index_wait":
        context["mapping_index"] = (user_choice or "").strip()
        return _confirm_reindex(response, context)

    if stage == "reindex_confirm":
        if "skip" in choice or "no" in choice:
            response["display"] = "Skipping the reindex."
            response["done"] = True
            return response
        return _auto_reindex_one(response, context)

    response["display"] = "Invalid stage."
    response["done"] = True
    return response


# ---------------------------------------------------------------------------
def _check_template(response, context):
    response["display"] += ("\n" if response["display"] else "") + "Checking the live Wazuh Indexer template..."
    templates_raw = indexer_api_get("/_cat/templates") or ""
    template, _ = indexer_api_get_json("/_template/wazuh")
    context["cat_templates"] = templates_raw

    response["display"] += f"\n\n_cat/templates:\n{templates_raw or '(empty)'}"

    wazuh_entry = (template or {}).get("wazuh")
    if not wazuh_entry:
        return _offer_template_fix(
            response, context,
            reason="The 'wazuh' index template is not registered on the indexer at all - "
                   "Filebeat's wazuh-template.json was never applied (or a different template "
                   "is overriding it).",
        )

    patterns_ok = EXPECTED_INDEX_PATTERNS.issubset(set(wazuh_entry.get("index_patterns", [])))
    if not patterns_ok:
        return _offer_template_fix(
            response, context,
            reason=f"A 'wazuh' template exists, but its index_patterns are "
                   f"{wazuh_entry.get('index_patterns')} instead of the expected "
                   f"{sorted(EXPECTED_INDEX_PATTERNS)} - this is a stray/custom template "
                   "overriding the real one.",
        )

    response["display"] += (
        f"\n\n[OK] 'wazuh' template is registered with the expected index_patterns "
        f"{sorted(EXPECTED_INDEX_PATTERNS)}."
    )

    total_fields_limit = _dotted_get(wazuh_entry, "settings.index.mapping.total_fields.limit")
    if total_fields_limit and str(total_fields_limit) != "10000":
        response["display"] += (
            f"\n[WARNING] mapping.total_fields.limit is {total_fields_limit}, not the "
            "documented 10000 - this can also be a symptom of a modified/outdated template."
        )

    context["wazuh_template"] = wazuh_entry
    return _ask_field_name(response, context)


def _ask_field_name(response, context):
    response["display"] += (
        "\n\nWhich field does the error mention (e.g. manager.name, cluster.name, or the "
        "field named in the mapper_parsing_exception/illegal_argument_exception message)? "
        "Type its dotted path, or 'skip' if you don't have one."
    )
    response["ask"] = []
    context["stage"] = "field_name_wait"
    return response


def _check_field_type(response, context, field_name):
    field_name = (field_name or "").strip()
    if not field_name or field_name.lower() == "skip":
        return _no_specific_field(response, context)

    wazuh_entry = context.get("wazuh_template")
    if wazuh_entry is None:
        template, _ = indexer_api_get_json("/_template/wazuh")
        wazuh_entry = (template or {}).get("wazuh", {})

    dotted_path = f"mappings.properties.{field_name.replace('.', '.properties.')}.type"
    field_type = _dotted_get(wazuh_entry, dotted_path)

    response["display"] = f"Live template type for '{field_name}': {field_type or '(not found in the live template)'}"

    if field_type is None:
        return _offer_template_fix(
            response, context,
            reason=f"'{field_name}' isn't defined in the live 'wazuh' template at all - it's "
                   "likely relying on OpenSearch's dynamic mapping, which guessed a type that "
                   "doesn't match what's now being sent.",
        )

    response["display"] += (
        "\n\nIf the error says this field should be a different type (commonly 'keyword' or "
        "'object'), the live template needs to be corrected."
    )
    response["ask"] = ["Needs a different type - fix it", "This type is correct - something else is wrong"]
    context["stage"] = "field_type_decision"
    context["mapping_field"] = field_name
    return response


def _no_specific_field(response, context):
    ai_text = ai_explain(UNCLEAR_TEMPLATE_SYSTEM_PROMPT, context.get("cat_templates", "")[:4000])
    response["display"] += (
        f"\n\nNo specific field to check further - here's an AI read of what we've gathered "
        f"so far:\n{ai_text}\n\n"
        f"If this doesn't resolve it, please reach out to the official Wazuh community:\n{WAZUH_COMMUNITY_URL}"
    )
    response["done"] = True
    return response


def _offer_template_fix(response, context, reason):
    response["display"] += (
        f"\n\n[ROOT CAUSE FOUND] Field-mapping / index-template issue\n\n{reason}\n\n"
        "The fix is to reinstall the official Wazuh index template and push it via Filebeat. "
        "This only affects indices created AFTER the fix - already-affected indices need a "
        "separate reindex (offered next).\n\n"
        "Would you like us to reinstall the template automatically, or do it yourself?"
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "fix_template"
    return response


def _manual_template_fix_instructions():
    return (
        "1. Back up the current template:\n\n"
        "    cp /etc/filebeat/wazuh-template.json /etc/filebeat/wazuh-template.json.backup\n\n"
        "2. Remove any stray/incorrect template on the indexer (Dev Tools):\n\n"
        "    DELETE /_index_template/wazuh\n\n"
        "   (or DELETE /_template/wazuh if the cluster is still on the legacy templates API)\n\n"
        "3. Install the official template on the Wazuh Manager/Filebeat host:\n\n"
        f"    curl -so /etc/filebeat/wazuh-template.json {WAZUH_TEMPLATE_URL}\n"
        "    chmod go+r /etc/filebeat/wazuh-template.json\n\n"
        "4. Push it to the indexer and restart Filebeat:\n\n"
        "    filebeat setup --index-management\n"
        "    systemctl restart filebeat\n\n"
        "This only affects new indices going forward - existing ones need a reindex."
    )


def _auto_fix_template(response, context):
    log = []
    log.append(run_command("cp /etc/filebeat/wazuh-template.json /etc/filebeat/wazuh-template.json.backup") or "")
    log.append(indexer_api_delete("/_index_template/wazuh") or "")
    log.append(run_command(f"curl -so /etc/filebeat/wazuh-template.json {WAZUH_TEMPLATE_URL}") or "")
    log.append(run_command("chmod go+r /etc/filebeat/wazuh-template.json") or "")
    log.append(run_command("filebeat setup --index-management") or "")
    log.append(run_command("systemctl restart filebeat") or "")

    response["display"] += "\n\nReinstalled the official Wazuh index template:\n" + "\n".join(l for l in log if l)

    template, _ = indexer_api_get_json("/_template/wazuh")
    wazuh_entry = (template or {}).get("wazuh")
    if wazuh_entry and EXPECTED_INDEX_PATTERNS.issubset(set(wazuh_entry.get("index_patterns", []))):
        response["display"] += "\n[OK] Verified - the 'wazuh' template now has the expected index_patterns."
    else:
        response["display"] += "\n[WARNING] The 'wazuh' template still doesn't look right after reinstalling - manual investigation needed."

    return _offer_reindex(response, context)


def _offer_reindex(response, context):
    suggested = check_most_recent_index()
    hint = f" (most recent: {suggested['index']})" if suggested.get("index") else ""
    response["display"] += (
        f"\n\nThe template fix only applies to new indices - any index that already has the "
        f"field-mapping conflict needs to be reindexed (backup, delete, restore, delete "
        f"backup) to pick up the corrected mapping{hint}.\n\n"
        "Would you like to reindex an affected index now?"
    )
    response["ask"] = ["Yes, reindex one", "Skip"]
    context["stage"] = "reindex_method"
    return response


def _handle_reindex_method(response, context, choice):
    if "skip" in choice:
        response["display"] = "Skipping the reindex."
        response["done"] = True
        return response

    suggested = check_most_recent_index()
    hint = f" (e.g. {suggested['index']})" if suggested.get("index") else ""
    response["display"] = f"Which index would you like to reindex{hint}? Type the exact index name."
    response["ask"] = []
    context["stage"] = "reindex_index_wait"
    return response


def _confirm_reindex(response, context):
    index_name = context.get("mapping_index", "")
    response["display"] = (
        f"This will back up '{index_name}', delete the original, restore from the backup with "
        "the corrected mapping, then delete the backup. Proceed?"
    )
    response["ask"] = ["Yes, reindex", "Skip"]
    context["stage"] = "reindex_confirm"
    return response


def _auto_reindex_one(response, context):
    index_name = context.get("mapping_index", "")
    steps = reindex_for_mapping_conflict(index_name)
    aborted_after = steps.get("aborted_after")
    if aborted_after:
        detail = (steps.get(aborted_after) or "(no response)")[:200]
        response["display"] = (
            f"Stopped after '{aborted_after}' - nothing irreversible happened past that "
            f"point. {detail}"
        )
    else:
        response["display"] = f"Reindexed {index_name} - it should now use the corrected mapping."
    response["done"] = True
    return response
