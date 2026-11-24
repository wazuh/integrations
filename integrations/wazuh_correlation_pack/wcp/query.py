"""Compile the supported Sigma detection subset into OpenSearch query DSL.

Matching semantics follow the Wazuh 5.x indexer: WCS keyword fields are exact,
case-sensitive matches (the 5.x migration guide notes that string matching is
case-sensitive). ``|contains``/``|startswith``/``|endswith`` become ``wildcard``
queries on the keyword field; ``|cidr`` becomes a ``term`` on an ``ip`` field.
"""

from .sigma import SigmaError


def _escape_wildcard(value):
    return str(value).replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _value_query(field, mods, value):
    mods = set(mods) - {"all"}
    if not mods:
        if isinstance(value, bool):
            return {"term": {field: value}}
        return {"term": {field: value}}
    if mods == {"contains"}:
        return {"wildcard": {field: {"value": "*%s*" % _escape_wildcard(value)}}}
    if mods == {"startswith"}:
        return {"prefix": {field: {"value": str(value)}}}
    if mods == {"endswith"}:
        return {"wildcard": {field: {"value": "*%s" % _escape_wildcard(value)}}}
    if mods == {"cidr"}:
        return {"term": {field: str(value)}}
    raise SigmaError("modifier combination %s on %s is not supported" % ("|".join(sorted(mods)), field))


def _item_query(field, mods, values):
    if "exists" in mods:
        q = {"exists": {"field": field}}
        return q if values[0] else {"bool": {"must_not": [q]}}
    plain = not (set(mods) - {"all"})
    if plain and "all" not in mods and len(values) > 1 and not any(isinstance(v, bool) for v in values):
        return {"terms": {field: list(values)}}
    subs = [_value_query(field, mods, v) for v in values]
    if len(subs) == 1:
        return subs[0]
    if "all" in mods:
        return {"bool": {"filter": subs}}
    return {"bool": {"should": subs, "minimum_should_match": 1}}


def selection_query(alternatives):
    alts = []
    for alt in alternatives:
        items = [_item_query(f, m, v) for f, m, v in alt]
        alts.append(items[0] if len(items) == 1 else {"bool": {"filter": items}})
    if len(alts) == 1:
        return alts[0]
    return {"bool": {"should": alts, "minimum_should_match": 1}}


def condition_query(tree, selections):
    kind = tree[0]
    if kind == "sel":
        return selection_query(selections[tree[1]])
    if kind == "not":
        return {"bool": {"must_not": [condition_query(tree[1], selections)]}}
    subs = [condition_query(t, selections) for t in tree[1]]
    if kind == "and":
        return {"bool": {"filter": subs}}
    return {"bool": {"should": subs, "minimum_should_match": 1}}


def rule_query(rule):
    return condition_query(rule.condition, rule.selections)


def correlation_selection(corr):
    """Query matching events of any of the correlation's base rules."""
    subs = [rule_query(r) for r in corr.rules]
    if len(subs) == 1:
        return subs[0]
    return {"bool": {"should": subs, "minimum_should_match": 1}}
