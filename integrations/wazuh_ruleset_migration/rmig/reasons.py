"""Closed catalog of reason codes.

Each code has a fixed English text, the state it causes, whether it propagates
from a parent rule to its children, the fidelity it implies on an ``AUTO`` item,
and the anchor of its section in the documentation
(``<DOC_PAGE>#<code in lower case>``, the reason codes section of the README). Codes are never renamed; new ones
are added per stage.

States are ordered ``AUTO < DECISION < RECIPE``. ``NOT_APPLICABLE`` overrides
the others when the item's own codes cause it.
"""

AUTO = "AUTO"
DECISION = "DECISION"
RECIPE = "RECIPE"
NOT_APPLICABLE = "NOT_APPLICABLE"
STATES = (AUTO, DECISION, RECIPE, NOT_APPLICABLE)
STATE_RANK = {AUTO: 0, DECISION: 1, RECIPE: 2}

EXACT = "exact"
APPROXIMATE = "approximate"

# Each code is explained in the README of the tool, section "Reason codes" (anchor: the code in lower case).
DOC_PAGE = "README.md"


class Reason:
    __slots__ = ("code", "text", "state", "propagates", "fidelity")

    def __init__(self, code, state, propagates, text, fidelity=None):
        self.code = code
        self.state = state
        self.propagates = propagates
        self.text = text
        self.fidelity = fidelity

    @property
    def anchor(self):
        return "%s#%s" % (DOC_PAGE, self.code.lower())


_R = Reason
CATALOG = {r.code: r for r in [
    # --- rules ---
    _R("RM-R-FREQUENCY", RECIPE, True, "The rule counts events (frequency/timeframe). 5.x rules have no state: an Alerting monitor replaces it."),
    _R("RM-R-CORRELATION", RECIPE, True, "The rule correlates events (if_matched_*, different_*, global_frequency). 5.x rules have no state: no direct translation."),
    _R("RM-R-FTS", RECIPE, True, "The rule uses first-time-seen (if_fts), which keeps state in 4.x. No direct translation."),
    _R("RM-R-CHECK-DIFF", RECIPE, True, "The rule compares the event with the previous one stored on disk (check_diff). No direct translation."),
    _R("RM-R-TIME", RECIPE, True, "The rule depends on the time of day or the weekday (time, weekday). Not supported in 5.x rules."),
    _R("RM-R-COMPILED", RECIPE, True, "The rule calls C code (compiled_rule). No declarative translation."),
    _R("RM-R-IGNORE", AUTO, False, "The rule throttles or suppresses repeated alerts (ignore, check_if_ignored). 5.x has no equivalent: the migrated rule fires every time.", APPROXIMATE),
    _R("RM-R-OPTIONS", AUTO, False, "The rule sets alert options (options, maxsize) that 5.x rules do not have. They are listed as a note."),
    _R("RM-R-GROUPING-ONLY", NOT_APPLICABLE, False, "The rule only groups its children (level 0, no condition of its own). It is not emitted; its children carry its conditions."),
    _R("RM-R-SILENCER-STOCK", RECIPE, False, "Level 0 rule that silences stock rules. Stock content cannot be changed: the exclusion is written in the recipe."),
    _R("RM-R-OVERWRITE-STOCK", RECIPE, True, "The rule changes a stock rule (overwrite, or a modified copy of a stock file). Stock content cannot be changed in 5.x."),
    _R("RM-R-SHADOWING", AUTO, False, "In 4.x only one rule alerts per event; in 5.x every matching rule produces a finding. This rule can now fire together with a parent or a sibling.", APPROXIMATE),
    _R("RM-R-NO-SOURCE", RECIPE, True, "Nothing ties the rule to a log source (no decoded_as and no parent rule that has one). It cannot be assigned to an integration."),
    _R("RM-R-IF-LEVEL", RECIPE, True, "The rule hangs from every rule of a minimum level (if_level). No translation."),
    _R("RM-R-RE-DIALECT", AUTO, False, "A pattern uses a construct with no exact form in the detector's regex dialect.", APPROXIMATE),
    _R("RM-R-LONG-MESSAGE", AUTO, False, "Samples are longer than 4096 bytes: the message field is not indexed above that size.", APPROXIMATE),
    _R("RM-R-OFFLINE-ENGINE", AUTO, False, "verify --engine-socket: the events ran through a 5.x engine with no indexer and the tool's own Sigma reader gave the rule verdicts (verification-offline.md). A check before 5.0 is installed; the final proof is verify on the 5.0 indexer, and activate reads only that one."),
    _R("RM-R-NOT-CHECKED", AUTO, False, "verify --engine-socket gave no verdict for the rule: it uses a form the local Sigma reader does not cover (or one whose meaning differs between logtest and the detector), or its events need content this engine does not have (stock decoders without --catalog, IoC enrichment). The detail names it. Run verify on the 5.0 indexer for it."),
    _R("RM-R-PARENT-RECIPE", RECIPE, True, "A parent rule is RECIPE, so this rule cannot be translated on its own either."),
    _R("RM-R-DUPLICATE-ID", NOT_APPLICABLE, False, "Another rule with the same id was loaded first and this one has no overwrite: 4.x ignores it."),
    _R("RM-R-FILE-SHADOWED", NOT_APPLICABLE, False, "The file is not loaded by 4.x (rule_exclude matches its path or base name, or the rule_dir pattern does not match)."),
    _R("RM-R-PARENT-NOT-LOADED", NOT_APPLICABLE, True, "No parent named by if_sid, if_group or if_level is loaded before this rule: 4.x discards it."),
    _R("RM-R-TITLE-SUFFIXED", AUTO, False, "Two migrated rules share the description: the title gets the suffix ' (4.x rule <id>)'."),
    _R("RM-R-LABEL-UNAVAILABLE", RECIPE, True, "The condition needs a tag set by a decoder of the migration, but the events come from a stock integration."),
    _R("RM-R-STOCK-COPY", NOT_APPLICABLE, False, "The rule is identical to the stock rule with the same id: it is stock content, not custom."),
    _R("RM-R-OVERWRITE-MERGED", NOT_APPLICABLE, False, "The rule overwrites a custom rule loaded before it: its content is translated there."),
    _R("RM-R-SILENCER", AUTO, False, "Level 0 rule that stops other rules from alerting. It is not emitted: its condition becomes an exclusion on the rules it silenced in 4.x."),
    _R("RM-R-RE-UNSUPPORTED", RECIPE, True, "A pattern has no form in the detector's regex dialect nor in a decoder label (see the detail), or the dialect validator refused it. The rule is not emitted."),
    _R("RM-R-MULTI-SOURCE", RECIPE, True, "The chains of the rule reach more than one log source (integration); a 5.x rule belongs to one integration."),
    _R("RM-R-FEED", AUTO, False, "The rule belongs to a feed: its root rule takes its events by <location>, by <field> conditions, or by the stock JSON decoder, not by a custom decoder. A generated decoder selects the events of the feed (decisions.json, feeds) and the rule keeps the conditions of its root. In 4.x the first root rule that matched took the event; in 5.x the first feed decoder whose selector matches takes it. Feeds without JSON are tried after the migrated decoders; JSON feeds hang from the recreated 4.x JSON decoder, which is tried before them, as the stock JSON decoder loads before custom decoders in 4.x.", APPROXIMATE),
    _R("RM-R-FEED-LOCATION", AUTO, False, "The feed selects its events by wazuh.protocol.location, the 5.x field of the 4.x location. That 5.x fills it with the same value as 4.x for module and socket feeds (and without the agent prefix 4.x adds) is not proven.", APPROXIMATE),
    _R("RM-R-FEED-NO-SELECTOR", DECISION, True, "The feed has no condition that can select its events in a decoder (see the detail), and another feed already takes every JSON event. Write the selector (a decoder check) in decisions.json (feeds)."),
    # --- fields ---
    _R("RM-F-UNMAPPED", DECISION, True, "A field the rule or decoder uses has no WCS destination yet. Complete it in decisions.json (fields)."),
    _R("RM-F-DROPPED", RECIPE, True, "A field the rule depends on is marked drop in decisions.json."),
    _R("RM-F-TYPE", AUTO, False, "A value of the field does not convert to its WCS type: the field stays unmapped for that value.", APPROXIMATE),
    _R("RM-F-DECODER-CHECK", AUTO, False, "A condition on a field with no WCS destination runs in the generated decoder that extracts the field, with the 4.x matching (OS_Match, OS_Regex or PCRE2, letter case, negate), and sets a tag that the rule matches. The rule matches the same events. The value is not stored in the event: map the field in decisions.json (fields) to keep it."),
    _R("RM-F-NOT-STORED", AUTO, False, "The decoder extracts a field with no WCS destination yet: rules can still check it (RM-F-DECODER-CHECK), but its value is not stored in the event. Map it in decisions.json (fields) to keep it.", APPROXIMATE),
    _R("RM-F-JSON-PATH", RECIPE, True, "A JSON key the rule uses has characters that a 5.x field path cannot hold (see the detail): the feed decoder cannot read it."),
    # --- stock content ---
    _R("RM-S-NO-EQUIVALENT", DECISION, False, "The rule depends on stock 4.x content (a decoder, rule or group) with no entry in the equivalence table. Complete decisions.json (stock)."),
    _R("RM-S-INTEGRATION-DISABLED", AUTO, False, "The stock 5.x integration this content depends on ships disabled: enable it."),
    _R("RM-S-INVALID-ENTRY", DECISION, False, "The decisions.json or equivalence entry for the stock content cannot be used (see the detail): fix it in decisions.json (stock)."),
    _R("RM-S-UNKNOWN-INTEGRATION", AUTO, False, "decisions.json names a stock integration that the tool's snapshot of the 5.x catalog does not list: category 'other' is assumed. Check the name and the category.", APPROXIMATE),
    _R("RM-S-BROAD-SELECTION", AUTO, False, "The stock decoder is selected only by its 5.x integration: the rule can also match events of other programs of that integration.", APPROXIMATE),
    _R("RM-S-WIN-APPROXIMATE", AUTO, False, "A Windows condition uses an equivalent of the Windows pack that is not exact (see the detail: a value table or a field map entry with a known difference).", APPROXIMATE),
    _R("RM-S-WIN-FULL-LOG", RECIPE, False, "<match> or <regex> on a Windows event: 4.x reads the event as JSON, 5.x has the original XML in event.original. Key syntax, separators and escaping differ: rewrite the condition on the WCS fields."),
    _R("RM-S-WIN-CONDITION", DECISION, False, "A condition of the stock Windows chain has no 5.x field in the Windows pack. Complete decisions.json (stock)."),
    _R("RM-S-WIN-DISCARDED", RECIPE, False, "The 5.x Windows base decoder discards the events of this event id: the rule cannot fire in 5.x."),
    # --- decoders ---
    _R("RM-D-PLUGIN", RECIPE, True, "The decoder runs C code (plugin_decoder). No declarative translation."),
    _R("RM-D-FTS", RECIPE, True, "The decoder declares first-time-seen fields (fts), which keep state in 4.x."),
    _R("RM-D-ACCUMULATE", RECIPE, True, "The decoder merges fields across events (accumulate), which keeps state in 4.x."),
    _R("RM-D-JSON-CATCHALL", DECISION, True, "The decoder accepts any JSON event. Write the check that selects its events in decisions.json (integrations, json_check)."),
    _R("RM-D-REGEX-DIALECT", AUTO, False, "A decoder pattern uses a construct with no exact RE2 form.", APPROXIMATE),
    _R("RM-D-STOCK-PARENT", DECISION, True, "The parent decoder is stock and is not available to recreate in the base integration yet."),
    _R("RM-D-REGEX-UNSUPPORTED", RECIPE, True, "A decoder pattern uses a PCRE2 construct that RE2 does not have (see the detail)."),
    _R("RM-D-DUAL-DOCUMENT", AUTO, False, "Events this decoder accepts are indexed twice: once by the standard policy and once by the custom policy."),
    _R("RM-D-STOCK-COPY", NOT_APPLICABLE, False, "The decoder is identical to the stock decoder with the same name: it is stock content, not custom."),
    _R("RM-D-PARENT-NOT-LOADED", NOT_APPLICABLE, False, "The parent decoder is not loaded before this one: 4.x refuses it."),
    _R("RM-D-HELPER-UNAVAILABLE", RECIPE, True, "The translation calls an engine helper that the target engine (--engine-helpers) does not register, or has no form of it in that engine's names (see the detail). It is not emitted."),
    _R("RM-D-FILE-SHADOWED", NOT_APPLICABLE, False, "The file is not loaded by 4.x (decoder_exclude matches its path or base name, or the decoder_dir pattern does not match)."),
    _R("RM-D-SHADOWED-ROOT", AUTO, False, "The root decoder of this item never matches in 4.x: a root decoder loaded earlier (see the detail) accepts every event it accepts. In 4.x the decoder, its children and the rules that depend on it never applied. If the winner is custom, 5.x keeps the 4.x order and they do not apply there either; if it is stock, the custom policy does not have it and the migrated content can produce findings that 4.x never raised. Check that it is still wanted.", APPROXIMATE),
    _R("RM-D-SHADOWED-LIKELY", AUTO, False, "Possibly shadowed by a stock 4.x decoder, confirm: a stock root decoder loaded earlier (see the detail) may take the events of this item's root decoder (every distinctive literal of its prematch is in this one's prematch, in order). Not proven offline. If it does, in 4.x this decoder, its children and the rules under it never applied, and 5.x would raise findings 4.x never raised. Check with a sample event in 4.x logtest that it is still wanted.", APPROXIMATE),
    _R("RM-D-FEED-JSON", AUTO, False, "The feed decoder parses the event as JSON (as the 4.x JSON decoder) and reads each key by its path. 4.x joins nested keys with dots, compares every value as text (integers as %i, other numbers with 6 decimals, true, false, null, arrays as JSON text) and ignores the letter case of field names; 5.x keeps the JSON types, reads a dotted key as nested objects and compares names exactly. A rule root without decoded_as is assumed to read fields of the 4.x JSON decoder.", APPROXIMATE),
    # --- lists ---
    _R("RM-L-STOCK", NOT_APPLICABLE, False, "The list has the same content as a stock list: nothing to migrate."),
    _R("RM-L-PREFIX-KEYS", AUTO, False, "The list has network prefix keys (ending in '.'): they become ip_cidr_match lookups (IPv4 only).", APPROXIMATE),
    _R("RM-L-KEY-VALUE-INVERTED", RECIPE, True, "address_match_key_value has its condition inverted in 4.14 compared with match_key_value. Review it by hand."),
    _R("RM-L-IOC-FEED", AUTO, False, "decisions.json moves this IoC list to the 5.x IoC feeds: the lookup becomes a match on wazuh.threat.enrichments.indicator.type (the wazuh-ioc enrichment). Entries of the list that no feed has are lost, and an indicator found in any field of the event matches. Not live-verified.", APPROXIMATE),
    _R("RM-L-IOC-FEED-UNSUPPORTED", RECIPE, True, "decisions.json moves this list to the 5.x IoC feeds, but the lookup (negated, with a value check, or of a list with no feed type) has no form on the IoC enrichment. Keep the KVDB (action kvdb) or rewrite the rule by hand."),
    _R("RM-L-MISSING", NOT_APPLICABLE, True, "The list is not declared in <ruleset><list>, or its file is missing: 4.x discards the rule that uses it."),
    # --- policy ---
    _R("RM-P-ROOT-OWNED", RECIPE, False, "The policy already has a root decoder that the tool did not set and that does not do what the standard decoder/core-wazuh-message/0 does (see the detail): it is never changed. Migrate into a policy without a custom root decoder, or merge by hand."),
    _R("RM-P-SHARED-ROOT", AUTO, False, "The draft policy already has the standard root decoder decoder/core-wazuh-message/0: the tool's decoders hang from it and the policy is not changed. The predecoder gets a check built from its child decoders, each test moved onto event.original: it accepts every event they accept, and a few more, which then end in wazuh4-base instead of a later sibling. The tool's integrations go first in the draft policy, so the predecoder is tried before the standard decoders that hang from the same root (decoder/syslog/0 takes every syslog line).", APPROXIMATE),
    _R("RM-P-ROOT-CATCHALL", RECIPE, False, "The tool can share the draft policy's root decoder, but a migrated decoder under the predecoder has no test that can limit the predecoder to its logs (see the detail): under a shared root the predecoder would take every event before the user's decoders. Nothing was changed. Migrate into a policy without a root decoder, or give the 4.x decoder a program_name or prematch."),
    _R("RM-P-NAME-CONFLICT", RECIPE, False, "A resource with the same name exists in the space and is not owned by the tool."),
    _R("RM-P-FOREIGN-POLICY-CHANGE", RECIPE, False, "The draft policy has changes that the tool did not make."),
    _R("RM-P-POLICY-LOCKED", RECIPE, False, "The policy cannot be written (403)."),
    _R("RM-P-ENGINE-LIMIT", RECIPE, False, "The content exceeds a limit of the 5.x indexer (see the detail): raise the cluster setting or migrate in parts."),
    _R("RM-P-UNCLASSIFIED-INDEXED", RECIPE, False, "The custom policy indexes unclassified events: base events would be indexed."),
    _R("RM-P-UNSAFE-PATH", RECIPE, False, "A file of out/ would be written outside out/ (a name of the input that is not a plain file name). Nothing was written."),
    _R("RM-P-SECOND-POLICY", AUTO, False, "Generated decoders add a second active policy: every event of the manager also goes through it."),
    # --- general ---
    _R("RM-X-UNKNOWN-ELEMENT", RECIPE, True, "The element or attribute is unknown to 4.14 (analysisd would refuse the file). Review it by hand."),
    _R("RM-X-INVALID", RECIPE, True, "4.14 would reject this element (see the detail). Review it by hand."),
    _R("RM-X-LITERAL-SYNTAX", AUTO, False, "A 4.x OS_Regex or OS_Match pattern has regular expression syntax that 4.x reads as plain text: a class [...], .* or .+ after a literal, or a {n} count (see the detail). The translation keeps the 4.x meaning, so the pattern matches what it matched in 4.x, which is probably not what its author intended. Check it.", APPROXIMATE),
    _R("RM-X-PROVISIONAL-AUTO", AUTO, False, "No construct that blocks the translation was found. The item is AUTO until the translator confirms it."),
    _R("RM-X-TRANSLATED", AUTO, False, "Translated with no difference from 4.x that the tool knows of."),
]}


def get(code):
    return CATALOG[code]


def doc_anchor(code):
    return CATALOG[code].anchor


def state_of(codes):
    """State from a set of codes: NOT_APPLICABLE if any causes it, else the
    highest of AUTO < DECISION < RECIPE."""
    states = [CATALOG[c].state for c in codes]
    if NOT_APPLICABLE in states:
        return NOT_APPLICABLE
    best = AUTO
    for s in states:
        if STATE_RANK[s] > STATE_RANK[best]:
            best = s
    return best


def fidelity_of(codes):
    for c in codes:
        if CATALOG[c].fidelity == APPROXIMATE:
            return APPROXIMATE
    return EXACT
