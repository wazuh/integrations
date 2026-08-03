"""
Regression tests for three decoder-generation defects:

1. /health reported wazuh-logtest as accessible while wazuh-analysisd was down,
   because the local probe only stat'd the binary.
2. The colon key=value scan invented fields (`14`, `accesslog`, `2026-08-01T14`,
   `https`) out of timestamps, syslog tags and URLs.
3. Split child decoders were emitted with an empty <parent> line and no parent
   decoder at all, so nothing could ever match.
"""
import re
import sys
import time
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "app"))

import app.main as main
from app.main import (
    _ensure_parent_decoder,
    _enforce_split_decoders,
    _is_noise_field_key,
    _logtest_output_indicates_down,
    _refresh_wazuh_accessible,
    extract_relevant_fields,
)


ACCESS_LOG = (
    '2026-08-01T14:22:31 myapp accesslog: client=203.0.113.45 '
    'ts=2026-08-01T14:22:31Z method=GET path=/api/v1/users status=200 '
    'referer="https://example.com/home" rt=0.042'
)


# ── 1. logtest accessibility probe ────────────────────────────────────────────

def test_logtest_output_indicates_down_detects_analysisd_error():
    """The real-world failure string must be recognised as 'manager down'."""
    assert _logtest_output_indicates_down(
        "", "** Wazuh-logtest error when connecting with wazuh-analysisd"
    )


def test_logtest_output_indicates_down_is_case_insensitive():
    assert _logtest_output_indicates_down(
        "ERROR WHEN CONNECTING WITH WAZUH-ANALYSISD", ""
    )


def test_logtest_output_healthy_output_is_not_down():
    assert not _logtest_output_indicates_down(
        "**Phase 1: Completed pre-decoding.\n\tfull event: 'test'", ""
    )


def test_refresh_marks_inaccessible_when_analysisd_is_down(monkeypatch):
    """Regression: exit code 0 + analysisd error on stderr must read as DOWN.

    wazuh-logtest exits 0 even when the manager is stopped, so a probe that
    trusts the return code alone reports a dead manager as healthy."""
    monkeypatch.setattr(main, "WAZUH_REMOTE_ENABLED", False)
    monkeypatch.setattr(main, "find_wazuh_logtest", lambda: "/var/ossec/bin/wazuh-logtest")
    monkeypatch.setattr(
        main,
        "run_local_sudo_command",
        lambda *a, **k: {
            "returncode": 0,
            "stdout": "",
            "stderr": "** Wazuh-logtest error when connecting with wazuh-analysisd",
            "connection_error": False,
        },
    )
    # _refresh_wazuh_accessible retries 3x with 2s backoff; skip the wait.
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    main._WAZUH_LOGTEST_ACCESSIBLE = None
    _refresh_wazuh_accessible()
    assert main._WAZUH_LOGTEST_ACCESSIBLE is False


def test_refresh_marks_accessible_when_logtest_round_trips(monkeypatch):
    monkeypatch.setattr(main, "WAZUH_REMOTE_ENABLED", False)
    monkeypatch.setattr(main, "find_wazuh_logtest", lambda: "/var/ossec/bin/wazuh-logtest")
    monkeypatch.setattr(
        main,
        "run_local_sudo_command",
        lambda *a, **k: {
            "returncode": 0,
            "stdout": "**Phase 1: Completed pre-decoding.",
            "stderr": "",
            "connection_error": False,
        },
    )

    main._WAZUH_LOGTEST_ACCESSIBLE = None
    _refresh_wazuh_accessible()
    assert main._WAZUH_LOGTEST_ACCESSIBLE is True


def test_refresh_marks_inaccessible_when_binary_missing(monkeypatch):
    monkeypatch.setattr(main, "find_wazuh_logtest", lambda: None)
    main._WAZUH_LOGTEST_ACCESSIBLE = None
    _refresh_wazuh_accessible()
    assert main._WAZUH_LOGTEST_ACCESSIBLE is False


# ── 2. noise fields from the colon scan ───────────────────────────────────────

@pytest.mark.parametrize(
    "key",
    ["14", "22", "2026-08-01T14", "https", "http", "0800", "2026-08-01"],
)
def test_noise_field_keys_are_rejected(key):
    assert _is_noise_field_key(key)


@pytest.mark.parametrize("key", ["client", "method", "status", "src_ip", "user-agent"])
def test_real_field_keys_are_kept(key):
    assert not _is_noise_field_key(key)


def test_access_log_extracts_only_real_fields():
    """Regression: the reported bug produced decoders for `14`, `accesslog`
    and `2026-08-01T14` alongside the genuine key=value fields."""
    fields = extract_relevant_fields(ACCESS_LOG)
    visible = {k for k in fields if not k.startswith(("_kv_", "_cef_"))}

    assert {"client", "method", "status", "path", "rt"} <= visible
    for junk in ("14", "accesslog", "2026-08-01T14", "https", "2026-08-01T14:22:31Z"):
        assert junk not in visible, f"noise field {junk!r} leaked into extraction"


def test_space_separated_clock_does_not_become_a_field():
    fields = extract_relevant_fields(
        "2026-08-01 14:22:31 myapp accesslog: client=10.0.0.5 status=200"
    )
    visible = {k for k in fields if not k.startswith(("_kv_", "_cef_"))}
    assert "14" not in visible
    assert "accesslog" not in visible
    assert fields.get("client") == "10.0.0.5"
    assert fields.get("status") == "200"


def test_pipe_delimited_values_stop_at_the_delimiter():
    """Regression: the first key swallowed the whole line, because `|` did not
    terminate a value — so proto/sport/dport were never extracted at all."""
    fields = extract_relevant_fields(
        "LOGV3|f:ts=2026-08-01T14:35:00Z|f:host=edge-11|d:proto=tcp|"
        "d:sport=51344|d:dport=445|m:bytes=0"
    )
    assert fields.get("ts") == "2026-08-01T14:35:00Z"
    assert fields.get("host") == "edge-11"
    assert fields.get("proto") == "tcp"
    assert fields.get("sport") == "51344"
    assert fields.get("dport") == "445"


def test_quoted_value_containing_spaces_survives():
    fields = extract_relevant_fields('evt=LOGIN_FAIL reason="bad_credentials attempts=5"')
    assert fields.get("evt") == "LOGIN_FAIL"
    assert fields.get("reason") == "bad_credentials attempts=5"


def test_colon_scan_still_runs_when_no_equals_pairs_exist():
    """Colon-delimited logs must keep working — the scan is gated, not removed."""
    fields = extract_relevant_fields("srcuser: alice action: login")
    assert fields.get("srcuser") == "alice"
    assert fields.get("action") == "login"


# ── 3. parent decoder synthesis ───────────────────────────────────────────────

PAIRS = [
    (r"\.+ client=(\S+)", ["srcip"]),
    (r"\.+ method=(\S+)", ["method"]),
    (r"\.+ status=(\S+)", ["status"]),
]


def blank_line_inside_a_block(xml):
    """Blank lines *between* decoder blocks are formatting; a blank line
    *inside* one is the empty-<parent> defect."""
    for block in re.findall(r"<decoder\b[^>]*>.*?</decoder>", xml, re.DOTALL):
        if any(line.strip() == "" for line in block.splitlines()):
            return True
    return False


def test_split_children_never_emit_an_empty_parent_line():
    """Regression: parent_tag was '' but its line was printed anyway, giving
    `<decoder ...>\\n  \\n  <regex>` — the blank line in the reported output."""
    combined = (
        '<decoder name="myapp-accesslog">\n'
        '  <regex>\\.+ client=(\\S+) method=(\\S+) status=(\\S+)</regex>\n'
        '  <order>srcip,method,status</order>\n'
        '</decoder>'
    )
    out = _enforce_split_decoders(combined, PAIRS, parent_name_hint="myapp")

    assert not blank_line_inside_a_block(out), "empty line where <parent> belongs"
    assert out.count("<parent>myapp</parent>") == 3


def test_split_children_inherit_an_existing_parent_block():
    xml = (
        '<decoder name="myapp">\n  <prematch>myapp</prematch>\n</decoder>\n\n'
        '<decoder name="myapp-accesslog">\n'
        '  <regex>\\.+ client=(\\S+) method=(\\S+) status=(\\S+)</regex>\n'
        '  <order>srcip,method,status</order>\n'
        '</decoder>'
    )
    out = _enforce_split_decoders(xml, PAIRS)
    assert out.count("<parent>myapp</parent>") == 3


def test_split_child_does_not_become_its_own_parent():
    """Self-parenting would be accepted by the XML but is a cycle."""
    combined = (
        '<decoder name="myapp-accesslog">\n'
        '  <regex>\\.+ client=(\\S+) method=(\\S+) status=(\\S+)</regex>\n'
        '  <order>srcip,method,status</order>\n'
        '</decoder>'
    )
    out = _enforce_split_decoders(
        combined, PAIRS, parent_name_hint="myapp-accesslog"
    )
    assert "<parent>myapp-accesslog</parent>" not in out


def test_ensure_parent_decoder_synthesizes_missing_parent():
    """Regression: children referenced a parent that nothing defined, so the
    whole decoder set could never match."""
    children = (
        '<decoder name="myapp-accesslog">\n'
        '  <parent>myapp</parent>\n'
        '  <regex>\\.+ client=(\\S+)</regex>\n'
        '  <order>srcip</order>\n'
        '</decoder>'
    )
    out = _ensure_parent_decoder(children, {"program_name": "myapp", "prematch": "myapp"})

    assert '<decoder name="myapp">' in out
    assert "<program_name>myapp</program_name>" in out
    # The parent must come first — Wazuh reads decoders in file order.
    assert out.index('<decoder name="myapp">') < out.index("myapp-accesslog")


def test_ensure_parent_decoder_falls_back_to_prematch():
    children = (
        '<decoder name="myapp-accesslog">\n'
        '  <parent>myapp</parent>\n'
        '  <regex>\\.+ client=(\\S+)</regex>\n'
        '  <order>srcip</order>\n'
        '</decoder>'
    )
    out = _ensure_parent_decoder(children, {"program_name": None, "prematch": "myapp accesslog:"})
    assert "<prematch>myapp accesslog:</prematch>" in out


def test_ensure_parent_decoder_is_a_noop_when_parent_exists():
    xml = (
        '<decoder name="myapp">\n  <prematch>myapp</prematch>\n</decoder>\n\n'
        '<decoder name="myapp-accesslog">\n'
        '  <parent>myapp</parent>\n'
        '  <regex>\\.+ client=(\\S+)</regex>\n'
        '  <order>srcip</order>\n'
        '</decoder>'
    )
    assert _ensure_parent_decoder(xml, {"program_name": "myapp"}) == xml


def test_ensure_parent_decoder_handles_empty_input():
    assert _ensure_parent_decoder("", {}) == ""
    assert _ensure_parent_decoder("no xml here", {}) == "no xml here"


# ── 4. normalizing what the model actually emits ──────────────────────────────

def test_parent_attribute_is_rewritten_as_an_element():
    """Wazuh ignores parent="x" as an attribute, orphaning the child."""
    xml = (
        '<decoder name="client-ip" parent="myapp-accesslog">\n'
        '  <regex>\\.+ client=(\\S+)</regex>\n'
        '  <order>srcip</order>\n'
        '</decoder>'
    )
    out = main._normalize_parent_attribute(xml)
    assert 'parent="myapp-accesslog"' not in out
    assert "<parent>myapp-accesslog</parent>" in out
    assert '<decoder name="client-ip">' in out


def test_parent_attribute_normalization_leaves_clean_xml_alone():
    xml = (
        '<decoder name="child">\n  <parent>p</parent>\n'
        '  <regex>x</regex>\n  <order>f</order>\n</decoder>'
    )
    assert main._normalize_parent_attribute(xml) == xml


def test_verified_prematch_replaces_the_models_paraphrase():
    """The model drops a leading \\p and the prematch stops matching; the
    analysis prematch was checked against the sample, so it wins."""
    xml = (
        '<decoder name="myapp-accesslog">\n'
        '  <prematch>^\\d+\\pAug\\s+\\d+</prematch>\n'
        '</decoder>'
    )
    out = main._inject_parent_prematch(xml, r"^\p\d+\pAug\s+appgw\d+")
    assert r"<prematch>^\p\d+\pAug\s+appgw\d+</prematch>" in out


def test_prematch_is_inserted_when_the_model_omitted_it():
    """Regression: an empty parent decoder selects nothing. The model left the
    block bare and the injector only replaced existing prematches."""
    xml = '<decoder name="appauth">\n</decoder>'
    out = main._inject_parent_prematch(xml, r"^H\psev\p\d+")
    assert r"<prematch>^H\psev\p\d+</prematch>" in out


def test_prematch_is_not_added_to_a_program_name_parent():
    """<program_name> is the right form when Wazuh pre-decoded one."""
    xml = '<decoder name="p">\n  <program_name>^accesslog$</program_name>\n</decoder>'
    assert main._inject_parent_prematch(xml, "SOMETHING") == xml


def test_prematch_injection_does_not_touch_children():
    xml = (
        '<decoder name="p">\n  <prematch>PARENT</prematch>\n</decoder>\n\n'
        '<decoder name="c">\n  <parent>p</parent>\n'
        '  <prematch>CHILD</prematch>\n'
        '  <regex>x</regex>\n  <order>f</order>\n</decoder>'
    )
    out = main._inject_parent_prematch(xml, "NEW")
    assert "<prematch>NEW</prematch>" in out
    assert "<prematch>CHILD</prematch>" in out, "child prematch must be left alone"


def test_renamed_order_field_still_gets_the_correct_regex():
    """Asking for `client` and getting `<order>srcip</order>` used to leave the
    model's bare (\\S+) in place, matching the wrong token."""
    xml = (
        '<decoder name="c1">\n  <parent>p</parent>\n'
        '  <regex>\\S+</regex>\n  <order>srcip</order>\n</decoder>'
    )
    pairs = [(r"\.+ client=(\d+.\d+.\d+.\d+)", ["client"])]
    out = main._inject_correct_regex(xml, pairs)
    assert r"<regex>\.+ client=(\d+.\d+.\d+.\d+)</regex>" in out
    assert "<order>client</order>" in out


def test_positional_fallback_is_skipped_when_counts_disagree():
    """Mismatched counts mean we cannot trust position — leave it alone."""
    xml = (
        '<decoder name="c1">\n  <parent>p</parent>\n'
        '  <regex>\\S+</regex>\n  <order>srcip</order>\n</decoder>'
    )
    pairs = [(r"\.+ a=(\S+)", ["a"]), (r"\.+ b=(\S+)", ["b"])]
    out = main._inject_correct_regex(xml, pairs)
    assert "<order>srcip</order>" in out


def test_broken_model_output_becomes_a_working_decoder_set():
    """The exact shape the tool produced for the reported access log:
    parent= attribute, paraphrased prematch, renamed field with a bare regex."""
    ai_response = (
        '<decoder name="myapp-accesslog">\n'
        '  <prematch>^\\d+\\pAug\\s+\\d+</prematch>\n'
        '</decoder>\n\n'
        '<decoder name="client-ip" parent="myapp-accesslog">\n'
        '  <regex>\\S+</regex>\n  <order>srcip</order>\n</decoder>\n\n'
        '<decoder name="method" parent="myapp-accesslog">\n'
        '  <regex>\\.+ method=(\\S+)</regex>\n  <order>method</order>\n</decoder>'
    )
    verified = r"^\p\d+\pAug\s+appgw\d+\s+accesslog\p"
    pairs = [(r"\.+ client=(\d+.\d+.\d+.\d+)", ["client"]), (r"\.+ method=(\S+)", ["method"])]

    out, _ = main._extract_xml_from_ai_response(
        ai_response,
        regex_order_pairs=pairs,
        analysis={"app_name": "myapp", "prematch": verified, "program_name": None},
    )

    assert 'parent="myapp-accesslog"' not in out
    assert out.count("<parent>myapp-accesslog</parent>") == 2
    assert f"<prematch>{verified}</prematch>" in out
    assert "<order>client</order>" in out
    assert "<regex>\\S+</regex>" not in out


def test_full_path_produces_a_matchable_decoder_set():
    """End-to-end: a combined, parentless AI response must come out as a parent
    plus one child per field, each child pointing at that parent."""
    ai_response = (
        "```xml\n"
        '<decoder name="myapp-accesslog">\n'
        '  <regex>\\.+ client=(\\S+) method=(\\S+) status=(\\S+)</regex>\n'
        '  <order>srcip,method,status</order>\n'
        '</decoder>\n'
        "```"
    )
    decoder_xml, _ = main._extract_xml_from_ai_response(
        ai_response,
        regex_order_pairs=PAIRS,
        analysis={"app_name": "myapp", "program_name": "myapp", "prematch": "myapp"},
    )

    assert '<decoder name="myapp">' in decoder_xml
    assert decoder_xml.count("<parent>myapp</parent>") == 3
    assert decoder_xml.count("<order>") == 3
    assert not blank_line_inside_a_block(decoder_xml)


# ── a log Wazuh already decodes must not get a redundant custom decoder ──────
#
# The AI endpoint computed `needs_custom_decoder` and then ignored it, so a log
# the stock ruleset already handles (json, sshd, fortigate, ...) still got a
# generated decoder. That decoder can never fire — the built-in wins Phase 2 —
# yet validation reported success because it only checked that *some* decoder
# matched. Emit a rule keyed to the built-in with <decoded_as> instead.

def _builtin_analysis(needs_custom_rule):
    return {
        "app_name": "jsonapi",
        "needs_custom_decoder": False,
        "needs_custom_rule": needs_custom_rule,
        "wazuh_logtest_summary": {"decoder_name": "json", "rule_id": 1002},
    }


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def _body(response):
    import json

    return json.loads(bytes(response.body).decode())


def test_builtin_decoded_log_with_no_rule_requirement_generates_nothing():
    request = main.AIGenerateRequest(
        app_name="jsonapi",
        logs=[main.LogSample(raw_log='{"level":"ERROR","service":"payments-api"}')],
    )
    body = _body(_run(main._rule_only_for_builtin_decoder(
        request, _builtin_analysis(needs_custom_rule=False), "json"
    )))

    assert body["decoder_xml"] == "", "no decoder should be generated"
    assert body["rule_xml"] == ""
    assert body["decoder_skipped"] is True
    assert body["builtin_decoder"] == "json"
    assert body["builtin_rule_id"] == 1002
    assert body["working"] is True
    assert body["attempts"] == 0
    assert "json" in body["validation"]["reason"]


def test_generated_rule_ids_reads_every_rule():
    assert main._generated_rule_ids(
        '<rule id="100900" level="7"></rule>\n<rule id="100901" level="3"></rule>'
    ) == [100900, 100901]
    assert main._generated_rule_ids("") == []


def test_rule_only_validation_requires_a_rule_id_to_check():
    """Without an id there is nothing to assert fired, so it must not pass."""
    result = main._validate_ai_rule_with_logtest(
        "<rule level=\"7\"><decoded_as>json</decoded_as></rule>",
        [main.LogSample(raw_log='{"level":"ERROR"}')],
        "jsonapi",
        "json",
    )
    assert result["validated"] is False
    assert "no <rule id" in result["reason"]


def test_rule_only_validation_rejects_empty_and_malformed_xml():
    logs = [main.LogSample(raw_log='{"level":"ERROR"}')]
    assert main._validate_ai_rule_with_logtest("", logs, "jsonapi", "json")["validated"] is False
    bad = main._validate_ai_rule_with_logtest(
        '<rule id="100900"><decoded_as>json</decoded_as>', logs, "jsonapi", "json"
    )
    assert bad["validated"] is False
    assert "rule XML" in bad["reason"]


# ── a decoded field named `id` must not be read back as the rule id ──────────
#
# Phase 2 prints decoded fields and Phase 3 prints rule properties using the
# same names (`id`, `level`, `description`). `id` is one of Wazuh's documented
# static field names, so an Aruba/firewall decoder extracting an event code put
# `id: '501094'` in Phase 2 — and the unscoped search read that as the rule id,
# reporting 501094 where rule 100912 had actually fired.

LOGTEST_WITH_DECODED_ID = """**Phase 1: Completed pre-decoding.
\ttimestamp: 'Jul 20 16:42:55'
\thostname: '2026'

**Phase 2: Completed decoding.
\tname: 'arubactl'
\tid: '501094'
\tsrcip: '10.7.2.19'
\tstatus: 'Client Match'

**Phase 3: Completed filtering (rules).
\tid: '100912'
\tlevel: '7'
\tdescription: 'Aruba: client association auth failure'
"""


def test_decoded_id_field_is_not_mistaken_for_the_rule_id():
    parsed = main.parse_logtest_output(LOGTEST_WITH_DECODED_ID)

    assert parsed["rule_id"] == 100912, "rule id must come from Phase 3"
    assert parsed["rule_level"] == 7
    assert parsed["rule_description"] == "Aruba: client association auth failure"
    assert parsed["decoded_fields"]["id"] == "501094", "the decoded field keeps its own value"
    assert parsed["decoder_name"] == "arubactl"
    assert parsed["no_rule_match"] is False


def test_no_rule_match_is_true_when_only_a_decoded_id_is_present():
    """A Phase 2 `id:` must not make a ruleless event look like a rule fired."""
    stdout = LOGTEST_WITH_DECODED_ID.split("**Phase 3")[0] + (
        "**Phase 3: Completed filtering (rules).\n\tNo rule matched.\n"
    )
    parsed = main.parse_logtest_output(stdout)

    assert parsed["rule_id"] is None
    assert parsed["no_rule_match"] is True
    assert parsed["decoded_fields"]["id"] == "501094"
