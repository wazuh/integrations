"""
Regression tests for parent-decoder <prematch> derivation.

The reported failure was a parent decoder of `^\\d+\\S+ \\S+`, which matches
nothing in the sample it was generated from. A prematch must:

  * cover the log's stable header up to its first distinctive token,
  * keep vendor/product tags (LOGV3, APPAUTH) literal while generalizing
    instance digits (appgw03 -> appgw\\d+, years, clocks),
  * be matched against what Phase 2 actually sees, not the raw log.
"""
import sys
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "app"))

from app.main import (
    derive_parent_prematch,
    osregex_matches,
    osregex_to_python,
    postpredecode_remainder,
)


SYSLOG_ACCESSLOG = (
    '<134>Aug  1 14:49:10 appgw03 accesslog: ts=2026-08-01T14:49:10Z '
    'client=10.9.8.7 method=GET path=/ status=active bytes=3267 '
    'referer="-" ua="" upstream=- rt=0.002'
)
PIPE_APPAUTH = (
    '2026-08-01T14:23:11.842Z|APPAUTH|sev=4|node=auth-svc-07|txn:9f3a-22b1-4c8d|'
    'evt=LOGIN_FAIL|actor{id=u8821;role=admin;mfa=false}|'
    'src<ip=203.0.113.45;geo=RU;asn=AS12345>|reason="bad_credentials attempts=5"|'
    'latency_ms=142'
)
LOGV3 = (
    'LOGV3|f:ts=2026-08-01T14:35:00Z|f:host=edge-11|f:evt=fw.block|d:proto=tcp|'
    'd:sport=51344|d:dport=445|m:bytes=0|m:pkts=1|x:rule=EMERGING-2001|x:class=exploit'
)


# ── OS_Regex → Python translation (used to verify generated prematches) ───────

def test_osregex_backslash_dot_is_any_char_not_a_literal_dot():
    """OS_Regex inverts PCRE: \\. is any-char, a bare . is a literal dot."""
    assert osregex_matches(r"a\.+b", "axxb")
    assert osregex_matches(r"a.b", "a.b")
    assert not osregex_matches(r"a.b", "axb")


def test_osregex_classes():
    assert osregex_matches(r"\d+", "2026")
    assert osregex_matches(r"\s+", "a b")
    assert osregex_matches(r"\p", "|")
    assert osregex_matches(r"\p", ":")
    assert not osregex_matches(r"\p", "a")


@pytest.mark.parametrize("char", list("~@^_/\\`"))
def test_osregex_punct_class_excludes_what_wazuh_excludes(char):
    """Verified against wazuh-logtest 4.14: these are NOT in \\p, however much
    they look like punctuation. Treating them as \\p let osregex_matches()
    approve prematches that real Wazuh never fires."""
    assert not osregex_matches(r"\p", char)


@pytest.mark.parametrize("char", list("()*+,-.:;<=>?[]!\"'#$%&|{}"))
def test_osregex_punct_class_covers_what_wazuh_covers(char):
    assert osregex_matches(r"\p", char)


def test_tilde_delimited_header_keeps_the_tilde_literal():
    """`~PAYGW~` generalized to `\\p...\\p` verified clean and matched nothing in
    production, because `~` is outside Wazuh's \\p. Keep it literal instead —
    it is a fixed delimiter of the format, not per-event data."""
    prematch = derive_parent_prematch(EPOCH_PAYGW)
    assert "~PAYGW~" in prematch
    assert osregex_matches(prematch, EPOCH_PAYGW)


def test_tilde_marker_and_slash_date_stay_literal():
    log = (
        "~AUDIT~ 2026/08/01-14:36:14 usr=jane.doe@corp ~ obj=doc:finance/q3.xlsx ~ "
        "action=PERMISSION_CHANGE ~ grantor=admin.bob"
    )
    prematch = derive_parent_prematch(log)
    assert prematch.startswith("^~AUDIT~"), prematch
    assert "/" in prematch, "the date separator is outside \\p, so it stays literal"
    assert osregex_matches(prematch, log)
    # A different day must still match — only the delimiters are literal.
    assert osregex_matches(
        prematch,
        "~AUDIT~ 2026/12/25-23:44:18 usr=omar.said@corp ~ obj=doc:legal/nda.docx ~ "
        "action=PERMISSION_CHANGE ~ grantor=admin.kim",
    )


def test_osregex_anchor_is_honoured():
    assert osregex_matches(r"^LOGV3", "LOGV3|f:ts=1")
    assert not osregex_matches(r"^LOGV3", "x|LOGV3")


def test_osregex_to_python_survives_bad_input():
    assert osregex_matches("", "anything") is False
    assert osregex_to_python(r"\d+") == r"\d+"


# ── derivation per log shape ──────────────────────────────────────────────────

@pytest.mark.parametrize("log", [SYSLOG_ACCESSLOG, PIPE_APPAUTH, LOGV3])
def test_derived_prematch_always_matches_its_own_log(log):
    """The defect in one sentence: the shipped prematch did not match."""
    prematch = derive_parent_prematch(log)
    assert prematch, "no prematch derived"
    assert osregex_matches(prematch, log), f"{prematch!r} does not match its own sample"


def test_syslog_prematch_covers_header_through_program_tag():
    """`<134>Aug  1 14:49:10 appgw03 accesslog:` — up to the program marker."""
    prematch = derive_parent_prematch(SYSLOG_ACCESSLOG)
    assert prematch.startswith("^")
    assert "appgw" in prematch
    assert "accesslog" in prematch
    # The message body must stay out of the prematch.
    for body_token in ("client", "method", "10.9.8.7", "GET"):
        assert body_token not in prematch


def test_syslog_prematch_generalizes_the_host_instance_number():
    """appgw03 -> appgw\\d+, so appgw01/appgw02 match the same parent."""
    prematch = derive_parent_prematch(SYSLOG_ACCESSLOG)
    assert "appgw03" not in prematch
    assert r"appgw\d+" in prematch
    sibling = SYSLOG_ACCESSLOG.replace("appgw03", "appgw07")
    assert osregex_matches(prematch, sibling)


def test_pipe_format_prematch_keeps_the_product_tag_literal():
    """APPAUTH identifies the format — generalizing it away loses the anchor."""
    prematch = derive_parent_prematch(PIPE_APPAUTH)
    assert "APPAUTH" in prematch
    assert "sev" not in prematch, "prematch ran past the product tag into the body"


def test_logv3_prematch_keeps_digits_inside_the_product_tag():
    """LOGV3 is a name, not LOGV followed by a version — \\d+ would break it."""
    prematch = derive_parent_prematch(LOGV3)
    assert "LOGV3" in prematch
    assert r"LOGV\d+" not in prematch


def test_logv3_prematch_covers_tag_plus_first_field():
    """`LOGV3|f:ts=<timestamp>` — the tag alone is thin, the body is overfit."""
    prematch = derive_parent_prematch(LOGV3)
    assert "ts" in prematch
    assert "host" not in prematch, "prematch ran into the second field"
    # Same format, different timestamp and host must still match.
    other = LOGV3.replace("2026-08-01T14:35:00Z", "2027-01-09T02:00:11Z").replace(
        "edge-11", "edge-42"
    )
    assert osregex_matches(prematch, other)


def test_syslog_month_name_is_generalized():
    """A literal `Aug` pins the parent decoder to August."""
    prematch = derive_parent_prematch(SYSLOG_ACCESSLOG)
    assert "Aug" not in prematch
    december = SYSLOG_ACCESSLOG.replace("Aug  1", "Dec 25")
    assert osregex_matches(prematch, december)


def test_prematch_is_not_overfit_to_one_events_values():
    """A different event of the same family must match the same parent."""
    prematch = derive_parent_prematch(SYSLOG_ACCESSLOG)
    other_event = (
        '<134>Aug  3 09:01:55 appgw01 accesslog: ts=2026-08-03T09:01:55Z '
        'client=198.51.100.2 method=POST path=/login status=denied'
    )
    assert osregex_matches(prematch, other_event)


# ── the pre-decoding trap ─────────────────────────────────────────────────────

def test_prematch_targets_the_post_predecode_remainder():
    """Wazuh consumes `2026-08-01T14:23:11.842Z|APPAUT` as the timestamp on this
    format, cutting mid-tag. Phase 2 sees only what follows, so a prematch built
    from the raw log can never fire."""
    consumed = "2026-08-01T14:23:11.842Z|APPAUT"
    remainder = postpredecode_remainder(PIPE_APPAUTH, consumed, None)
    assert remainder.startswith("H|sev=4")

    from_raw = derive_parent_prematch(PIPE_APPAUTH)
    assert not osregex_matches(from_raw, remainder), (
        "a raw-log prematch appeared to match the remainder; the trap is gone "
        "or the test sample changed"
    )

    from_remainder = derive_parent_prematch(remainder)
    assert osregex_matches(from_remainder, remainder)


# ── the prematch must not pin one event's field values ───────────────────────

EDR_PIPE = (
    'MSG#88213|type=EDR.ALERT|ts=1754056751|host=WKSTN12|proc=cmd.exe|'
    'cmdline_b64=Y21kLmV4ZSAvYyBwb3dlcnNoZWxs|pid=6624|ppid=4102|'
    'hash_sha256=hex:ABCDEF0123456789|verdict=SUSPICIOUS|score=88|'
    'mitre=[T1059.001,T1027]'
)
BRACKET_BODY = (
    '<2026.08.01 14:30> {SVC:orders-api} [REQ id=req-8821 method=POST '
    'route=/v2/checkout] [USR uid=88213 tier=gold] [RESP code=500 '
    'err="deadlock detected: txn 991 vs 882"]'
)
# Both open with `[`, which used to zero out the header zone.
EPOCH_PAYGW = (
    '[1754056222831] ~PAYGW~ >> merchant=MID99213 | card=****4821 | '
    'amt=15000.50:USD | mcc=5411 | result=DECLINE(51) | risk_score=0.87 | '
    'rules_fired=[VELOCITY,GEO_MISMATCH] | proc_ns=8823410'
)
APACHE_ERROR = (
    '[Mon Aug 03 09:22:31.113456 2026] [authz_core:error] [pid 2211:tid 140234] '
    '[client 203.0.113.77:52233] AH01630: client denied by server configuration: '
    '/var/www/html/admin'
)


def test_prematch_stops_at_the_key_and_never_takes_the_value():
    """`type=EDR.ALERT` in the prematch matches ALERT events and nothing else.

    The shipped derivation emitted `^MSG\\p\\d+\\ptype\\pEDR.ALERT`, so an
    EDR.INFO line from the very same source decoded as nothing at all."""
    prematch = derive_parent_prematch(EDR_PIPE)
    assert "EDR.ALERT" not in prematch, "prematch pinned the type value"
    assert "type" in prematch, "prematch dropped the structural key too"
    assert osregex_matches(prematch, EDR_PIPE)


@pytest.mark.parametrize(
    "sibling",
    [
        'MSG#88214|type=EDR.INFO|ts=1754056799|host=WKSTN12|proc=svchost.exe|pid=900',
        'MSG#90001|type=NET.FLOW|ts=1754060000|host=SRV07|verdict=CLEAN|score=0',
    ],
)
def test_other_event_types_from_the_same_source_still_match(sibling):
    prematch = derive_parent_prematch(EDR_PIPE)
    assert osregex_matches(prematch, sibling), (
        f"{prematch!r} rejects a sibling event from the same log source"
    )


def test_prematch_does_not_reach_into_a_bracketed_body():
    """The 4-token fallback used to swallow `[REQ`, pinning the parent to
    request events and excluding every other line from the same service."""
    prematch = derive_parent_prematch(BRACKET_BODY)
    assert "REQ" not in prematch
    assert "SVC" in prematch, "the header tag itself should survive"
    assert osregex_matches(prematch, BRACKET_BODY)
    # A line from the same service with no [REQ ...] block at all.
    assert osregex_matches(
        prematch, '<2026.08.01 14:33> {SVC:orders-api} startup complete'
    )


def test_header_zone_cuts_at_first_value_or_body_block():
    from app.main import _header_zone

    assert _header_zone("MSG#1|type=EDR.ALERT|ts=9") == "MSG#1|type="
    assert _header_zone("a b [REQ id=1]") == "a b "
    assert _header_zone("no values here") == "no values here"


def test_header_zone_survives_a_log_that_opens_with_a_bracket():
    """A `[` at position 0 collapsed the zone to "", so `derive_parent_prematch`
    returned None and the parent shipped with no prematch at all. The opening
    group is header — an epoch stamp, an apache date — not the body block the
    `[` stop is for."""
    from app.main import _header_zone

    assert _header_zone(EPOCH_PAYGW) == "[1754056222831] ~PAYGW~ >> merchant="
    assert _header_zone(APACHE_ERROR) == "[Mon Aug 03 09:22:31.113456 2026] "


@pytest.mark.parametrize("log", [EPOCH_PAYGW, APACHE_ERROR])
def test_bracket_opening_logs_still_get_a_parent_prematch(log):
    prematch = derive_parent_prematch(log)
    assert prematch, "a log opening with '[' must still yield a prematch"
    assert osregex_matches(prematch, log)


def test_epoch_bracket_prematch_covers_the_header_without_pinning_a_value():
    """`[<epoch>] ~PAYGW~` is the envelope; the merchant id is one event's data."""
    prematch = derive_parent_prematch(EPOCH_PAYGW)
    assert "PAYGW" in prematch, "the product tag should survive"
    assert "1754056222831" not in prematch, "the epoch is per-event"
    assert "MID99213" not in prematch, "the merchant id is per-event"
    assert osregex_matches(
        prematch,
        "[1754056301447] ~PAYGW~ >> merchant=MID41022 | card=****9930 | "
        "amt=289.00:EUR | result=DECLINE(05)",
    )


def test_weekday_name_is_generalized_like_the_month():
    """`[Mon Aug 03 ...]` kept `Mon` literal, so the decoder matched only
    Mondays — a month-shaped overfit that the month rule did not cover."""
    prematch = derive_parent_prematch(APACHE_ERROR)
    assert "Mon" not in prematch
    for other in (
        "[Tue Sep 15 22:05:02.884211 2026] [authz_core:error] [client 10.0.0.3:41022] AH01630: denied",
        "[Sun Dec 25 01:02:03.000001 2027] [authz_core:error] [client 10.0.0.1:1] AH01630: denied",
    ):
        assert osregex_matches(prematch, other)


def test_weekday_generalization_leaves_words_that_merely_start_with_one_alone():
    """"Monday-svc01" and "Sunfire-01" are hostnames, not dates."""
    from app.main import _generalize_with_digit_runs_and_months

    assert "Monday" in _generalize_with_digit_runs_and_months("Monday-svc01")
    assert "Sunfire" in _generalize_with_digit_runs_and_months("Sunfire-01")


def test_weekday_generalization_leaves_all_caps_product_tags_alone():
    """A `MON` or `SUN` product tag is a tag; only title case is a weekday."""
    from app.main import _generalize_prematch_prefix

    generalized = _generalize_prematch_prefix("MON|SUN|")
    assert "MON" in generalized and "SUN" in generalized


# ── guardrail backstop for an LLM-authored prematch ──────────────────────────

def test_detect_overfit_prematch_flags_a_pinned_field_value():
    from app.main import detect_overfit_prematch

    bad = '<decoder name="myapp"><prematch>^MSG\\p\\d+\\ptype\\pEDR.ALERT</prematch></decoder>'
    reason = detect_overfit_prematch(bad, None, sample_log=EDR_PIPE)
    assert reason and "EDR.ALERT" in reason


def test_detect_overfit_prematch_accepts_the_envelope_form():
    from app.main import detect_overfit_prematch

    good = '<decoder name="myapp"><prematch>^MSG\\p\\d+\\ptype\\p</prematch></decoder>'
    assert detect_overfit_prematch(good, None, sample_log=EDR_PIPE) is None


def test_detect_overfit_prematch_is_backwards_compatible_without_a_sample():
    from app.main import detect_overfit_prematch

    bad = '<decoder name="myapp"><prematch>^MSG\\p\\d+\\ptype\\pEDR.ALERT</prematch></decoder>'
    assert detect_overfit_prematch(bad, None) is None


# ── the second producer: prematch_osregex_from_current_logs ──────────────────

def test_second_producer_also_stops_at_the_key():
    """default_prematch_boundary's fallback splits on whitespace, so a
    pipe-delimited log with no spaces came back whole — every value included."""
    from app.main import prematch_osregex_from_current_logs

    prematch = prematch_osregex_from_current_logs([EDR_PIPE], "myapp")
    assert "EDR.ALERT" not in prematch
    assert "SUSPICIOUS" not in prematch
    assert osregex_matches(prematch, EDR_PIPE)


def test_both_producers_agree_on_the_envelope():
    from app.main import prematch_osregex_from_current_logs

    assert derive_parent_prematch(EDR_PIPE) == prematch_osregex_from_current_logs(
        [EDR_PIPE], "myapp"
    )


@pytest.mark.parametrize("day", ["Aug  1", "Dec 25", "Jan  3", "Nov 11"])
def test_second_producer_generalizes_the_month_and_day_padding(day):
    """A syslog priority prefix ("<134>Aug ...") pushes the month off position 0,
    past the timestamp branches, and the fallback kept it literal. Syslog also
    space-pads single-digit days, so each space escaped to its own \\s+."""
    from app.main import prematch_osregex_from_current_logs

    prematch = prematch_osregex_from_current_logs([SYSLOG_ACCESSLOG], "myapp")
    assert "Aug" not in prematch
    assert osregex_matches(prematch, SYSLOG_ACCESSLOG.replace("Aug  1", day))


def test_month_generalization_leaves_hostnames_alone():
    """"March-svc01" is a hostname; only a standalone month is a date."""
    from app.main import _generalize_with_digit_runs_and_months

    assert "March" in _generalize_with_digit_runs_and_months("March-svc01")


def test_overfit_guardrail_takes_the_shape_the_endpoint_actually_passes():
    """AIGenerateRequest.logs is List[LogSample], not List[str].

    /api/ai/generate-validated feeds the guardrail from request.logs, and
    first_non_empty() calls .strip() on each element — handing it LogSample
    objects raises AttributeError and 500s the endpoint. Pin the contract."""
    from app.main import AIGenerateRequest, detect_overfit_prematch, first_non_empty

    request = AIGenerateRequest(app_name="myapp", logs=[{"raw_log": EDR_PIPE}])
    sample = first_non_empty([s.raw_log for s in request.logs])
    assert sample == EDR_PIPE

    with pytest.raises(AttributeError):
        first_non_empty(request.logs)

    bad = '<decoder name="myapp"><prematch>^MSG\\p\\d+\\ptype\\pEDR.ALERT</prematch></decoder>'
    assert detect_overfit_prematch(bad, None, sample_log=sample)


# ── KEY(value) paren format ──────────────────────────────────────────────────

PAREN_NODEEVT = (
    '2026-08-01 14:43:00; PRIORITY(CRIT); COMPONENT(storage-node-3); '
    'EVENT(disk.smart.fail); DETAIL(dev=/dev/sdb; reallocated=1284; pending=44; '
    'temp=61C); ACTION(auto-evacuate started); TICKET(INC-99213)'
)


def test_paren_format_prematch_keeps_the_key_not_the_value():
    """`PRIORITY(CRIT)` in the prematch matches criticals and nothing else.

    The header zone knew `key=` and `[`, but this format uses `KEY(value)`, so
    the first `=` it found was buried inside `DETAIL(dev=...)` — the prematch
    ran through PRIORITY and COMPONENT, pinning both values."""
    prematch = derive_parent_prematch(PAREN_NODEEVT)
    assert "PRIORITY" in prematch, "the structural key should survive"
    for value in ("CRIT", "storage", "node", "disk", "smart"):
        assert value not in prematch, f"prematch pinned the value {value!r}"
    assert osregex_matches(prematch, PAREN_NODEEVT)


@pytest.mark.parametrize(
    "sibling",
    [
        '2026-08-01 15:02:11; PRIORITY(WARN); COMPONENT(net-edge-11); EVENT(link.flap)',
        '2027-01-09 02:00:00; PRIORITY(INFO); COMPONENT(api-7); EVENT(startup)',
        '2030-12-25 23:59:59; PRIORITY(DEBUG); COMPONENT(x); EVENT(y)',
    ],
)
def test_paren_format_matches_other_severities_and_components(sibling):
    assert osregex_matches(derive_parent_prematch(PAREN_NODEEVT), sibling)


def test_paren_format_prematch_still_discriminates():
    """Trimming the prematch must not make it match anything with a date."""
    prematch = derive_parent_prematch(PAREN_NODEEVT)
    assert not osregex_matches(
        prematch, '2026-08-01 14:43:00; SEVERITY(CRIT); COMPONENT(storage-node-3)'
    )
    assert not osregex_matches(prematch, 'MSG#1|type=EDR.ALERT|ts=1')


def test_default_boundary_does_not_cut_inside_a_clock():
    """`:\\s*` allowed the zero-width case, so "14:43:" satisfied the
    "program:" marker and the header was cut mid-timestamp."""
    from app.main import default_prematch_boundary

    assert default_prematch_boundary(PAREN_NODEEVT) == "2026-08-01 14:43:00; PRIORITY("
    # A genuine syslog program marker must still be honoured.
    assert default_prematch_boundary(SYSLOG_ACCESSLOG).endswith("accesslog: ")


# ── key:value records ────────────────────────────────────────────────────────

SENSOR_KV = (
    'DEV:TH-SENSOR-0442,SEQ:88213,T:2026-08-01T14:44:09Z,temp:23.4C,hum:61%,'
    'batt:3.71V,rssi:-72dBm,evt:THRESHOLD_BREACH,thr:temp>22.0C,fw:1.4.2,crc:0x8A3F'
)


def test_kv_colon_record_prematch_pins_nothing():
    """`key:value` hit none of the known boundaries, so the whole record --
    device id, event name, firmware, crc -- ended up in the prematch."""
    prematch = derive_parent_prematch(SENSOR_KV)
    for value in ("TH-SENSOR-0442", "88213", "THRESHOLD_BREACH", "8A3F", "1.4.2"):
        assert value not in prematch, f"prematch pinned {value!r}"
    assert osregex_matches(prematch, SENSOR_KV)


def test_kv_colon_record_matches_a_different_device_and_event():
    prematch = derive_parent_prematch(SENSOR_KV)
    assert osregex_matches(
        prematch,
        'DEV:TH-SENSOR-0001,SEQ:2,T:2027-01-09T02:00:00Z,temp:19.0C,'
        'evt:HEARTBEAT,fw:2.0.0,crc:0x11BB',
    )


def test_a_clock_colon_is_not_a_field_boundary():
    """Every timestamp has colons; treating them as kv separators would cut
    the header mid-time. Keys must start with a letter."""
    from app.main import _header_zone

    assert _header_zone(SYSLOG_ACCESSLOG).startswith("<134>Aug  1 14:49:10")
    assert _header_zone(PAREN_NODEEVT) == "2026-08-01 14:43:00; PRIORITY("


def test_namespaced_colon_is_not_a_value_boundary():
    """`LOGV3|f:ts=...` — `f:` introduces a namespace, not a value. The value
    starts after `ts=`, so the header must reach that far and no further."""
    prematch = derive_parent_prematch(LOGV3)
    assert "ts" in prematch
    assert "2026" not in prematch and "host" not in prematch


def test_lone_colon_tag_does_not_trigger_the_kv_rule():
    """A single `{SVC:name}` tag is a header, not a kv record — the rule needs
    several pairs before a colon counts, so this keeps its earlier behaviour."""
    prematch = derive_parent_prematch(BRACKET_BODY)
    assert "SVC" in prematch
    assert not osregex_matches(
        prematch, '<2026.08.01 14:30> {SVC:payments-api} [REQ id=req-1]'
    )


# ── child captures on delimited records ──────────────────────────────────────

def test_child_capture_is_bounded_by_the_record_delimiter():
    """(\\S+) is non-space and so is a comma, so `temp:(\\S+)` swallowed the
    whole rest of the record. OS_Regex backtracks when a literal follows the
    group, so the delimiter bounds it."""
    from app.main import build_split_regexes_from_fields

    pairs = build_split_regexes_from_fields(
        [SENSOR_KV], {"temp": "23.4C", "evt": "THRESHOLD_BREACH", "crc": "0x8A3F"}
    )
    by_field = {order[0]: regex for regex, order in pairs}
    assert by_field["temp"].endswith(r"(\S+),")
    assert by_field["evt"].endswith(r"(\S+),")
    # crc is the final field of the record — nothing follows it to anchor on.
    assert by_field["crc"].endswith(r"(\S+)")


# ── field-name matching must not collide on fragments ────────────────────────

def test_single_letter_field_does_not_match_an_unrelated_wazuh_field():
    """A log field named `T` matched `dstip`, because "t" is a substring of
    "dstip". That scored an unrelated junos firewall template above zero, and
    the tool emitted a <order>dstip</order> child for a log with no IP in it."""
    from app.main import extract_relevant_fields, select_requested_fields

    available = extract_relevant_fields(SENSOR_KV)
    assert "T" in available, "sample no longer has the single-letter field"
    selected, missing = select_requested_fields(available, ["dstip"])
    assert selected == {}
    assert missing == ["dstip"]


@pytest.mark.parametrize(
    "one,other,expected",
    [
        ("t", "dstip", False),      # the reported collision
        ("a", "action", False),     # any single letter
        ("ip", "srcip", True),      # suffix — what the fallback is for
        ("temp", "temperature", True),   # prefix
        ("user", "dstuser", True),
        ("st", "dstip", False),     # mid-word fragment
    ],
)
def test_affix_match_accepts_prefixes_and_suffixes_only(one, other, expected):
    from app.main import _affix_match

    assert _affix_match(one, other) is expected
    assert _affix_match(other, one) is expected, "must be symmetric"


def test_low_confidence_template_does_not_inject_its_fields():
    """junos-rt-flow-reassemble-fail scored 0.19 against a sensor log and
    contributed order=['dstip']. With the field no longer matching, the
    template scores zero and is dropped."""
    from app.main import score_ml_decoder_template, extract_relevant_fields

    available = extract_relevant_fields(SENSOR_KV)
    junos = {"name": "junos-rt-flow-reassemble-fail", "order": ["dstip"], "score": 0.1895}
    assert score_ml_decoder_template(junos, available, ["temp", "hum"]) == 0.0


# ── <order> spelling ─────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "given,expected",
    [
        ("dstuser", "user"),
        ("DstUser", "user"),
        (" dstuser ", "user"),
        ("srcuser", "srcuser"),   # only dstuser is aliased onto user
        ("user", "user"),
        ("dstip", "dstip"),
        ("temp", "temp"),
    ],
)
def test_order_field_name_prefers_user_over_dstuser(given, expected):
    """Wazuh resolves <order>user</order> onto dstuser internally — logtest
    emits `dstuser` for both spellings — so `user` is the clearer source form."""
    from app.main import normalize_order_field_name

    assert normalize_order_field_name(given) == expected


def test_order_normalization_reaches_model_authored_xml():
    """The deterministic renderers normalise their own output, but XML the
    model wrote goes straight through — both paths must agree."""
    from app.main import normalize_decoder_order_xml

    xml = (
        '<decoder name="a"><order>dstuser</order></decoder>'
        '<decoder name="a"><order>srcip, dstuser</order></decoder>'
    )
    out = normalize_decoder_order_xml(xml)
    assert "dstuser" not in out
    assert "<order>user</order>" in out
    assert "<order>srcip, user</order>" in out


def test_derive_handles_empty_and_junk_input():
    assert derive_parent_prematch("") is None
    assert derive_parent_prematch("   ") is None
    assert derive_parent_prematch(None) is None


def test_single_token_log_still_yields_a_matching_prematch():
    prematch = derive_parent_prematch("something-happened")
    assert prematch is None or osregex_matches(prematch, "something-happened")


# ── the hostname wazuh-logtest does not print ────────────────────────────────
#
# On the ISO8601 path logtest emits no `hostname:` line, yet Wazuh still eats
# the token after the timestamp as the hostname. Proven by giving a child
# decoder `^(\S+)` against
#   '2026-08-03T08:15:01.824+00:00 VPNGW01 event=authentication ...'
# which captured 'event=authentication', not 'VPNGW01'. Trusting the absent
# hostname left the tag in the remainder, so every derived prematch anchored a
# token too early and the parent could never fire.

ISO_KV_LOG = (
    '2026-08-03T08:15:01.824+00:00 VPNGW01 event=authentication status=failed '
    'username="john.doe" src_ip=192.168.10.25 risk_score=47'
)


def test_iso8601_remainder_drops_the_unreported_hostname_token():
    remainder = postpredecode_remainder(ISO_KV_LOG, "2026-08-03T08:15:01.824+00:00", None)
    assert remainder.startswith("event=authentication"), remainder
    assert "VPNGW01" not in remainder


@pytest.mark.parametrize("stamp", [
    "2026-08-03T08:15:01.824+00:00",
    "2026-08-03T08:15:01+00:00",
    "2026-08-03T08:15:01.824000+00:00",
    "2026-08-03T08:15:01.824Z",
])
def test_every_clean_iso8601_form_consumes_the_following_token(stamp):
    log = f"{stamp} HOSTTAG key=value other=thing"
    assert postpredecode_remainder(log, stamp, None) == "key=value other=thing"


def test_a_mangled_timestamp_consumes_no_token():
    """When the pre-decoder grabs a fixed 31 chars it slices into the next field
    and the reported timestamp carries that debris — no token boundary there is
    trustworthy, so nothing extra may be dropped."""
    log = "2026-08-01T14:23:11.842Z|APPAUTH|sev=4|node=auth-svc-07"
    remainder = postpredecode_remainder(log, "2026-08-01T14:23:11.842Z|APPAUT", None)
    assert remainder == "H|sev=4|node=auth-svc-07"


def test_a_reported_hostname_is_still_what_gets_stripped():
    log = "Aug  3 09:14:22 gw01 something happened here"
    assert postpredecode_remainder(log, "Aug  3 09:14:22", "gw01") == "something happened here"


def test_no_timestamp_still_means_nothing_was_predecoded():
    assert postpredecode_remainder("[1754056222831] ~PAYGW~ >> merchant=X", None, None) is None


def test_iso_kv_prematch_anchors_on_the_first_key_not_the_tag():
    """Consequence worth pinning: with the tag eaten, the prematch can only
    anchor on the first key — which is why sources sharing a first key collide
    and cannot be told apart by a decoder at all."""
    remainder = postpredecode_remainder(ISO_KV_LOG, "2026-08-03T08:15:01.824+00:00", None)
    prematch = derive_parent_prematch(remainder)
    assert prematch.startswith("^event"), prematch
    assert osregex_matches(prematch, remainder)


# ── overfit shapes the key=value scan could not see ──────────────────────────

def test_overfit_detects_a_pinned_json_value():
    """JSON has no `key=`, so a prematch embedding ERROR, payments-api, jdoe and
    a whole message text passed the guardrail clean."""
    from app.main import detect_overfit_prematch

    sample = (
        '{"timestamp":"2026-08-03T09:31:12Z","level":"ERROR","service":"payments-api",'
        '"user":"jdoe","message":"payment authorization failed","status":502}'
    )
    bad = (
        '<decoder name="jsonapi"><prematch>'
        r'^\p\p\plevel\p\p\pERROR\p\p\pservice\p\p\ppayments\papi\p'
        '</prematch></decoder>'
    )
    assert detect_overfit_prematch(bad, None, sample_log=sample)


def test_overfit_detects_an_opaque_id_from_a_positional_format():
    """Zeek is tab-separated: no key to scan, so the connection uid sat in the
    prematch and matched that one connection for good."""
    from app.main import detect_overfit_prematch

    sample = "1754214122.441\tCwXyZ1abcd2EfGh\t203.0.113.9\t51221\t10.0.0.5\t22\ttcp\tssh"
    bad = (
        '<decoder name="zeek"><prematch>'
        r'^\d+\p\d+\s+CwXyZ\d+abcd\d+EfGh\s+\d+\p\d+\p\d+\p\d+'
        '</prematch></decoder>'
    )
    reason = detect_overfit_prematch(bad, None, sample_log=sample)
    assert reason and "CwXyZ1abcd2EfGh" in reason, reason


def test_overfit_detects_a_numeric_date_literal():
    """`^E0803` is klog severity plus month 08 day 03 — a literal date no
    alphabetic-month rule can see."""
    from app.main import detect_overfit_prematch

    sample = 'E0803 09:48:21.113455       1 authorization.go:74] Forbidden: verb="delete"'
    bad = '<decoder name="kubeapi"><prematch>^E0803\\s+\\d+\\p\\d+</prematch></decoder>'
    reason = detect_overfit_prematch(bad, None, sample_log=sample)
    assert reason and "0803" in reason


def test_overfit_detects_a_prematch_that_swallowed_the_whole_record():
    """A Palo Alto prematch generalized only the digits of a 40-field CSV and
    kept allow/inbound/ssl/untrust/deny literal — near-identical sessions only."""
    from app.main import detect_overfit_prematch

    sample = (
        "1,2026/08/03 09:40:22,013201004215,TRAFFIC,end,2561,203.0.113.45,10.1.1.20,"
        "allow-inbound,ssl,vsys1,untrust,trust,ethernet1/1,LogForward,tcp,deny"
    )
    bad = (
        '<decoder name="paloalto"><prematch>'
        r'^\d+\p\d+\pTRAFFIC\pend\p\d+\pallow\pinbound\pssl\pvsys\d+\puntrust\ptrust'
        r'\pethernet\d+\pLogForward\ptcp\pdeny'
        '</prematch></decoder>'
    )
    assert detect_overfit_prematch(bad, None, sample_log=sample)


@pytest.mark.parametrize("prematch,sample", [
    (r"^CEF\p\d+\p", "CEF:0|Trellix|EDR|4.2.1|MALWARE_FOUND|x|8|src=203.0.113.31"),
    (r"^LEEF\p\d+\p\d+\pImperva\pWAF", "LEEF:2.0|Imperva|WAF|12.0|SQL_INJECTION|src=1.2.3.4"),
    (r"^\pPLC\pSTN\p", "$PLC,STN=04,TS=20260801143201,TAG=PMP01.FLOW,VAL=142.7"),
    (r"^\p\d+\p\s+~PAYGW~\s+\p\p\s+merchant\p",
     "[1754056222831] ~PAYGW~ >> merchant=MID99213 | card=****4821"),
    (r"^id\p", 'id=firewall sn=0017C58A1B2C time="2026-08-03 09:52:18" fw=10.0.0.1'),
    (r"^\p\d+\p\d+\p\d+\s+\d+\p\d+\p\s+\pSVC\porders\papi\p",
     "<2026.08.01 14:30> {SVC:orders-api} [REQ id=req-8821 method=POST]"),
])
def test_good_envelope_prematches_are_not_flagged(prematch, sample):
    """The guardrail must not cry wolf on a correct envelope prematch."""
    from app.main import detect_overfit_prematch

    xml = f'<decoder name="x"><prematch>{prematch}</prematch></decoder>'
    assert detect_overfit_prematch(xml, None, sample_log=sample) is None


# ── one prematch has to cover every sample supplied ──────────────────────────

ARUBA_CLI = (
    "10.7.2.19 cli[6005]: <341004> <WARN> AP:HRD_GF-:cc:ff:3c_Master "
    "<10.7.2.19 A8:5B:F7:CC:FF:3C>  AP 10.7.2.15: Client 5a:5a:84:2d:39:56 authenticate fail"
)
ARUBA_STM = (
    "10.7.2.19 stm[6041]: <501094> <NOTI> AP:HRD_GF-:cc:ff:3c_Master "
    "<10.7.2.19 A8:5B:F7:CC:FF:33>  Auth failure: d6:a5:17:db:81:42: AP 10.7.2.19-a8:5b:f7"
)


def test_multi_sample_prematch_covers_both_subsystems():
    """Deriving from sample 1 alone produced `...\\s+cli`, which fails sample 2
    even though both were supplied in the same request. An Aruba controller
    emits cli, stm, authmgr, sapd..."""
    from app.main import derive_parent_prematch_multi

    prematch = derive_parent_prematch_multi([ARUBA_CLI, ARUBA_STM])
    assert prematch
    assert "cli" not in prematch and "stm" not in prematch
    assert osregex_matches(prematch, ARUBA_CLI)
    assert osregex_matches(prematch, ARUBA_STM)


def test_single_sample_prematch_stays_specific():
    """Generalizing only where the samples actually disagree — one sample means
    nothing is known to vary, so the token stays."""
    from app.main import derive_parent_prematch_multi

    assert derive_parent_prematch_multi([ARUBA_CLI]) == derive_parent_prematch(ARUBA_CLI)


def test_multi_sample_keeps_a_prematch_that_already_covers_everything():
    from app.main import derive_parent_prematch_multi

    both = [ARUBA_CLI, ARUBA_CLI.replace("10.7.2.15", "10.7.2.44")]
    assert derive_parent_prematch_multi(both) == derive_parent_prematch(ARUBA_CLI)


def test_multi_sample_handles_empty_input():
    from app.main import derive_parent_prematch_multi

    assert derive_parent_prematch_multi([]) is None
    assert derive_parent_prematch_multi(["", "   "]) is None
