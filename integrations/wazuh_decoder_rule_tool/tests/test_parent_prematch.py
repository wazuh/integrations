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


def test_derive_handles_empty_and_junk_input():
    assert derive_parent_prematch("") is None
    assert derive_parent_prematch("   ") is None
    assert derive_parent_prematch(None) is None


def test_single_token_log_still_yields_a_matching_prematch():
    prematch = derive_parent_prematch("something-happened")
    assert prematch is None or osregex_matches(prematch, "something-happened")
