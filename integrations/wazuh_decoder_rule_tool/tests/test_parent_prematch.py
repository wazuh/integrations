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


def test_derive_handles_empty_and_junk_input():
    assert derive_parent_prematch("") is None
    assert derive_parent_prematch("   ") is None
    assert derive_parent_prematch(None) is None


def test_single_token_log_still_yields_a_matching_prematch():
    prematch = derive_parent_prematch("something-happened")
    assert prematch is None or osregex_matches(prematch, "something-happened")
