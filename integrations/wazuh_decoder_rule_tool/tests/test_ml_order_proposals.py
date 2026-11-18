"""
Regression tests for retrieval-proposed <order> fields.

`ml_order` used to be routed through select_requested_fields(), which
intersects it against what the local extractor already found — so a retrieved
decoder's <order> could only reorder fields, never contribute one. The field
most worth having was the one that got dropped: for an sshd-shaped failed
login, retrieval says `srcuser,srcip` and the extractor finds only `srcip`.

A proposal is allowed to reach a decoder only when the regex the generator
would actually emit captures, in *every* sample log, exactly the value located
in that log. So these tests pin down both directions:

  * a correct proposal adds a field, and does not cost the fields the
    extractor had already found,
  * a proposal that only fits the first sample, or names a field the log does
    not contain, changes nothing at all.
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "app"))

from app.main import (  # noqa: E402
    build_log_based_regex,
    choose_log_driven_fields,
    locate_field_value,
    osregex_captures,
    osregex_matches,
    propose_ml_order_fields,
)

SSHD_INVALID_USER = (
    "Dec 25 20:45:02 web01 sshd[1234]: Failed password for invalid user admin "
    "from 192.168.1.50 port 54321 ssh2"
)
SSHD_SECOND_USER = (
    "Dec 25 20:46:11 web01 sshd[1299]: Failed password for invalid user bob "
    "from 10.0.0.9 port 2222 ssh2"
)
SSHD_NO_USER = "Dec 25 20:46:11 web01 sshd[1299]: Connection closed by 10.0.0.9 port 2"
KV_APP = "2026-08-03T10:15:00Z myapp[9]: action=login user=bob result=denied srcip=203.0.113.9"
NOVEL_VENDOR = "Aug  3 11:00:01 host01 vendorxyz: SESSION_END id=A91F duration=32"


# --- osregex_captures ------------------------------------------------------

def test_captures_reads_the_group_osregex_matches_cannot():
    # osregex_matches escapes parens, so it reports no match for any pattern
    # with a capture group -- which is why verification needed its own helper.
    regex = r"\.+user (\S+)"
    assert osregex_matches(regex, SSHD_INVALID_USER) is False
    assert osregex_captures(regex, SSHD_INVALID_USER) == ("admin",)


def test_captures_returns_none_when_pattern_misses():
    assert osregex_captures(r"\.+nosuchlabel (\S+)", SSHD_INVALID_USER) is None


def test_escaped_paren_stays_literal():
    assert osregex_captures(r"pid \((\d+)\)", "pid (1234) ok") == ("1234",)


def test_prematch_verification_is_unchanged():
    # keep_groups defaults off, so prematch checking keeps its old meaning.
    assert osregex_matches(r"^\d+\p\d+\p\d+", "2026-08-03 something") is True


# --- locating a value by label --------------------------------------------

def test_locates_space_separated_label():
    assert locate_field_value(SSHD_INVALID_USER, "srcuser") == "admin"


def test_locates_key_value_label():
    assert locate_field_value(KV_APP, "user") == "bob"


def test_locates_via_label_hint_not_just_the_field_name():
    # `status` is the Wazuh field name; the log spells it `result`.
    assert locate_field_value(KV_APP, "status") == "denied"


def test_returns_none_when_no_label_present():
    assert locate_field_value(NOVEL_VENDOR, "srcuser") is None


def test_does_not_take_the_next_key_as_a_value():
    assert locate_field_value("evt=LOGIN user action=deny", "srcuser") != "action=deny"


def test_quoted_value_after_colon_is_not_truncated_at_the_space():
    log = '1 2019-05-15T16:27:08Z HOST CheckPoint - [action:"Key Install"; flags:"133376"]'
    assert locate_field_value(log, "action") == "Key Install"


def test_bare_space_is_not_trusted_for_a_prose_label():
    # "Unescaped URL path matches" must not offer url="path".
    log = "[Tue Sep 30] [client 77.127.180.111:54082] AH01136: Unescaped URL path matches"
    assert locate_field_value(log, "url") is None


def test_bare_space_is_not_trusted_for_ip_labels():
    # `dst outside:116.6.127.120` would hand back the interface prefix too.
    log = "%ASA-3-106010: Deny inbound protocol 47 src outside:115.51.6.185 dst outside:116.6.127.120"
    assert locate_field_value(log, "dstip") is None


def test_bare_space_still_works_where_it_is_the_convention():
    assert locate_field_value(SSHD_INVALID_USER, "srcuser") == "admin"
    assert locate_field_value(SSHD_INVALID_USER, "srcport") == "54321"


def test_structural_word_is_not_taken_as_a_space_separated_value():
    # This log names no user at all; `user from 172.18.1.1` must not yield "from".
    log = "2020-03-24 08:38:42 localhost sshd[2519]: Failed password for user from 172.18.1.1 port 4"
    assert locate_field_value(log, "srcuser") is None


def test_structural_word_is_still_a_valid_explicit_value():
    # After an explicit separator these are real values, not line structure.
    assert locate_field_value("type=event level=info status=unknown", "status") == "unknown"


# --- strict resolution for retrieved names --------------------------------

def test_retrieved_names_are_not_affix_matched_onto_other_fields():
    from app.main import select_requested_fields

    available = {"time": "2019-02-15", "dst": "1.2.3.4", "src": "5.6.7.8"}
    # A person typing "ip" should still find something fuzzy...
    assert select_requested_fields(available, ["dst"], allow_affix=True)[0]
    # ...but a retrieved `timezone` must not be answered with `time`'s value.
    strict, missing = select_requested_fields(available, ["timezone"], allow_affix=False)
    assert strict == {}
    assert missing == ["timezone"]
    loose, _ = select_requested_fields(available, ["timezone"], allow_affix=True)
    assert loose == {"timezone": "2019-02-15"}


def test_true_synonyms_still_resolve_strictly():
    from app.main import select_requested_fields

    selected, _ = select_requested_fields({"proto": "tcp"}, ["protocol"], allow_affix=False)
    assert selected == {"protocol": "tcp"}


# --- proposals: accepted --------------------------------------------------

def test_proposal_adds_the_field_the_extractor_missed():
    proposals = propose_ml_order_fields([SSHD_INVALID_USER], ["srcuser", "srcip"], {})
    assert proposals == {"srcuser": "admin"}


def test_proposal_survives_across_logs_with_different_values():
    logs = [SSHD_INVALID_USER, SSHD_SECOND_USER]
    assert propose_ml_order_fields(logs, ["srcuser"], {}) == {"srcuser": "admin"}


def test_accepted_proposal_does_not_cost_the_heuristic_fields():
    # Routing proposals through requested_fields would flip field selection to
    # "requested only" and drop srcip, making the output worse than before.
    _, order, _ = choose_log_driven_fields(
        [SSHD_INVALID_USER], [], ml_order=["srcuser", "srcip"]
    )
    assert "srcuser" in order
    assert "srcip" in order


def test_proposal_reaches_the_generated_regex_pairs():
    pairs, _, _ = build_log_based_regex(
        [SSHD_INVALID_USER], [], ml_order=["srcuser", "srcip"]
    )
    by_field = {tuple(order): regex for regex, order in pairs}
    assert ("srcuser",) in by_field
    assert osregex_captures(by_field[("srcuser",)], SSHD_INVALID_USER) == ("admin",)


def test_field_already_found_is_not_re_proposed():
    assert propose_ml_order_fields(
        [SSHD_INVALID_USER], ["srcip"], {"srcip": "192.168.1.50"}
    ) == {}


# --- proposals: rejected --------------------------------------------------

def test_rejects_field_that_only_appears_in_the_first_log():
    logs = [SSHD_INVALID_USER, SSHD_NO_USER]
    assert propose_ml_order_fields(logs, ["srcuser"], {}) == {}


def test_rejects_fields_absent_from_the_log():
    proposals = propose_ml_order_fields(
        [NOVEL_VENDOR], ["srcuser", "srcip", "dstport"], {}
    )
    assert proposals == {}


def test_nonsense_order_leaves_output_identical():
    baseline = choose_log_driven_fields([SSHD_INVALID_USER], [], ml_order=None)
    garbage = choose_log_driven_fields(
        [SSHD_INVALID_USER], [], ml_order=["totally", "made", "up"]
    )
    assert garbage == baseline


def test_empty_and_missing_order_are_safe():
    assert propose_ml_order_fields([SSHD_INVALID_USER], None, {}) == {}
    assert propose_ml_order_fields([SSHD_INVALID_USER], [], {}) == {}
    assert propose_ml_order_fields([], ["srcuser"], {}) == {}
    assert propose_ml_order_fields(["   "], ["srcuser"], {}) == {}
