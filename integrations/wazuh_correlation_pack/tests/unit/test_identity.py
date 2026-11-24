import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)

from wcp import alerting as A  # noqa: E402
from wcp import config as C  # noqa: E402
from wcp import identity as I  # noqa: E402
from wcp import sigma as S  # noqa: E402

acct = I.windows_target_account
NULL_SID = "S-1-0-0"


# ----------------------------------------------------------------------------- fixtures
# Fixtures are raw 4625 EventData records. ``decode`` turns them into indexed documents with the
# stock decoder steps (decoder/windows-event/0 step 2, decoder/windows-security/0 steps 5-13; the
# same steps as tests/validation/winevents.decoder_model, observed on 5.0.0-rc1 and rc2).
# ``spec`` derives the expected account from the raw *failed-target* fields only, independently of
# wcp.identity: TargetDomainName is observable as the target's domain only when the decoders put it
# in user.target.domain, which they do when the event has a reporting subject; otherwise - or when
# it is missing, empty or "-" - the realm is unknown ("?"). "." is the reporting computer.

def decode(computer, data):
    out = {}
    g = data.get

    def put(k, v):
        if v is not None:
            out[k] = v
    put("host.name", computer)
    put("user.domain", g("SubjectDomainName"))
    put("user.id", g("SubjectUserSid"))
    put("user.target.name", g("TargetUserName"))
    put("user.target.id", g("TargetUserSid"))
    if g("SubjectUserName") is not None and g("SubjectUserName") != "-":
        out["user.name"] = g("SubjectUserName")
    if "user.id" not in out or out["user.id"] == NULL_SID:
        put("user.id", g("TargetUserSid"))
    tun = g("TargetUserName")
    if "user.name" in out and tun is not None and tun != "-":
        out["user.target.name"] = tun
    elif "user.name" not in out and tun is not None and tun != "-":
        out["user.name"] = tun
    if "user.domain" in out and out["user.domain"] != "-":
        put("user.target.domain", g("TargetDomainName"))
    else:
        put("user.domain", g("TargetDomainName"))
    return out


def spec(computer, data):
    name = (data.get("TargetUserName") or "").strip().lower()
    if name in ("", "-"):
        return None
    subject = (data.get("SubjectDomainName") or "").strip()
    td = (data.get("TargetDomainName") or "").strip().lower()
    realm = td if subject not in ("", "-") and td not in ("", "-") else ""
    if realm == ".":
        realm = (computer or "").split(".", 1)[0].lower()
    return (realm or "?") + "\\" + name


def raw(target, target_domain=None, subject=None, subject_domain=None, subject_sid=None, target_sid=NULL_SID):
    """subject=None: no reporting subject (network logon: all subject fields '-' / NULL SID)."""
    d = {"TargetUserName": target, "TargetUserSid": target_sid}
    if target_domain is not None:
        d["TargetDomainName"] = target_domain
    if subject is None:
        d.update(SubjectUserName="-", SubjectDomainName="-", SubjectUserSid=NULL_SID)
    else:
        d.update(SubjectUserName=subject, SubjectDomainName=subject_domain or "WORKGROUP",
                 SubjectUserSid=subject_sid or "S-1-5-21-1000000001-1000000002-1000000003-500")
    return d


def accounts(records, computer="WIN-LAB1"):
    """(implementation, specification) account lists for a list of raw records."""
    return [acct(decode(computer, r)) for r in records], [spec(computer, r) for r in records]


class TestWindowsTargetAccount(unittest.TestCase):
    def assertSpec(self, records, computer="WIN-LAB1"):
        got, want = accounts(records, computer)
        self.assertEqual(got, want)
        return got

    # -- the defect of the 5.0.0-rc2 run (P1, ambiguous account domain)
    def test_changing_subject_domains_one_unknown_account_no_spray(self):
        recs = [raw("bob", "-", subject="svc", subject_domain="SUBJ%d" % i, subject_sid=NULL_SID) for i in range(5)]
        got = self.assertSpec(recs)
        self.assertEqual(set(got), {"?\\bob"})          # one account: no spray (threshold 5)
        self.assertFalse(any(a.startswith("subj") for a in got))
        recs = [raw("bob", None, subject="svc", subject_domain="SUBJ%d" % i, subject_sid=NULL_SID) for i in range(5)]
        self.assertEqual(set(self.assertSpec(recs)), {"?\\bob"})

    def test_subject_domain_never_used(self):
        # user.domain holds the subject's domain here and user.id == user.target.id: still unknown
        d = decode("WIN-LAB1", raw("bob", None, subject="bob", subject_domain="SUBJ", subject_sid=NULL_SID))
        self.assertEqual((d["user.domain"], d["user.id"] == d["user.target.id"]), ("SUBJ", True))
        self.assertEqual(acct(d), "?\\bob")
        self.assertEqual(acct(decode("WIN-LAB1", raw("bob", "CONTOSO", subject="alice"))), "contoso\\bob")

    # -- distinct target names still make a spray when their domains are unknown
    def test_distinct_unknown_domain_names_still_count(self):
        recs = [raw("u%d" % i, "CONTOSO") for i in range(5)]                  # network logons, no subject
        got = self.assertSpec(recs)
        self.assertEqual(len(set(got)), 5)
        self.assertTrue(all(a.startswith("?\\") for a in got))
        recs = [raw("m%d" % i, "-", subject="svc") for i in range(5)]
        self.assertEqual(len(set(self.assertSpec(recs))), 5)

    # -- explicit target domains stay distinct
    def test_explicit_target_domains_distinct(self):
        recs = [raw("bob", d, subject="svc") for d in ("CONTOSO", "FABRIKAM", "NORTHWIND", "ADATUM", "TAILSPIN")]
        self.assertEqual(sorted(set(self.assertSpec(recs))),
                         ["adatum\\bob", "contoso\\bob", "fabrikam\\bob", "northwind\\bob", "tailspin\\bob"])

    def test_explicit_and_unknown_are_two_accounts(self):
        got = self.assertSpec([raw("bob", "CONTOSO", subject="svc"), raw("bob", "CONTOSO")])
        self.assertEqual(got, ["contoso\\bob", "?\\bob"])

    # -- documented loss: same name in different domains without a reporting subject
    def test_subject_absent_domains_merge(self):
        got = self.assertSpec([raw("bob", d) for d in ("CONTOSO", "FABRIKAM")])
        self.assertEqual(set(got), {"?\\bob"})

    # -- case folding, local computer, ordinary reporting-subject events
    def test_case_folding(self):
        got = self.assertSpec([raw(n, d, subject="svc") for n, d in (("Bob", "CONTOSO"), ("BOB", "contoso"), ("bob", "Contoso"))])
        self.assertEqual(set(got), {"contoso\\bob"})
        self.assertEqual(set(self.assertSpec([raw("Bob", "X"), raw("bob", "Y")])), {"?\\bob"})

    def test_local_computer(self):
        got = self.assertSpec([raw("Admin", ".", subject="svc"), raw("admin", "WIN-LAB1", subject="svc")],
                              computer="WIN-LAB1.corp.example")
        self.assertEqual(set(got), {"win-lab1\\admin"})
        nohost = decode(None, raw("admin", ".", subject="svc"))
        self.assertEqual(acct(nohost), "?\\admin")
        self.assertEqual(acct(decode("WIN-LAB1", raw("admin", "."))), "?\\admin")   # no subject: not observable

    def test_ordinary_reporting_subject_events(self):
        recs = [raw("t%d" % i, "CONTOSO", subject="WIN10$", subject_domain="WORKGROUP", subject_sid="S-1-5-18")
                for i in range(5)]
        self.assertEqual(sorted(set(self.assertSpec(recs))), ["contoso\\t%d" % i for i in range(5)])
        same = [raw("bob", "CONTOSO", subject="svc%d" % i, subject_domain="D%d" % i) for i in range(5)]
        self.assertEqual(set(self.assertSpec(same)), {"contoso\\bob"})

    # -- missing / empty / "-" target domain, with and without a reporting subject
    def test_missing_empty_dash_target_domain(self):
        for subject in (None, "svc"):
            got = self.assertSpec([raw("bob", td, subject=subject) for td in (None, "", "-", "  ")])
            self.assertEqual(set(got), {"?\\bob"}, subject)
        for v in (None, "", "-", " - ", "   "):
            d = {"user.target.name": "bob", "host.name": "H"}
            if v is not None:
                d["user.target.domain"] = v
            self.assertEqual(acct(d), "?\\bob", repr(v))

    def test_missing_or_dash_user_not_counted(self):
        self.assertIsNone(acct(decode("H", raw("-", "CONTOSO", subject="svc"))))
        self.assertIsNone(spec("H", raw("-", "CONTOSO", subject="svc")))
        self.assertIsNone(acct({"user.target.domain": "CONTOSO"}))

    def test_observed_rc2_shapes(self):
        # decoded documents of the 5.0.0-rc2 run (evidence/2026-11-22-rc2/p2.json), identity fields only
        smb = {"host.name": "WIN-LAB", "user.domain": "WCPOTHERDOM", "user.id": NULL_SID, "user.name": "wcpt-p2-smb",
               "user.target.id": NULL_SID, "user.target.name": "wcpt-p2-smb"}
        logonuser = {"host.name": "WIN-LAB", "user.domain": "WIN-LAB", "user.id": "S-1-5-21-1-2-3-500",
                     "user.name": "admin", "user.target.domain": "WCPOTHERDOM", "user.target.id": NULL_SID,
                     "user.target.name": "wcpt-p2-t1"}
        self.assertEqual(acct(smb), "?\\wcpt-p2-smb")
        self.assertEqual(acct(logonuser), "wcpotherdom\\wcpt-p2-t1")

    def test_flattened_and_list_values(self):
        self.assertEqual(acct({"user.target.name": ["Bob"], "user.target.domain": "CONTOSO"}), "contoso\\bob")
        self.assertEqual(acct({"user": {"target": {"name": "Bob", "domain": ["CONTOSO"]}}}), "contoso\\bob")

    def test_painless_does_not_read_subject_fields(self):
        src = I.PAINLESS_WINDOWS_TARGET_ACCOUNT
        for f in ("'user.domain'", "'user.id'", "'user.target.id'", "'user.name'"):
            self.assertNotIn(f, src)
        self.assertIn("'user.target.domain'", src)


class TestRendering(unittest.TestCase):
    def setUp(self):
        _r, cs = S.load_content(PACK)
        self.corrs = {c.name: c for c in cs}
        self.prof = C.load_profile(os.path.join(PACK, "pack.yml"))

    def render(self, name):
        return A.render_monitor(self.corrs[name], C.settings_for(self.prof, name), self.prof["version"])

    def test_windows_spray_uses_derived_account(self):
        m = self.render("wcp_windows_password_spray")
        q = m["inputs"][0]["search"]["query"]
        sm = q["aggregations"]["wcp_groups"]["aggregations"]["wcp_score"]["scripted_metric"]
        self.assertTrue(sm["map_script"]["source"].startswith("String wcpFirst(def d, String f)"))
        self.assertIn("v = wcpRealm + '\\\\' + wcpName;", sm["map_script"]["source"])
        self.assertNotIn("params.vf", sm["map_script"]["source"])
        self.assertEqual(sm["params"]["vf"], "")
        self.assertTrue(sm["params"]["distinct"])
        filt = q["query"]["bool"]["filter"]
        self.assertIn({"exists": {"field": "user.target.name"}}, filt)
        self.assertNotIn({"exists": {"field": "wcp.windows_target_account"}}, filt)
        # the subject-side fields are read only through the guarded derivation
        src = sm["map_script"]["source"]
        self.assertNotIn("'user.name'", src)

    def test_other_monitors_use_shared_map_script(self):
        for name in ("wcp_ssh_bruteforce", "wcp_ssh_password_spray", "wcp_windows_failed_logon_burst"):
            sm = self.render(name)["inputs"][0]["search"]["query"]["aggregations"]["wcp_groups"]["aggregations"][
                "wcp_score"]["scripted_metric"]
            self.assertEqual(sm["map_script"]["source"], A.PAINLESS_MAP, name)

    def test_virtual_field_rules(self):
        base = {"title": "b", "id": "11111111-1111-4111-8111-111111111111", "name": "t_base", "taxonomy": "wcs",
                "detection": {"sel": {"wcp.windows_target_account": "x"}, "condition": "sel"}}
        with self.assertRaisesRegex(S.SigmaError, "only be a correlation condition.field"):
            S.BaseRule(base, "b.yml")
        corr = {"title": "c", "id": "22222222-2222-4222-8222-222222222222", "name": "t_corr",
                "correlation": {"type": "value_count", "rules": ["t_base"], "group-by": ["source.ip"],
                                "timespan": "5m", "condition": {"field": "wcp.nope", "gte": 3}}}
        with self.assertRaisesRegex(S.SigmaError, "unknown derived value"):
            S.Correlation(corr, "c.yml")
        corr["correlation"]["condition"]["field"] = "wcp.windows_target_account"
        corr["correlation"]["group-by"] = ["wcp.windows_target_account"]
        with self.assertRaisesRegex(S.SigmaError, "cannot be a group-by"):
            S.Correlation(corr, "c.yml")


class TestExpectedMonitors(unittest.TestCase):
    """Golden files: expected/monitors/<name>.monitor.json must equal the current rendering.
    Regenerate with `python -m wcp render --out expected/monitors` when detection code changes, and
    record the commit in expected/README.md."""

    def test_rendering_matches_expected(self):
        _r, cs = S.load_content(PACK)
        prof = C.load_profile(os.path.join(PACK, "pack.yml"))
        d = os.path.join(PACK, "expected", "monitors")
        files = sorted(f for f in os.listdir(d) if f.endswith(".monitor.json"))
        self.assertEqual(files, sorted("%s.monitor.json" % c.name for c in cs))
        for c in cs:
            with open(os.path.join(d, "%s.monitor.json" % c.name), encoding="utf-8") as fh:
                want = json.load(fh)
            got = json.loads(json.dumps(A.render_monitor(c, C.settings_for(prof, c.name), prof["version"])))
            self.assertEqual(got, want, c.name)


if __name__ == "__main__":
    unittest.main()
