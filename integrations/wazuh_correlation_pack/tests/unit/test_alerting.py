import json
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)

from wcp import alerting as A  # noqa: E402
from wcp import config as C  # noqa: E402
from wcp import sigma as S  # noqa: E402

S_ = 1000
W = 120 * S_


def brute(events, window_ms, distinct=False):
    """Obvious O(n^2) definition: best over windows starting at each event of [t, t+W)."""
    seen, q = set(), []
    for e in sorted(events, key=lambda e: e[0]):
        if e[2] is not None:
            if e[2] in seen:
                continue
            seen.add(e[2])
        q.append(e)
    best = 0
    for a in q:
        inwin = [e for e in q if a[0] <= e[0] < a[0] + window_ms]
        score = len({e[1] for e in inwin if e[1] is not None}) if distinct else len(inwin)
        best = max(best, score)
    return best


class TestSlidingWindow(unittest.TestCase):
    def ev(self, secs, value=None, ident=None):
        return [(int(s * S_), value, ident) for s in secs]

    def test_below_at_above_threshold(self):
        self.assertEqual(A.sliding_score(self.ev(range(0, 7 * 10, 10)), W)[0], 7)
        self.assertEqual(A.sliding_score(self.ev(range(0, 8 * 10, 10)), W)[0], 8)
        self.assertEqual(A.sliding_score(self.ev(range(0, 9 * 10, 10)), W)[0], 9)

    def test_window_boundary_is_half_open(self):
        # 8 events spanning exactly 120 s: first and last are NOT in one 120 s window
        evs = self.ev([0, 20, 40, 60, 80, 100, 110, 120])
        self.assertEqual(A.sliding_score(evs, W)[0], 7)
        # spanning 119.999 s: all 8 in one window
        evs = [(0, None, None)] + self.ev([20, 40, 60, 80, 100, 110]) + [(119999, None, None)]
        self.assertEqual(A.sliding_score(evs, W)[0], 8)

    def test_spread_outside_window(self):
        # 8 events but every pair of 8 spans more than 2 minutes
        evs = self.ev([i * 20 for i in range(8)] )  # 0..140 s
        self.assertEqual(A.sliding_score(evs, W)[0], 6)

    def test_window_not_widened_by_lookback(self):
        # 4 events, then 4 more 3 minutes later: lookback may cover both, the window does not
        evs = self.ev([0, 1, 2, 3, 180, 181, 182, 183])
        self.assertEqual(A.sliding_score(evs, W)[0], 4)

    def test_distinct_values(self):
        users = ["u%d" % i for i in range(5)]
        evs = [(i * S_, users[i % 5], None) for i in range(20)]
        self.assertEqual(A.sliding_score(evs, W, distinct=True)[0], 5)
        # same user repeated: distinct is 1, event count is 10
        evs = [(i * S_, "alice", None) for i in range(10)]
        self.assertEqual(A.sliding_score(evs, W, distinct=True)[0], 1)
        self.assertEqual(A.sliding_score(evs, W)[0], 10)

    def test_distinct_window_slides(self):
        # b(10) and c(130) are exactly 120 s apart: never in one half-open 120 s window
        evs = [(0, "a", None), (10 * S_, "b", None), (130 * S_, "c", None), (140 * S_, "d", None)]
        self.assertEqual(A.sliding_score(evs, W, distinct=True)[0], 2)
        # move c and d to 129 s and 129.5 s: b, c, d fit in [10 s, 130 s)
        evs[2] = (129 * S_, "c", None)
        evs[3] = (129500, "d", None)
        self.assertEqual(A.sliding_score(evs, W, distinct=True)[0], 3)

    def test_identity_dedup(self):
        evs = [(i * S_, None, "id%d" % (i % 4)) for i in range(8)]
        best, _s, _e, dups = A.sliding_score(evs, W)
        self.assertEqual(best, 4)
        self.assertEqual(dups, 4)
        # identical content without identity is NOT collapsed
        evs = [(5 * S_, None, None)] * 8
        self.assertEqual(A.sliding_score(evs, W)[0], 8)

    def test_max_events_keeps_latest(self):
        evs = self.ev(range(100))
        self.assertEqual(A.sliding_score(evs, W, max_events=10)[0], 10)

    def test_random_against_bruteforce(self):
        rnd = random.Random(1234)
        for _ in range(300):
            n = rnd.randint(0, 40)
            evs = [(rnd.randint(0, 600) * S_ + rnd.choice([0, 999]), rnd.choice(["a", "b", "c", "d", None]),
                    rnd.choice([None, None, "x%d" % rnd.randint(0, 30)])) for _ in range(n)]
            for distinct in (False, True):
                self.assertEqual(A.sliding_score(evs, W, distinct)[0], brute(evs, W, distinct), msg=(evs, distinct))


CORR = {
    "title": "SSH brute force", "id": "22222222-2222-4222-8222-222222222222", "name": "t_corr",
    "correlation": {"type": "event_count", "rules": ["t_base"], "group-by": ["wazuh.agent.id", "source.ip"],
                    "timespan": "2m", "condition": {"gte": 8}}, "level": "high"}
BASE = {"title": "b", "id": "11111111-1111-4111-8111-111111111111", "name": "t_base", "taxonomy": "wcs",
        "detection": {"sel": {"event.reason": "Failed password"}, "condition": "sel"}}


def corr_obj(**over):
    doc = json.loads(json.dumps(CORR))
    doc["correlation"].update(over)
    c = S.Correlation(doc, "c.yml")
    c.rules = [S.BaseRule(BASE, "b.yml")]
    return c


B = "\\"


def acc(realm, name):
    return realm + B + name


def painless_unknown_realm(events, w):
    """Line-by-line transliteration of the incremental counting in A.PAINLESS_REDUCE_UNKNOWN_REALM."""
    q = sorted(events, key=lambda e: e[0])
    best, i, cnt, known, unknown = 0, 0, {}, {}, set()
    n_known = n_unknown_only = 0
    for j in range(len(q)):
        tj, vj = q[j][0], q[j][1]
        if vj is not None:
            c0 = cnt.get(vj, 0)
            cnt[vj] = c0 + 1
            if c0 == 0:
                r, nm = vj.split(B, 1)
                if r == "?":
                    unknown.add(nm)
                    if known.get(nm, 0) == 0:
                        n_unknown_only += 1
                else:
                    n_known += 1
                    kn = known.get(nm, 0)
                    if kn == 0 and nm in unknown:
                        n_unknown_only -= 1
                    known[nm] = kn + 1
        while tj - q[i][0] >= w:
            vi = q[i][1]
            if vi is not None:
                c = cnt[vi] - 1
                if c == 0:
                    del cnt[vi]
                    r, nm = vi.split(B, 1)
                    if r == "?":
                        unknown.discard(nm)
                        if known.get(nm, 0) == 0:
                            n_unknown_only -= 1
                    else:
                        n_known -= 1
                        kn = known[nm] - 1
                        if kn == 0:
                            del known[nm]
                            if nm in unknown:
                                n_unknown_only += 1
                        else:
                            known[nm] = kn
                else:
                    cnt[vi] = c
            i += 1
        best = max(best, n_known + n_unknown_only)
    return best


class TestUnknownRealmCounting(unittest.TestCase):
    """Windows accounts whose realm may be unknown ('?'): a failed target seen through both decoded
    shapes is one account; explicit domains stay distinct; distinct user names always count."""
    W = 120000

    def score(self, values, spacing=1000):
        return A.sliding_score([(k * spacing, v, None) for k, v in enumerate(values)], self.W, distinct=True,
                               unknown_realm=True)[0]

    def test_three_accounts_in_both_shapes_count_three(self):
        vals = []
        for n in ("alice", "bob", "carol"):
            vals += [acc("?", n), acc("contoso", n)]
        self.assertEqual(self.score(vals), 3)
        self.assertEqual(A.sliding_score([(k, v, None) for k, v in enumerate(vals)], self.W, distinct=True)[0], 6)

    def test_five_distinct_names_still_count(self):
        vals = [acc("?", "u0"), acc("contoso", "u1"), acc("?", "u2"), acc("?", "u3"), acc("fabrikam", "u4")]
        self.assertEqual(self.score(vals), 5)

    def test_explicit_domains_stay_distinct(self):
        vals = [acc(d, "bob") for d in ("contoso", "fabrikam", "northwind", "adatum", "tailspin")]
        self.assertEqual(self.score(vals), 5)
        self.assertEqual(self.score(vals + [acc("?", "bob")]), 5)     # unknown bob merges, adds nothing

    def test_unknown_only_names_count(self):
        self.assertEqual(self.score([acc("?", "n%d" % k) for k in range(5)]), 5)
        self.assertEqual(self.score([acc("?", "bob")] * 4), 1)

    def test_unknown_counts_again_when_the_known_one_leaves_the_window(self):
        ev = [(0, acc("contoso", "bob"), None), (130000, acc("?", "bob"), None), (131000, acc("?", "x"), None)]
        self.assertEqual(A.sliding_score(ev, self.W, distinct=True, unknown_realm=True)[0], 2)
        ev = [(0, acc("contoso", "bob"), None), (10000, acc("?", "bob"), None)]
        self.assertEqual(A.sliding_score(ev, self.W, distinct=True, unknown_realm=True)[0], 1)

    def test_score_function(self):
        got = A.unknown_realm_score([acc("contoso", "alice"), acc("?", "alice"), acc("?", "bob"), acc("fabrikam", "bob"),
                                     acc("contoso", "bob"), acc("?", "carol")])
        self.assertEqual(sorted(got), [acc("?", "carol"), acc("contoso", "alice"), acc("contoso", "bob"),
                                       acc("fabrikam", "bob")])

    def test_incremental_painless_logic_equals_reference(self):
        rnd = random.Random(20261123)
        names, realms = ["a", "b", "c", "d", "e", "f"], ["?", "contoso", "fabrikam", "?"]
        for _trial in range(600):
            n = rnd.randint(1, 40)
            ev = [(rnd.randint(0, 400000), acc(rnd.choice(realms), rnd.choice(names)), None) for _ in range(n)]
            ev.sort(key=lambda e: e[0])
            ref = A.sliding_score(ev, self.W, distinct=True, unknown_realm=True)[0]
            self.assertEqual(painless_unknown_realm(ev, self.W), ref, ev)

    def test_only_the_windows_spray_monitor_uses_the_variant(self):
        rules, corrs = S.load_content(PACK)
        prof = C.load_profile(os.path.join(PACK, "pack.yml"))
        for c in corrs:
            m = A.render_monitor(c, C.settings_for(prof, c.name), prof["version"])
            red = m["inputs"][0]["search"]["query"]["aggregations"]["wcp_groups"]["aggregations"]["wcp_score"][
                "scripted_metric"]["reduce_script"]["source"]
            want = A.PAINLESS_REDUCE_UNKNOWN_REALM if c.name == "wcp_windows_password_spray" else A.PAINLESS_REDUCE
            self.assertEqual(red, want, c.name)
        self.assertIn("indexOf('" + B + B + "')", A.PAINLESS_REDUCE_UNKNOWN_REALM)   # Painless literal for one backslash


class TestMonitor(unittest.TestCase):
    def settings(self, **kw):
        prof = {"pack": "p", "version": "0.1.0", "defaults": kw}
        return C.settings_for(prof, "t_corr")

    def test_shape(self):
        m = A.render_monitor(corr_obj(), self.settings(), "0.1.0")
        self.assertEqual(m["monitor_type"], "bucket_level_monitor")
        self.assertEqual(m["schedule"], {"period": {"interval": 1, "unit": "MINUTES"}})
        q = m["inputs"][0]["search"]["query"]
        rng = q["query"]["bool"]["filter"][-1]["range"]["event.start"]
        # lookback = window 120 + lateness 120 + interval 60
        self.assertEqual(rng["gte"], "{{period_end}}||-300s")
        comp = q["aggregations"]["wcp_groups"]["composite"]
        self.assertEqual([list(s)[0] for s in comp["sources"]], ["g0_wazuh_agent_id", "g1_source_ip"])
        params = q["aggregations"]["wcp_groups"]["aggregations"]["wcp_score"]["scripted_metric"]["params"]
        self.assertEqual(params["window_ms"], 120000)
        self.assertFalse(params["distinct"])
        trig = m["triggers"][0]["bucket_level_trigger"]
        self.assertEqual(trig["condition"]["script"]["source"], "params.score >= 8")
        self.assertEqual(trig["condition"]["buckets_path"], {"score": "wcp_score.value"})
        self.assertEqual(trig["severity"], "2")
        self.assertEqual(A.marker_of(m)["pack"], "wazuh_correlation_pack")
        self.assertEqual(trig["actions"], [])

    def test_group_fields_required(self):
        m = A.render_monitor(corr_obj(), self.settings(), "0.1.0")
        filt = m["inputs"][0]["search"]["query"]["query"]["bool"]["filter"]
        self.assertIn({"exists": {"field": "wazuh.agent.id"}}, filt)
        self.assertIn({"exists": {"field": "source.ip"}}, filt)

    def test_hash_stable_and_sensitive(self):
        a = A.render_monitor(corr_obj(), self.settings(), "0.1.0")
        b = A.render_monitor(corr_obj(), self.settings(), "0.1.0")
        c = A.render_monitor(corr_obj(), self.settings(interval="2m"), "0.1.0")
        self.assertEqual(A.marker_of(a)["content_hash"], A.marker_of(b)["content_hash"])
        self.assertNotEqual(A.marker_of(a)["content_hash"], A.marker_of(c)["content_hash"])

    def test_actions_policy(self):
        s = self.settings(actions=[{"name": "n", "channel_id": "abc", "notify_on": ["NEW", "COMPLETED"]}])
        m = A.render_monitor(corr_obj(), s, "0.1.0")
        act = m["triggers"][0]["bucket_level_trigger"]["actions"][0]
        self.assertEqual(act["action_execution_policy"]["action_execution_scope"]["per_alert"]["actionable_alerts"],
                         ["NEW", "COMPLETED"])

    def test_settings_validation(self):
        with self.assertRaises(C.ConfigError):
            self.settings(interval="30s")
        with self.assertRaises(C.ConfigError):
            self.settings(bogus=1)
        with self.assertRaises(C.ConfigError):
            self.settings(actions=[{"name": "x"}])
        self.assertEqual(self.settings(allowed_lateness="0s")["allowed_lateness_s"], 0)


if __name__ == "__main__":
    unittest.main()
