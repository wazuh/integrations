"""Windows account-identity scenarios for P1 (replay through the ingestion pipeline) and the
synthetic part of P2 (reporting subject differs from the failed target).

Every record here is **synthetic** (provenance ``synthetic-derived``): built by
``winevents.build_4625`` from the first event of the real capture, with the identity fields set
as listed. Captured events (P2/P3) are recorded separately with provenance ``captured``.

Expected values are written from the specification of ``wcp.windows_target_account``
(README "Grouping", wcp/identity.py docstring), not computed by the implementation. The
specification, in terms of the raw failed-target fields: the realm is TargetDomainName when the
event carries it as the target's domain - the decoders do that when the event has a reporting
subject (``user.target.domain``) - with ``.`` = the reporting computer; otherwise (no reporting
subject, or TargetDomainName missing, empty or ``-``) the realm is unknown, ``?``. The reporting
subject's domain is never a realm.

* ``account``: the account the record must count as (``<realm>\\<user>``, lower case);
* ``score`` / ``alert``: distinct accounts per scenario and whether the spray monitor
  (threshold 5) must alert.

Each scenario is decisive: its alert / no-alert outcome or its account set differs from what a
wrong identity (user name only, case-sensitive, subject domain, the 105573d ``user.domain``
fallback, ...) would give - see ``discriminates``.
"""

SUBJ_ABSENT = {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-"}
MACHINE_SUBJECT = MS = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WCP-WIN-LAB1$", "SubjectDomainName": "WORKGROUP"}
COMPUTER = "WCP-WIN-LAB1.lab.example"   # host.name; realm '.' becomes its first label, lower case


def count_accounts(accounts):
    """Accounts the specification counts in one window (independent of wcp): every account with a known
    realm once; an unknown-realm account ``?\\name`` only if no known-realm account has the same user
    name - a representation change of one failed target is not a second account."""
    accounts = {a for a in accounts if a}
    known = {a for a in accounts if not a.startswith("?\\")}
    known_names = {a.split("\\", 1)[1] for a in known}
    return known | {a for a in accounts if a.startswith("?\\") and a.split("\\", 1)[1] not in known_names}


def same_accounts(sample, expected):
    """True if an account sample names exactly the expected accounts, one entry per account.

    The monitor's sample lists the values in the window when the best score was first reached, so an
    account can appear through either representation of the same failed target: a known-realm entry
    must equal an expected account; an unknown-realm entry ``?\\name`` stands for the expected account
    with that user name (``?\\name`` itself or ``<realm>\\name``). Every expected account must be named
    exactly once."""
    sample, expected = list(sample), sorted(set(expected))
    if len(sample) != len(set(sample)) or len(sample) != len(expected):
        return False
    left = list(expected)
    for v in sorted(sample, key=lambda v: v.startswith("?\\")):      # known-realm entries first
        if not v.startswith("?\\"):
            if v not in left:
                return False
            left.remove(v)
            continue
        name = v.split("\\", 1)[1]
        cand = [a for a in left if a.split("\\", 1)[1] == name]
        if len(cand) != 1:
            return False
        left.remove(cand[0])
    return not left


def rec(user, domain, subject=None, sid="S-1-0-0", computer=COMPUTER, account=None, note=None):
    """One record: TargetUserName=user, TargetDomainName=domain (None removes the element)."""
    data = dict(subject or SUBJ_ABSENT)
    data.update({"TargetUserName": user, "TargetDomainName": domain, "TargetUserSid": sid})
    r = {"computer": computer, "data": data, "account": account}
    if note:
        r["note"] = note
    return r


def scenarios():
    S = []

    def sc(name, prio, desc, records, discriminates, known_limitation=None):
        accounts = sorted(count_accounts(r["account"] for r in records))
        S.append({"name": name, "priority": prio, "description": desc, "records": records,
                  "provenance": "synthetic-derived", "expected_accounts": accounts,
                  "expected_score": len(accounts), "expected_alert": len(accounts) >= 5,
                  "discriminates": discriminates, "known_limitation": known_limitation})

    # ---------------------------------------------------------------- P1: identity variants
    # explicit target domains (reporting subject present: the decoders set user.target.domain)
    sc("p1_same_name_two_domains", "P1",
       "explicit target domains: bob in CONTOSO and in FABRIKAM plus 3 other CONTOSO users: 5 accounts",
       [rec("bob", "CONTOSO", subject=MS, account="contoso\\bob"), rec("bob", "FABRIKAM", subject=MS, account="fabrikam\\bob"),
        rec("alice", "CONTOSO", subject=MS, account="contoso\\alice"),
        rec("carol", "CONTOSO", subject=MS, account="contoso\\carol"),
        rec("dave", "CONTOSO", subject=MS, account="contoso\\dave")],
       "alert only if the domain is part of the account (user name only: 4, no alert)")
    sc("p1_same_name_five_domains", "P1",
       "explicit target domains: the same user name in five domains: 5 accounts",
       [rec("bob", d, subject=MS, account="%s\\bob" % d.lower())
        for d in ("CONTOSO", "FABRIKAM", "NORTHWIND", "ADATUM", "TAILSPIN")],
       "user name only: 1, no alert")
    sc("p1_missing_target_domain", "P1",
       "TargetDomainName absent, '-' or empty (subject present): realm '?'; ?\\bob and contoso\\bob in one window "
       "count once, so 3 accounts",
       [rec("bob", None, subject=MS, account="?\\bob"), rec("bob", "CONTOSO", subject=MS, account="contoso\\bob"),
        rec("alice", "-", subject=MS, account="?\\alice"), rec("alice", "CONTOSO", subject=MS, account="contoso\\alice"),
        rec("carol", "", subject=MS, account="?\\carol")],
       "unknown realm counted as its own account (representation keys): 5, alert")
    sc("p1_case_variants", "P1",
       "five spellings of CONTOSO\\admin: one account",
       [rec(u, d, subject=MS, account="contoso\\admin") for u, d in (("admin", "CONTOSO"), ("Admin", "contoso"),
                                                                    ("ADMIN", "Contoso"), ("aDmin", "CONTOSO"),
                                                                    ("admiN", "cONTOSO"))],
       "case-sensitive identity: 5, alert")
    sc("p1_local_computer_realm", "P1",
       "'.\\admin', 'WCP-WIN-LAB1\\admin' and 'wcp-win-lab1\\admin' on that computer are one account; "
       "plus 2 other local users: 3 accounts",
       [rec("admin", ".", subject=MS, account="wcp-win-lab1\\admin"),
        rec("admin", "WCP-WIN-LAB1", subject=MS, account="wcp-win-lab1\\admin"),
        rec("Admin", "wcp-win-lab1", subject=MS, account="wcp-win-lab1\\admin"),
        rec("u1", ".", subject=MS, account="wcp-win-lab1\\u1"), rec("u2", ".", subject=MS, account="wcp-win-lab1\\u2")],
       "'.' kept as its own realm: 4; case-sensitive: 5, alert")
    sc("p1_local_realm_alert", "P1",
       "five local users written with realm '.': 5 accounts, all in realm wcp-win-lab1",
       [rec("loc%d" % i, ".", subject=MS, account="wcp-win-lab1\\loc%d" % i) for i in range(5)],
       "'.' or host realm unresolved still gives 5; checks the realm text in the alert sample")
    sc("p1_local_vs_domain", "P1",
       "'.\\admin' and 'CONTOSO\\admin' are different accounts; 3 more domain users: 5",
       [rec("admin", ".", subject=MS, account="wcp-win-lab1\\admin"),
        rec("admin", "CONTOSO", subject=MS, account="contoso\\admin"),
        rec("x1", "CONTOSO", subject=MS, account="contoso\\x1"), rec("x2", "CONTOSO", subject=MS, account="contoso\\x2"),
        rec("x3", "CONTOSO", subject=MS, account="contoso\\x3")],
       "user name only: 4, no alert")
    # no reporting subject (network logons): TargetDomainName is in user.domain, not attributable -> '?'
    sc("p1_no_subject_same_name_merges", "P1",
       "no reporting subject: bob in five domains is one unknown-domain account (documented loss)",
       [rec("bob", d, account="?\\bob") for d in ("CONTOSO", "FABRIKAM", "NORTHWIND", "ADATUM", "TAILSPIN")],
       "105573d user.domain fallback or raw TargetDomainName: 5, alert")
    sc("p1_no_subject_distinct_names", "P1",
       "no reporting subject: five distinct user names with unknown domains still make a spray",
       [rec("n%d" % i, "CONTOSO", account="?\\n%d" % i) for i in range(5)],
       "dropping unknown-realm accounts: 0, no alert; the sample realm differs from the fallback (contoso)")
    sc("p1_target_domain_representations", "P1",
       "missing, empty and '-' TargetDomainName, with and without a reporting subject: one account ?\\bob",
       [rec("bob", None, subject=MS, account="?\\bob"), rec("bob", "", subject=MS, account="?\\bob"),
        rec("bob", "-", subject=MS, account="?\\bob"), rec("bob", None, account="?\\bob"),
        rec("bob", "-", account="?\\bob")],
       "'-' or '' taken as a realm: 2-3 accounts in the sample")

    # ---------------------------------------------------------------- P2: reporting subject (synthetic)
    sc("p2_subject_present_distinct_targets", "P2",
       "one reporting subject (WORKGROUP\\WCP-WIN-LAB1$), five target accounts in CONTOSO",
       [rec("t%d" % i, "CONTOSO", subject=MS, account="contoso\\t%d" % i) for i in range(5)],
       "counting the subject: 1, no alert; subject domain as realm: sample shows workgroup\\")
    subjects = [{"SubjectUserSid": "S-1-5-21-1-2-3-%d" % (1100 + i), "SubjectUserName": "svc%d" % i,
                 "SubjectDomainName": "SUBJ%d" % i} for i in range(5)]
    sc("p2_distinct_subjects_same_target", "P2",
       "five different reporting subjects, all failing for CONTOSO\\bob: one account",
       [rec("bob", "CONTOSO", subject=s, account="contoso\\bob") for s in subjects],
       "counting subjects or using the subject domain: 5, alert")
    sc("p2_subject_present_target_domain_missing", "P2",
       "subject present (WORKGROUP), TargetDomainName '-': realm '?', never the subject domain",
       [rec("m%d" % i, "-", subject=MS, account="?\\m%d" % i) for i in range(5)],
       "subject domain as realm: sample shows workgroup\\m0...")
    sc("p2_subject_present_and_absent_counts_once", "P2",
       "CONTOSO\\bob with a reporting subject (contoso\\bob) and without one (?\\bob) is one account; "
       "3 more: 4",
       [rec("bob", "CONTOSO", account="?\\bob"), rec("bob", "CONTOSO", subject=MS, account="contoso\\bob"),
        rec("c1", "CONTOSO", account="?\\c1"), rec("c2", "CONTOSO", subject=MS, account="contoso\\c2"),
        rec("c3", "CONTOSO", account="?\\c3")],
       "representation keys (4564e849): 5, alert")
    mixed = []
    for n in ("alice", "bob", "carol"):
        mixed += [rec(n, "CONTOSO", account="?\\" + n), rec(n, "CONTOSO", subject=MS, account="contoso\\" + n)]
    sc("p2_mixed_shapes_three_accounts", "P2",
       "CONTOSO\\alice, \\bob, \\carol each without and with a reporting subject: 3 actual accounts, no spray",
       mixed, "representation keys (4564e849): 6, alert")
    sc("p2_mixed_shapes_five_names", "P2",
       "five distinct user names across both shapes and missing/'-' domains: 5 accounts, spray",
       [rec("u0", "CONTOSO", account="?\\u0"), rec("u1", "CONTOSO", subject=MS, account="contoso\\u1"),
        rec("u2", None, account="?\\u2"), rec("u3", "-", subject=MS, account="?\\u3"), rec("u4", "-", account="?\\u4")],
       "dropping unknown-realm accounts: 1, no alert")
    null_sid_subject = [{"SubjectUserSid": "S-1-0-0", "SubjectUserName": "svc", "SubjectDomainName": "SUBJ%d" % i}
                        for i in range(5)]
    sc("p2_ambiguous_subject_domain", "P2",
       "subject name with SubjectUserSid S-1-0-0, TargetDomainName '-', five subject domains, one target name: "
       "one account ?\\bob, no spray (the defect found on 5.0.0-rc2 with 105573d)",
       [rec("bob", "-", subject=s, account="?\\bob") for s in null_sid_subject],
       "subject domain as realm (105573d fallback): 5, alert")
    sc("p2_ambiguous_no_target_domain_element", "P2",
       "as above with the TargetDomainName element absent: one account ?\\bob",
       [rec("bob", None, subject=s, account="?\\bob") for s in null_sid_subject],
       "subject domain as realm (105573d fallback): 5, alert")
    return S


def all_records():
    for s in scenarios():
        for r in s["records"]:
            yield s, r
