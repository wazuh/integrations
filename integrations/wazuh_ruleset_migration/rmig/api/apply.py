"""``apply`` and ``rollback``.

``apply``: reconcile ``state.json`` with the ownership mark, stop before any
write on a name conflict, a foreign root decoder, an indexed ``unclassified``
or pending foreign changes; then, per integration of ``out/`` (``wazuh4-base``
first): create or update in draft, set ``root_decoder`` once by
read-modify-write, and promote draft -> test **that integration only** (its
ids and the checked policy). An integration the engine refuses is set aside
(removed from the tool's draft content) with the engine's message, whether
it refuses the promotion or answers 400 to a create or update; apply goes on
with the next integration and exits 1.

``rollback``: remove the tool's content from draft and promote the removals to
test, except ``wazuh4-base`` while its root is the policy's ``root_decoder``.
What ``activate`` put in custom stays there and is listed; with ``--yes`` the
tool's detectors are deleted and the removals are promoted test -> custom too
(the same promotion ``activate`` makes, own changes only).
"""

import sys
import time

from .. import limits as L

from .client import ApiError
from .content import (CHANGE_KEY, CHANGE_LISTS, KEY_TYPE, PATH, BASE, Ownership, Snapshot, empty_changes,
                      foreign_changes, other_tool_changes, policy_differences, policy_put_body, read_policy,
                      refresh)
from . import shared_root as SR
from .outdir import BASE_KEY, Out, doc_title
from .report import stop_entry, stop_line, update_report, write_mapping_applied
from .state import State, now, paths
from ..textsafe import plain

PROMOTE = BASE + "/promote"
DELETE_ORDER = ("rule", "decoder", "kvdb", "integration")
CONTENT_TYPES = ("rule", "decoder", "kvdb")
# Security Analytics keeps the integration's log type while a copy of one of its
# rules is in another space: the DELETE answers 500 with this text (seen against a live
# indexer, tests/data/api/recorded/07-rollback.json). The integration is deleted after the next promotion.
LOGTYPE_BUSY = "cannot be deleted because active rules exist"
PARKED_WAITS = (2, 5, 10)  # seconds rollback waits before trying a parked integration again

ROOT_OWNED_TEXT = ("The draft policy already has root_decoder %s (below), which the tool did not set and cannot "
                   "share: %s. Nothing was changed. The tool's decoders hang only from a root that does what the "
                   "standard decoder/core-wazuh-message/0 does. Choose by hand: migrate into a policy without a "
                   "custom root decoder, or merge the generated decoders with that root by hand (see the recipe).")

ROOT_CHANGED_TEXT = ("The tool's decoders hang from the standard root decoder %s (%s), and that decoder has changed "
                     "since apply: %s. Nothing was changed. Check the change in the standard content; to apply this "
                     "out/ again, run rollback, then apply (the tool then checks the new root from the start).")

ROOT_MOVED_TEXT = ("The tool's decoders were applied under the draft policy root_decoder %s (%s), and the draft policy "
                   "root_decoder is now %s: nothing was changed. Run rollback, then apply again.")

CATCHALL_TEXT = ("The draft policy root_decoder %s is the standard decoder/core-wazuh-message/0 and the tool can hang "
                 "its decoders from it, but the predecoder needs a check that limits it to the migrated logs, and "
                 "these decoders give it none (below): it would take every event before the customer's decoders. "
                 "Nothing was changed.")

FOREIGN_TEXT = ("The draft space has pending changes that the tool did not make. Promote or discard them first, "
                "or pass --include-foreign-changes to promote them together (recorded).")


FOREIGN_YES_TEXT = ("The %s space has changes that the tool did not make (listed below: someone else's content, or a "
                    "policy change). rollback --yes changes custom, where the manager runs, and never carries those "
                    "changes there, not even with --include-foreign-changes: nothing was changed. Promote or discard "
                    "them first, or run rollback without --yes.")


class Refused(Exception):
    """The content manager answered 400 (or 413) to a create or update of the tool's
    content (the engine refused the asset): the integration is set aside."""

    def __init__(self, what, exc):
        self.message = "%s: %s" % (what, exc.server_message)
        super().__init__(self.message)


class Stop(Exception):
    def __init__(self, entry, exit_code=2):
        super().__init__(entry["text"])
        self.entry = entry
        self.exit_code = exit_code


class Runner:
    """Shared by apply, rollback, verify and activate: the client, the work
    directory, the dry-run switch and the call log."""

    def __init__(self, client, workdir, out_dir=None, dry_run=False, stream=None):
        self.client = client
        self.workdir = workdir
        self.paths = paths(workdir)
        self.out_dir = out_dir or self.paths["out"]
        self.dry_run = dry_run
        self.stream = stream or sys.stdout
        self._dry_seq = 0

    def say(self, text):
        print(plain(text), file=self.stream)  # names and server messages: no escape sequence reaches the terminal

    def write(self, method, path, body, what):
        """Every write goes through here: printed, and not sent on --dry-run."""
        self.say("%s%s %s  (%s)" % ("[dry-run] " if self.dry_run else "", method, path, what))
        if self.dry_run:
            self._dry_seq += 1
            return {"message": "dry-run-%d" % self._dry_seq, "status": 200}
        return self.client.request(method, path, body)

    def promote_preview(self, space):
        # The preview is computed from the content indices: without a refresh, writes made just before
        # (a DELETE right before promoting) are not in it yet and stay pending in draft (5.0.0-rc1).
        if not self.dry_run:
            refresh(self.client)
        res = self.client.request("GET", PROMOTE, params={"space": space})
        return res.get("changes") or {}

    def section(self, command):
        return {"command": command, "when": now(), "dry_run": self.dry_run, "result": "", "stops": [],
                "integrations": [], "operations": [], "notes": []}


def _lid_integration(lid, out, state):
    e = state.get(lid)
    if e and e.get("integration"):
        return e["integration"]
    if out is not None and lid in out.by_local:
        return out.by_local[lid].integration
    return None


def _ids_of(key, own, out, state):
    """Server ids (any space) the tool owns for an integration key."""
    return {sid for sid, lid in own.owned.items() if _lid_integration(lid, out, state) == key}


def _select(changes, ids):
    sel = empty_changes()
    for k in CHANGE_LISTS:
        if k == "policy":
            continue
        sel[k] = [op for op in changes.get(k) or [] if op.get("id") in ids]
    return sel


def _is_empty(sel):
    return not any(sel[k] for k in CHANGE_LISTS)


def _merge_foreign(sel, changes, own):
    for k in CHANGE_LISTS:
        if k == "policy":
            continue
        have = {op.get("id") for op in sel[k]}
        sel[k].extend(op for op in changes.get(k) or [] if not own.is_own(op.get("id")) and op.get("id") not in have)


def _new_info(key):
    return {"key": key, "status": "", "created": 0, "updated": 0, "unchanged": 0, "deleted": 0, "message": None}


class Apply:
    def __init__(self, runner, include_foreign=False, accept_unclassified=False, engine_limits=None):
        self.r = runner
        self.client = runner.client
        self.include_foreign = include_foreign
        self.accept_unclassified = accept_unclassified
        self.engine_limits = engine_limits
        self.sec = runner.section("apply")
        self.foreign_included = False

    # -- entry point ---------------------------------------------------------
    def run(self):
        r = self.r
        self.out = Out(r.out_dir)
        self.state = State.load(r.workdir)
        self.snap = Snapshot(self.client)
        self.own = Ownership(self.snap, self.state, set(self.out.by_local) | set(self.state.resources))
        self.shared = None  # {"server_id", "name"}: the draft policy root the tool's decoders hang from
        try:
            self.prechecks()
        except Stop as stop:
            return self.finish("stopped", stop)
        if not self.r.dry_run:
            self.state.data["shared_root"] = dict(self.shared, when=now()) if self.shared else None
        exit_code = 0
        try:
            for integ in self.out.integrations:
                info = self.apply_integration(integ)
                self.sec["integrations"].append(info)
                if info["status"] == "set aside":
                    exit_code = 1
            self.order_policy()
            self.retire_missing()
            self.retire_stale_base()
        except Stop as stop:
            return self.finish("stopped", stop)
        aside = sum(1 for i in self.sec["integrations"] if i["status"] == "set aside")
        return self.finish("set aside: %d" % aside if exit_code else "ok", None, exit_code)

    def finish(self, result, stop, exit_code=None):
        if stop is not None:
            self.sec["stops"].append(stop.entry)
            self.r.say(stop_line("apply", stop.entry))
            for it in stop.entry["items"]:
                self.r.say("  - %s" % it)
            exit_code = stop.exit_code
        self.sec["result"] = result
        for n in self.unknown_marked_notes():
            self.sec["notes"].append(n)
        if not self.r.dry_run:
            self.state.data["last_apply"] = self.sec["when"]
            self.state.save()
            n = write_mapping_applied(self.out, self.state, self.r.paths["mapping_applied"])
            self.sec["notes"].append("work/mapping-applied.csv: %d rule(s) with a server id." % n)
            update_report(self.r.paths, "apply", self.sec)
        elif stop is not None:
            # a dry run that stops still explains why in the report (marked as a dry run); state stays as it was
            update_report(self.r.paths, "apply", self.sec)
        self.r.say("apply: %s" % result)
        return exit_code

    def unknown_marked_notes(self):
        return ["%s %s in %s carries the tool's mark with a local id this out/ does not know: left untouched." % (
            rtype, sid, space) for space, rtype, sid in self.own.unknown_marked]

    def record_op(self, op, detail):
        if self.r.dry_run:
            self.sec["operations"].append({"op": op, "command": "apply", "who": "-", "when": "-", "detail": detail})
            return
        self.sec["operations"].append(self.state.operation(op, "apply", detail))

    # -- checks before any write ------------------------------------------------
    def own_root(self):
        if not self.out.root:
            return (self.state.data.get("root_decoder") or {}).get("server_id")
        rd = self.state.data.get("root_decoder") or {}
        if rd.get("server_id"):
            return rd["server_id"]
        return self.own.in_space("draft", self.out.root["local_id"])

    def prechecks(self):
        draft = self.snap.policy.get("draft")
        if draft is None:
            raise Stop(stop_entry(None, "The draft policy was not found in wazuh-threatintel-policies."))
        if self.out.root:
            self.choose_root(draft.get("root_decoder"))
        conflicts = []
        for res in self.out.by_local.values():
            for sid, doc in sorted(self.snap.docs["draft"][res.rtype].items()):
                if doc_title(res.rtype, doc) == res.title and self.own.owned.get(sid) != res.local_id:
                    conflicts.append("%s %r: draft already has %s, not owned by the tool (%s)" % (
                        res.rtype, res.title, sid, res.file))
        self.check_limits()
        if conflicts:
            raise Stop(stop_entry("RM-P-NAME-CONFLICT", "Resources with the same name exist in draft and are not the "
                                  "tool's: nothing was changed. Rename or remove them, then run apply again.", conflicts))
        if self.out.root or self.shared:
            custom = self.snap.policy.get("custom") or {}
            if custom.get("index_unclassified_events"):
                if not self.accept_unclassified:
                    raise Stop(stop_entry("RM-P-UNCLASSIFIED-INDEXED", "The custom policy has index_unclassified_events: "
                                          "true, so events that only match wazuh4-base would be indexed. Set it to false "
                                          "or pass --accept-unclassified-indexing (recorded)."))
                self.record_op("accept-unclassified-indexing", "custom policy has index_unclassified_events: true")
        changes = self.r.promote_preview("draft")
        self.check_foreign(changes)

    def choose_root(self, cur):
        """Which root the tool's decoders hang from. The tool's own root when the draft policy has none or has
        the tool's; the policy root when it is the standard core-wazuh-message (shared mode, recorded in
        state.json); else stop. A change of mode while the tool's content is applied stops: rollback first."""
        mine = self.own_root()
        applied = bool(self.state.resources)
        rec = self.state.data.get("shared_root") or {}
        if applied and rec.get("server_id") and cur != rec["server_id"]:
            raise Stop(stop_entry("RM-P-ROOT-OWNED", ROOT_MOVED_TEXT % (rec["server_id"], rec.get("name") or "-",
                                                                       cur or "empty"),
                                  self.describe_root(cur) if cur else []))
        if not cur or cur == mine:
            return
        if applied and not rec.get("server_id") and mine and self.snap.get("draft", "decoder", mine):
            # the tool's own root is applied and someone else set another root
            raise Stop(stop_entry("RM-P-ROOT-OWNED", ROOT_OWNED_TEXT % (
                cur, "the tool's decoders hang from the tool's own root %s, which is applied" % mine),
                self.describe_root(cur)))
        doc = self.snap.get("draft", "decoder", cur)
        why = SR.compatibility(doc, SR.tool_root_resource(self.out))
        if why and applied and rec.get("server_id") == cur:
            # the standard root the tool's content already hangs from was updated (a new Wazuh version)
            raise Stop(stop_entry("RM-P-ROOT-OWNED", ROOT_CHANGED_TEXT % (cur, rec.get("name") or "-", why),
                                  self.describe_root(cur)))
        if why:
            raise Stop(stop_entry("RM-P-ROOT-OWNED", ROOT_OWNED_TEXT % (cur, why), self.describe_root(cur)))
        siblings = self.root_siblings(doc["name"])
        try:
            notes = SR.share(self.out, doc["name"])
        except SR.GateError as exc:
            raise Stop(stop_entry("RM-P-ROOT-CATCHALL", CATCHALL_TEXT % cur, exc.items))
        self.shared = {"server_id": cur, "name": doc["name"]}
        self.r.say("apply: the tool's decoders hang from the draft policy root_decoder %s (%s); the policy root is "
                   "not changed (RM-P-SHARED-ROOT)" % (cur, doc["name"]))
        self.sec["notes"].append("RM-P-SHARED-ROOT: the tool's decoders hang from the draft policy root_decoder %s "
                                 "(%s), which is the standard one; the tool's own root is not created and the policy "
                                 "root_decoder is not changed. %s" % (cur, doc["name"], " ".join(notes)))
        if siblings:
            # wazuh-core of the standard catalog lists decoder/syslog/0 under core-wazuh-message: no check, it
            # parses every syslog line. The engine tries siblings in the order of the policy's integrations, so
            # order_policy puts the tool's integrations first: the predecoder, limited by its check, is tried
            # before them and the events it does not take go on to them
            shown = siblings[:10] + (["... %d more" % (len(siblings) - 10)] if len(siblings) > 10 else [])
            self.sec["notes"].append("RM-P-SHARED-ROOT: %d decoder(s) of others hang from the same root (%s). The "
                                     "tool's integrations go first in the draft policy so that the predecoder is "
                                     "tried before them." % (len(siblings), "; ".join(shown)))

    def root_siblings(self, root_name):
        """Decoders of draft that the tool does not own and that hang from the policy root: one line each."""
        titles = {}
        for iid, d in self.snap.docs["draft"]["integration"].items():
            for sid in d.get("decoders") or []:
                titles.setdefault(sid, doc_title("integration", d) or iid)
        out = []
        for sid, d in sorted(self.snap.docs["draft"]["decoder"].items()):
            if root_name in (d.get("parents") or []) and not self.own.is_own(sid):
                out.append("decoder %s (%s), integration %s" % (d.get("name") or "-", sid, titles.get(sid, "-")))
        return out

    def base_holder(self):
        """The integration every other one hangs from: the one with the tool's root, or under a shared root the
        one with the predecoder."""
        if self.out.root:
            return self.out.by_local[self.out.root["local_id"]].integration
        if self.out.shared_root:
            return self.out.shared_root["base_integration"]
        return None

    def describe_root(self, sid):
        """The draft policy's root decoder: id, name, title and the integration that lists it."""
        doc = self.snap.get("draft", "decoder", sid) or {}
        title = (doc.get("metadata") or {}).get("title") or "-"
        integ = [doc_title("integration", d) or iid for iid, d in sorted(self.snap.docs["draft"]["integration"].items())
                 if sid in (d.get("decoders") or [])]
        return ["root decoder: id %s, name %s, title %s, integration %s" % (
            sid, doc.get("name") or "-", title, ", ".join(integ) or "-")]

    def check_limits(self):
        """Stop before any write when the draft space would hold more resources than the content manager
        accepts (what is in draft now plus what the tool still has to create there), or a decoder body is
        larger than the indexer accepts."""
        lim = L.values(self.engine_limits)
        over = []
        for rtype, name in (("rule", "max_rules"), ("decoder", "max_decoders"), ("integration", "max_integrations"),
                            ("kvdb", "max_kvdbs")):
            now_ = len(self.snap.docs["draft"][rtype])
            new = sum(1 for res in self.out.by_local.values()
                      if res.rtype == rtype and self.own.in_space("draft", res.local_id) is None)
            if now_ + new > lim[name]:
                over.append("%s: %d in draft now + %d to create = %d, limit %d: %s" % (
                    L.LIMITS[name][1], now_, new, now_ + new, lim[name], L.action(name)))
        for res in sorted(self.out.by_local.values(), key=lambda r: r.file):
            if res.rtype != "decoder":
                continue
            size = L.decoder_body_bytes(res.resource)
            if size > lim["decoder_body_bytes"]:
                over.append("decoder %s (%s): body of %d bytes, limit %d: %s" % (
                    res.title, res.integration, size, lim["decoder_body_bytes"], L.action("decoder_body_bytes")))
        if over:
            raise Stop(stop_entry("RM-P-ENGINE-LIMIT", "The content exceeds limits of the indexer: nothing was "
                                  "changed. Raise the cluster settings (then pass --engine-limit NAME=N), or "
                                  "migrate in parts.", over))

    def check_foreign(self, changes):
        """Stop on foreign resource changes or a foreign policy change, unless
        --include-foreign-changes (recorded once)."""
        foreign = foreign_changes(changes, self.own)
        pol = []
        if changes.get("policy"):
            refresh(self.client)
            pol = policy_differences(read_policy(self.client, "draft"), read_policy(self.client, "test"),
                                     self.own, self.own_root())
        if not foreign and not pol:
            return
        items = ["%s %s %s" % (f["operation"], f["type"], f["id"]) for f in foreign] + ["policy: %s" % d for d in pol]
        if not self.include_foreign:
            raise Stop(stop_entry("RM-P-FOREIGN-POLICY-CHANGE" if pol else None, FOREIGN_TEXT, items))
        if not self.foreign_included:
            self.record_op("include-foreign-changes", "; ".join(items))
            self.foreign_included = True

    # -- per integration ---------------------------------------------------------
    def ensure(self, res, info, integration_id=None):
        """Create or update one resource in draft. Returns ``(server id,
        action)``; an integration's PUT is sent by the caller, which restates
        its lists."""
        sid = self.own.in_space("draft", res.local_id)
        entry = self.state.get(res.local_id)
        if sid is None:
            body = {"resource": res.resource}
            if integration_id is not None:
                body = {"integration": integration_id, "resource": res.resource}
            what = "create %s %s" % (res.rtype, res.title)
            resp = self.write_content("POST", PATH[res.rtype], body, what)
            sid = resp.get("message")
            info["created"] += 1
            self.track(res, sid)
            return sid, "created"
        if entry is None or entry.get("sha256") != res.sha256 or entry.get("server_id") != sid:
            if res.rtype != "integration":
                self.write_content("PUT", "%s/%s" % (PATH[res.rtype], sid), {"resource": res.resource},
                                   "update %s %s" % (res.rtype, res.title))
            info["updated"] += 1
            self.track(res, sid)
            return sid, "updated"
        info["unchanged"] += 1
        return sid, "unchanged"

    def write_content(self, method, path, body, what):
        """A write of the tool's content: a 400 is the engine or Security Analytics refusing it. Security
        Analytics also answers some refusals with 500 "Error in Security Analytics. ..." (a tag without a
        namespace, a condition naming a missing block: seen on 5.0.0-rc1), so those count as refusals too, and
        so does 413 (a body above the indexer's size limit for the type: "Request body exceeds maximum allowed
        size of 50000 bytes for type 'decoder'", seen live; reached when --engine-limit decoder_body_bytes is
        raised above what the indexer accepts)."""
        try:
            return self.r.write(method, path, body, what)
        except ApiError as exc:
            if exc.status in (400, 413) or (exc.status == 500 and "Security Analytics" in (exc.server_message or "")):
                raise Refused(what, exc)
            raise

    def track(self, res, sid):
        self.state.record(res, sid, space="draft")
        self.own.owned[sid] = res.local_id
        self.snap.docs["draft"][res.rtype].setdefault(sid, {"id": sid})

    def apply_integration(self, integ):
        """Create or update one integration and promote it. A 400 to any of
        its writes sets it aside (its own draft content is removed and the
        message kept in the report) and apply goes on with the next one; the
        integration with the root decoder stops apply instead, since the
        others hang from it."""
        info = _new_info(integ.key)
        self.r.say("apply: integration %s" % integ.key)
        try:
            self.write_integration(integ, info)
        except Refused as ref:
            if integ.key == self.base_holder():
                raise Stop(stop_entry(None, "The engine refused content of %s, which holds the root decoder: "
                                      "nothing else can be applied." % integ.key, [ref.message]), exit_code=1)
            self.set_aside(integ.key, ref.message, info)
            return info
        self.promote_integration(integ.key, info)
        return info

    def write_integration(self, integ, info):
        iid, action = self.ensure(integ.me, info)
        existing = self.snap.get("draft", "integration", iid) or {}
        lists = {k: list(existing.get(k) or []) for k in ("kvdbs", "decoders", "rules")}
        for res in integ.kvdbs + integ.decoders:
            sid, _ = self.ensure(res, info, iid)
            key = CHANGE_KEY[res.rtype]
            if sid not in lists[key]:
                lists[key].append(sid)
        mine = [self.state.get(d.local_id)["server_id"] for d in integ.decoders]
        desired = mine + [d for d in lists["decoders"] if d not in mine]
        if action == "updated" or desired != lists["decoders"]:
            body = dict(integ.me.resource)
            body.update({"kvdbs": lists["kvdbs"], "decoders": desired, "rules": lists["rules"]})
            self.write_content("PUT", "%s/%s" % (PATH["integration"], iid), {"resource": body},
                               "update integration %s (metadata and decoder order)" % integ.key)
        if self.out.root and any(d.local_id == self.out.root["local_id"] for d in integ.decoders):
            self.set_root()
        for res in integ.rules:
            self.ensure(res, info, iid)
        if integ.key != BASE_KEY:
            info["deleted"] += self.delete_stale(integ)

    def set_root(self):
        rid = self.state.get(self.out.root["local_id"])["server_id"]
        if self.r.dry_run:
            current = self.snap.policy.get("draft") or {}
        else:
            refresh(self.client)
            current = read_policy(self.client, "draft")
        cur = current.get("root_decoder")
        if cur == rid:
            return
        if cur:
            raise Stop(stop_entry("RM-P-ROOT-OWNED", "The draft policy root_decoder changed to %s during apply; "
                                  "it is never overwritten." % cur, self.describe_root(cur)))
        try:
            self.r.write("PUT", BASE + "/policy/draft", policy_put_body(current, rid),
                         "set root_decoder to the wazuh4-base root (read-modify-write)")
        except ApiError as exc:
            if exc.status == 403:
                raise Stop(stop_entry("RM-P-POLICY-LOCKED", "PUT /policy/draft answered 403: the policy cannot be "
                                      "written by this user or policy updates are disabled "
                                      "(plugins.content_manager.catalog.policy_update.enabled). Ask an administrator "
                                      "to set root_decoder to %s, then run apply again." % rid, [exc.server_message]))
            raise
        if not self.r.dry_run:
            self.state.data["root_decoder"] = {"server_id": rid, "local_id": self.out.root["local_id"],
                                               "set_by_tool": True, "when": now()}

    def delete_stale(self, integ):
        """Own resources of this integration that out/ no longer has."""
        wanted = {r.local_id for r in integ.all()}
        stale = [(lid, e) for lid, e in self.state.integration_ids(integ.key).items() if lid not in wanted]
        n = 0
        for rtype in CONTENT_TYPES:
            for lid, e in sorted(stale, key=lambda p: p[0]):
                if e.get("type") != rtype:
                    continue
                if e.get("server_id") in self.snap.docs["draft"][rtype]:
                    self.r.write("DELETE", "%s/%s" % (PATH[rtype], e["server_id"]), None,
                                 "delete %s %s (no longer in out/)" % (rtype, e.get("title")))
                    n += 1
                if e.get("space") == "draft":
                    self.state.forget(lid)
                else:
                    e["space"] = "draft-deleted"
        return n

    def order_policy(self):
        """Put the tool's integrations of the draft policy in the order of out/ (the 4.x load order of their
        root decoders): the 5.x engine tries sibling decoders in the order of the policy's integrations, and
        integrations are appended in creation order, so an earlier apply or a new one in between leaves them
        out of order. Integrations of others keep their positions."""
        wanted = []
        for integ in self.out.integrations:
            e = self.state.get(integ.me.local_id)
            if e and e.get("server_id"):
                wanted.append(e["server_id"])
        if self.r.dry_run:
            current = self.snap.policy.get("draft") or {}
        else:
            refresh(self.client)
            current = read_policy(self.client, "draft") or {}
        cur = list(current.get("integrations") or [])
        mine = set(wanted)
        order = [sid for sid in wanted if sid in cur]
        if self.shared:
            # under a shared root the tool's predecoder is a sibling of the standard decoders (decoder/syslog/0
            # takes every syslog line): the tool's integrations go first, the others keep their relative order
            new = order + [sid for sid in cur if sid not in mine]
        else:
            slots = [i for i, sid in enumerate(cur) if sid in mine]
            new = list(cur)
            for pos, sid in zip(slots, order):
                new[pos] = sid
        if new == cur:
            return
        resource = {k: v for k, v in current.items() if k != "id"}
        resource["integrations"] = new
        self.r.say("apply: the tool's integrations are put in the 4.x load order of their root decoders%s"
                   % (", before the others (shared root)" if self.shared else ""))
        try:
            self.r.write("PUT", BASE + "/policy/draft", {"resource": resource},
                         "reorder the tool's integrations in the draft policy (read-modify-write)")
        except ApiError as exc:
            if exc.status not in (400, 403):
                raise
            self.sec["notes"].append(
                "The tool's integrations could not be put in the 4.x load order of their root decoders "
                "(PUT /policy/draft answered %d: %s). Where two root decoders accept the same event, 5.x may "
                "pick a different one than 4.x: reorder them by hand in that order: %s."
                % (exc.status, exc.server_message, ", ".join(i.key for i in self.out.integrations)))
            self.r.say("apply: the policy could not be reordered (%d); see the report" % exc.status)
            return
        if self.r.dry_run:
            return
        changes = self.r.promote_preview("draft")
        self.check_foreign(changes)
        sel = empty_changes()
        sel["policy"] = list(changes.get("policy") or [])
        if _is_empty(sel):
            return
        self.r.say("POST %s  (promote the draft policy -> test: integration order)" % PROMOTE)
        status, body = self.client.call("POST", PROMOTE, {"space": "draft", "changes": sel})
        if status >= 300:
            msg = ApiError("POST", PROMOTE, status, body).server_message
            self.sec["notes"].append("The new order of the tool's integrations stays in draft: the promotion "
                                     "was refused (%s)." % msg)
            self.r.say("apply: the reordered policy was not promoted: %s" % msg)

    def retire_stale_base(self):
        """Resources that a new version of the tool no longer puts in
        wazuh4-base: deleted only after every other integration has been
        updated, since until then their decoders may still hang from them."""
        base = [i for i in self.out.integrations if i.key == BASE_KEY]
        if not base:
            return
        wanted = {r.local_id for r in base[0].all()}
        if not any(lid not in wanted for lid in self.state.integration_ids(BASE_KEY)):
            return
        aside = sorted(set(self.state.data.get("set_aside") or {})
                       | {i["key"] for i in self.sec["integrations"] if i["status"] == "set aside"})
        if aside:
            # a set-aside integration keeps its previous version in test, which may hang from them
            self.sec["notes"].append("wazuh4-base resources that this build no longer has are kept until %s "
                                     "can be applied: its previous version in test may still use them."
                                     % ", ".join(aside))
            return
        info = _new_info(BASE_KEY)
        info["deleted"] = self.delete_stale(base[0])
        if not info["deleted"]:
            return
        self.r.say("apply: integration %s (resources it no longer has)" % BASE_KEY)
        self.promote_integration(BASE_KEY, info)
        self.sec["integrations"].append(info)

    def promote_integration(self, key, info):
        if self.r.dry_run:
            self.r.say("[dry-run] GET %s?space=draft; POST %s  (promote integration %s draft -> test, with the "
                       "checked policy)" % (PROMOTE, PROMOTE, key))
            info["status"] = "dry run"
            return
        changes = self.r.promote_preview("draft")
        self.check_foreign(changes)
        ids = _ids_of(key, self.own, self.out, self.state)
        promoted_keys = [key]
        if changes.get("policy"):
            # The policy travels as one document and lists every integration in draft. An own integration that
            # is new in draft (left by an interrupted run) must reach test in the same promotion, or the engine
            # refuses it: "Integration with UUID '<id>' does not exist" (5.0.0-rc1).
            for op in changes.get("integrations") or []:
                sid = op.get("id")
                if op.get("operation") != "add" or sid in ids or not self.own.is_own(sid):
                    continue
                other = _lid_integration(self.own.owned.get(sid), self.out, self.state)
                if other and other != key:
                    ids |= _ids_of(other, self.own, self.out, self.state)
                    promoted_keys.append(other)
        sel = _select(changes, ids)
        if self.include_foreign:
            _merge_foreign(sel, changes, self.own)
        if changes.get("policy"):
            sel["policy"] = list(changes["policy"])
        if len(promoted_keys) > 1:
            self.r.say("apply: %s is promoted together with %s (pending in the draft policy)"
                       % (key, ", ".join(promoted_keys[1:])))
        if _is_empty(sel):
            # nothing pending: what is in draft is also in test (state lost, or adopted)
            for sid in ids:
                lid = self.own.owned.get(sid)
                e = self.state.get(lid)
                if e and e.get("server_id") == sid and sid in self.snap.docs["test"].get(e.get("type"), {}):
                    self.state.set_space(lid, "test")
            info["status"] = "unchanged"
            return
        self.r.say("POST %s  (promote %s draft -> test: %s)" % (
            PROMOTE, key, ", ".join("%d %s" % (len(sel[k]), k) for k in CHANGE_LISTS if sel[k])))
        status, body = self.client.call("POST", PROMOTE, {"space": "draft", "changes": sel})
        if status >= 300:
            msg = ApiError("POST", PROMOTE, status, body).server_message
            if key == self.base_holder():
                raise Stop(stop_entry(None, "The engine refused the promotion of %s, which holds the root decoder: "
                                      "nothing else can be promoted." % key, [msg]), exit_code=1)
            self.set_aside(key, msg, info)
            return
        for k in CHANGE_LISTS:
            if k == "policy":
                continue
            for op in sel[k]:
                lid = self.own.owned.get(op.get("id"))
                if lid is None:
                    continue
                if op.get("operation") == "remove":
                    e = self.state.get(lid)
                    if e and e.get("server_id") == op.get("id") and e.get("space") == "draft-deleted":
                        self.state.forget(lid)
                else:
                    self.state.set_space(lid, "test")
        self.state.data["set_aside"].pop(key, None)
        info["status"] = "promoted to test"
        self.state.save()

    def set_aside(self, key, msg, info):
        """Remove this integration's draft content (the tool's only) and keep
        the engine's message with it."""
        self.r.say("apply: the engine refused %s; setting it aside: %s" % (key, msg))
        refresh(self.client)
        n, parked = delete_integration_content(self.r, key, self.own, self.out, self.state,
                                               Snapshot(self.client, ("draft",)))
        for lid in list(self.state.integration_ids(key)):
            self.state.forget(lid)
        self.state.data["set_aside"][key] = {"message": msg, "when": now()}
        info.update({"status": "set aside", "message": msg, "deleted": info["deleted"] + n})
        if parked:
            self.sec["notes"].append("%s: integration %s stays in draft until its rules leave test." % (key, parked[0]))
        self.state.save()

    def retire_missing(self):
        """Integrations of the state that out/ no longer has: content first,
        promoted, then the integration (its log type is busy while test has
        its rules), promoted again."""
        keys = sorted({e.get("integration") for e in self.state.resources.values()}
                      - {i.key for i in self.out.integrations} - {None})
        for key in keys:
            info = _new_info(key)
            if key == BASE_KEY and self._base_is_root():
                info["status"] = "kept (its root is the policy root_decoder)"
                self.sec["integrations"].append(info)
                continue
            for types in (CONTENT_TYPES, ("integration",)):
                snap = self.snap if self.r.dry_run else Snapshot(self.client, ("draft",))
                n, _parked = delete_integration_content(self.r, key, self.own, self.out, self.state, snap, types)
                info["deleted"] += n
                for lid, e in list(self.state.integration_ids(key).items()):
                    if e.get("type") not in types:
                        continue
                    if e.get("space") == "draft":
                        self.state.forget(lid)
                    else:
                        e["space"] = "draft-deleted"
                self.promote_integration(key, info)
            if info["status"] in ("promoted to test", "unchanged"):
                info["status"] = "retired (no longer in out/)"
            self.sec["integrations"].append(info)

    def _base_is_root(self):
        rd = (self.state.data.get("root_decoder") or {}).get("server_id")
        pol = self.snap.policy.get("draft") or {}
        return bool(rd) and pol.get("root_decoder") == rd


def delete_integration_content(runner, key, own, out, state, snap, types=DELETE_ORDER):
    """DELETE in draft every resource of ``key`` the tool owns, of ``types``:
    rules, decoders (children first), kvdbs, then the integration. Returns
    ``(deleted, parked)``: an integration whose log type is still used by
    rules of test is left in draft (parked) to be deleted after the next
    promotion."""
    n = 0
    parked = []
    by_type = {t: [] for t in DELETE_ORDER}
    for rtype in types:
        for sid, doc in snap.docs["draft"][rtype].items():
            lid = own.owned.get(sid)
            if lid is not None and _lid_integration(lid, out, state) == key:
                by_type[rtype].append((sid, doc))
    order = {}
    if out is not None and out.integration(key):
        for i, d in enumerate(out.integration(key).decoders):
            order[d.local_id] = i
    by_type["decoder"].sort(key=lambda p: (-order.get(own.owned.get(p[0]), -1), p[0]))
    for rtype in DELETE_ORDER:
        if rtype not in types:
            continue
        for sid, doc in sorted(by_type[rtype], key=lambda p: p[0]) if rtype != "decoder" else by_type[rtype]:
            try:
                runner.write("DELETE", "%s/%s" % (PATH[rtype], sid), None,
                             "delete %s %s" % (rtype, doc_title(rtype, doc) or sid))
            except ApiError as exc:
                if rtype == "integration" and LOGTYPE_BUSY in str(exc.server_message):
                    runner.say("  %s is still used by rules of test: deleted after the next promotion" % sid)
                    parked.append(sid)
                    continue
                if exc.status == 404:
                    continue
                raise
            n += 1
    return n, parked


def _custom_problem(sel, snap):
    """What would be inconsistent in custom after promoting ``sel`` from test (``snap``: test and custom), or
    None: the policy names a missing integration or root decoder, or an integration lists a missing resource.
    The engine refuses such a space; rollback checks it before sending."""
    after = {t: set(snap.docs["custom"][t]) for t in ("integration", "kvdb", "decoder", "rule")}
    source = {}
    for k in CHANGE_LISTS:
        t = KEY_TYPE.get(k)
        if t is None:  # the policy, filters (never the tool's)
            continue
        for op in sel[k]:
            sid = op.get("id")
            if op.get("operation") == "remove":
                after[t].discard(sid)
            else:
                after[t].add(sid)
                if t == "integration":
                    source[sid] = snap.get("test", t, sid)
    policy = snap.policy.get("test") if sel["policy"] else snap.policy.get("custom")
    policy = policy or {}
    for iid in policy.get("integrations") or []:
        if iid not in after["integration"]:
            return "the policy names integration %s, which custom would not have" % iid
    if policy.get("root_decoder") and policy["root_decoder"] not in after["decoder"]:
        return "the policy root_decoder %s would not be in custom" % policy["root_decoder"]
    for iid in sorted(after["integration"]):
        doc = source.get(iid) or snap.get("custom", "integration", iid) or {}
        for t, field in (("decoder", "decoders"), ("kvdb", "kvdbs"), ("rule", "rules")):
            for x in doc.get(field) or []:
                if x not in after[t]:
                    return "integration %s lists %s %s, which custom would not have" % (iid, t, x)
    return None


class Rollback:
    def __init__(self, runner, include_foreign=False, yes=False):
        self.r = runner
        self.client = runner.client
        self.include_foreign = include_foreign
        self.yes = yes
        self.sec = runner.section("rollback")
        self.recorded = False
        self.custom = False  # the tool's content is in custom: with --yes the removals go there too
        self.custom_left = 0  # rolled-back resources of the tool still in custom at the end

    def run(self):
        r = self.r
        self.state = state = State.load(r.workdir)
        try:
            # under a shared root (state.json shared_root) out/ is read as apply wrote it: no tool root
            out = SR.load_out(r.out_dir, state)
        except Exception:  # noqa: BLE001 - rollback works from the state alone
            out = None
        snap = Snapshot(self.client)
        known = set(state.resources) | (set(out.by_local) if out else set())
        self.own = own = Ownership(snap, state, known)
        draft = snap.policy.get("draft") or {}
        base_root = (state.data.get("root_decoder") or {}).get("server_id")
        if not base_root and out is not None and out.root:
            base_root = own.in_space("draft", out.root["local_id"])
        keep_base = bool(base_root) and base_root in (draft.get("root_decoder"),
                                                      (snap.policy.get("test") or {}).get("root_decoder"))
        keys = sorted({_lid_integration(lid, out, state) for lid in own.owned.values()} - {None},
                      key=lambda k: (k == BASE_KEY, k))
        if keep_base:
            keys = [k for k in keys if k != BASE_KEY]
        exit_code = 0
        infos = {k: _new_info(k) for k in keys}
        self.out = out
        self.base_root = base_root
        self.keys = set(keys)  # the integrations rolled back (not wazuh4-base while it is kept)
        self.custom = any(own.is_own(sid) for docs in snap.docs["custom"].values() for sid in docs)
        try:
            # before writing: foreign changes already pending in draft
            self.check(r.promote_preview("draft"), base_root)
            if self.yes and self.custom:
                self.promote_custom(check_only=True)
            if self.yes and (self.custom or self.state.data.get("detectors")):
                # also when custom no longer has the tool's content: detectors left in the state would
                # otherwise be reported as "run rollback --yes again" on every run
                self.delete_detectors()
            # phase 1: rules, decoders, kvdbs; phase 2: the integrations, once test
            # no longer has their rules (Security Analytics keeps the log type)
            # Security Analytics frees a log type only once the removal of its rules has reached test, and not
            # always on the first promotion: a parked integration is tried again after each promotion
            # (seen on 5.0.0-rc1: 18 of 37 integrations were parked once, 2 of them twice).
            phases = [CONTENT_TYPES] + [("integration",)] * (1 + len(PARKED_WAITS))
            for phase, types in enumerate(phases):
                if phase > 1 and not r.dry_run:
                    time.sleep(PARKED_WAITS[phase - 2])
                if phase:
                    snap = Snapshot(self.client) if not r.dry_run else snap
                pending = False
                for key in keys:
                    if phase > 1 and not infos[key]["message"]:
                        continue
                    n, parked = delete_integration_content(r, key, own, out, state, snap, types)
                    infos[key]["deleted"] += n
                    infos[key]["message"] = (
                        "integration %s is still used by rules outside draft" % parked[0]) if parked else None
                    pending = pending or bool(parked)
                self.promote(snap, base_root)
                if phase and not pending:
                    break
            for key in keys:
                infos[key]["status"] = "removed" if not infos[key]["message"] else "partly removed"
                self.sec["integrations"].append(infos[key])
            if keep_base:
                self.sec["integrations"].append(dict(_new_info(BASE_KEY), status="kept", message=(
                    "Its root decoder %s is the root_decoder of the policy: the API refuses to delete it and the "
                    "engine refuses an empty space." % base_root)))
                self.sec["notes"].append(
                    "wazuh4-base stays while its root decoder (%s) is the policy root_decoder. To retire it: set "
                    "root_decoder to another decoder (or empty it) with PUT /policy/draft, delete the wazuh4-base "
                    "decoders, kvdbs and integration, and promote draft -> test." % base_root)
                r.say("rollback: wazuh4-base is kept: its root decoder is the policy root_decoder (see report.md).")
            if not r.dry_run:
                self.forget_removed(keep_base)
            self.report_custom()
            result = "ok"
            if self.yes and self.custom_left:
                # rolled-back content is still in custom (a promotion skipped as inconsistent): not done
                result = "partly removed from custom"
                exit_code = 1
        except Stop as stop:
            self.sec["stops"].append(stop.entry)
            r.say(stop_line("rollback", stop.entry))
            for it in stop.entry["items"]:
                r.say("  - %s" % it)
            result = "stopped"
            exit_code = stop.exit_code
        self.sec["result"] = result
        if not self.yes:
            self.sec["notes"].append("The custom space is not touched by rollback without --yes.")
        if not r.dry_run:
            state.save()
            update_report(r.paths, "rollback", self.sec)
        r.say("rollback: %s" % result)
        return exit_code

    def promote(self, snap, base_root):
        r = self.r
        if r.dry_run:
            r.say("[dry-run] GET %s?space=draft; POST %s  (promote the removals draft -> test)" % (PROMOTE, PROMOTE))
            if self.yes and self.custom:
                r.say("[dry-run] GET %s?space=test; POST %s  (promote the removals test -> custom)" % (PROMOTE, PROMOTE))
            return
        changes = r.promote_preview("draft")
        self.check(changes, base_root)
        sel = _select(changes, set(self.own.owned))
        if self.include_foreign:
            _merge_foreign(sel, changes, self.own)
        if changes.get("policy"):
            sel["policy"] = list(changes["policy"])
        if _is_empty(sel):
            # nothing new for test (an earlier run promoted it): custom may still have to follow
            if self.yes and self.custom:
                self.promote_custom()
            return
        r.say("POST %s  (promote the removals draft -> test: %s)" % (
            PROMOTE, ", ".join("%d %s" % (len(sel[k]), k) for k in CHANGE_LISTS if sel[k])))
        status, body = self.client.call("POST", PROMOTE, {"space": "draft", "changes": sel})
        if status >= 300:
            msg = ApiError("POST", PROMOTE, status, body).server_message
            raise Stop(stop_entry(None, "The promotion of the removals to test failed: draft no longer has the "
                                  "tool's content, test still has it. Run rollback again once the cause is fixed.",
                                  [msg]), exit_code=1)
        if self.yes and self.custom:
            self.promote_custom()

    # -- custom (--yes) ---------------------------------------------------------------
    def delete_detectors(self):
        """The tool's detectors (state, or found by the names of out/detectors) use its rules of custom:
        deleted before those rules leave custom. The same DELETE as the temporary detector of verify."""
        from ..activate import DETECTORS, find_detector, foreign_rules

        known = dict(self.state.data.get("detectors") or {})
        names = sorted(set(known) | {d["name"] for d in (self.out.detectors if self.out is not None else [])})
        for name in names:
            det_id = (known.get(name) or {}).get("id")
            if not det_id and not self.r.dry_run:
                found = find_detector(self.client, name)
                det_id = found[0] if found else None
                other = foreign_rules(found[1], self.own) if found else []
                if other:
                    # same name, someone else's rules (another workdir of the same customer): never removed
                    self.sec["notes"].append("Detector %s (%s) has the tool's name but rules that are not its own "
                                             "(%s): left untouched." % (det_id, name, ", ".join(other[:5])))
                    self.r.say("rollback: detector %s is not the tool's: left untouched" % name)
                    continue
            if not det_id:
                if self.r.dry_run:
                    self.r.say("[dry-run] POST %s/_search, then DELETE the detector %s if it exists" % (DETECTORS, name))
                continue
            try:
                self.r.write("DELETE", "%s/%s" % (DETECTORS, det_id), None, "delete detector %s" % name)
            except ApiError as exc:
                if exc.status != 404:
                    raise
            if not self.r.dry_run:
                self.state.data.setdefault("detectors", {}).pop(name, None)
                self.sec["operations"].append(self.state.operation("delete-detector", "rollback",
                                                                   "%s %s" % (name, det_id)))

    def promote_custom(self, check_only=False):
        """Promote the tool's removals test -> custom (see ``custom_selection``), with the policy check of activate.
        ``check_only``: the check alone, before rollback writes anything."""
        from ..activate import foreign_items

        r = self.r
        changes = r.promote_preview("test")
        snap = Snapshot(self.client, ("test", "custom"))
        foreign = foreign_changes(changes, self.own, other_tool_ok=True)
        pol = []
        other_pol = []
        if changes.get("policy"):
            pol = policy_differences(snap.policy.get("test"), snap.policy.get("custom"), self.own, self.base_root,
                                     other_tool_ok=True)
            other_pol = [d for d in policy_differences(snap.policy.get("test"), snap.policy.get("custom"), self.own,
                                                       self.base_root) if d not in pol]
        others = other_tool_changes(changes, self.own)
        if foreign or pol:
            # rollback --yes removes; it never carries someone else's content or policy change to custom, not
            # even with --include-foreign-changes
            items = foreign_items(foreign, snap) + ["policy: %s" % d for d in pol]
            raise Stop(stop_entry("RM-P-FOREIGN-POLICY-CHANGE" if pol else None, FOREIGN_YES_TEXT % "test", items),
                       exit_code=2 if check_only else 1)
        self.note_other_tool("test", others, other_pol)
        if check_only or r.dry_run:
            return
        sel, unknown = self.custom_selection(changes)
        if changes.get("policy"):
            sel["policy"] = list(changes["policy"])
        if other_pol:
            # the test policy also carries another workdir's content: promoting it would carry that content to
            # custom, so the policy and the integration removals wait (the content removals go)
            sel["policy"] = []
            sel["integrations"] = [op for op in sel["integrations"] if op.get("operation") != "remove"]
        problem = _custom_problem(sel, snap)
        if problem and unknown:
            for k in CHANGE_LISTS:
                sel[k] = [op for op in sel[k] if op.get("id") not in unknown]
            problem = _custom_problem(sel, snap)
        if problem and (sel["policy"] or sel["integrations"]):
            # the test policy can name an integration custom does not have (applied after activate, not yet
            # removed from test): the content removals go first, the integrations and the policy with a later
            # promotion, once test no longer has them
            sel["policy"] = []
            sel["integrations"] = [op for op in sel["integrations"] if op.get("operation") != "remove"]
            problem = _custom_problem(sel, snap)
        if problem:
            note = ("rollback --yes did not promote these removals to custom, which would not be consistent (%s): "
                    "run rollback --yes again." % problem)
            if note not in self.sec["notes"]:
                self.sec["notes"].append(note)
            r.say("rollback: the removals are not promoted to custom yet: %s" % problem)
            return
        if _is_empty(sel):
            return
        r.say("POST %s  (promote the removals test -> custom: %s)" % (
            PROMOTE, ", ".join("%d %s" % (len(sel[k]), k) for k in CHANGE_LISTS if sel[k])))
        status, body = self.client.call("POST", PROMOTE, {"space": "test", "changes": sel})
        if status >= 300:
            msg = ApiError("POST", PROMOTE, status, body).server_message
            raise Stop(stop_entry(None, "The promotion of the removals to custom failed: test no longer has the "
                                  "tool's content, custom still has it. Run rollback --yes again once the cause is "
                                  "fixed.", [msg]), exit_code=1)

    def note_other_tool(self, space, others, other_pol=()):
        """List content of another rmig workdir pending in ``space`` (never removed, never a stop), once."""
        items = []
        for f in others:
            rtype = KEY_TYPE.get(f["type"])
            doc = next((self.own.snap.get(sp, rtype, f["id"]) for sp in ("draft", "test", "custom")
                        if self.own.snap.get(sp, rtype, f["id"])), None)
            title = doc_title(rtype, doc) if doc else None
            items.append("%s %s %s%s" % (f["operation"], f["type"], f["id"], " (%s)" % title if title else ""))
        items += ["policy: %s" % d.replace("by someone else", "by another rmig workdir") for d in other_pol]
        if not items:
            return
        text = ("Tool, other workdir: the %s space has changes of another rmig workdir (marked by the tool, not in "
                "this workdir's state). They are not removed and not promoted.%s" % (space, (
                    " The policy carries them, so it is not promoted to custom: roll back or activate that workdir, "
                    "then run rollback --yes again." if other_pol else "")))
        note = "%s %s" % (text, "; ".join(items))
        if note in self.sec["notes"]:
            return
        self.sec["notes"].append(note)
        self.r.say("rollback: %s" % text)
        for it in items:
            self.r.say("  - %s" % it)

    def custom_selection(self, changes):
        """The tool's changes of test that rollback may promote to custom: removals, and the updates of the
        integrations it rolls back (their lists lose the removed content). Never an add (content applied but not
        activated stays out of custom) and nothing of a kept wazuh4-base (a newer version in test is not
        activated by a rollback)."""
        sel = empty_changes()
        unknown = set()
        for k in CHANGE_LISTS:
            if k == "policy":
                continue
            for op in changes.get(k) or []:
                sid = op.get("id")
                if not self.own.is_own(sid):
                    continue
                key = _lid_integration(self.own.owned[sid], self.out, self.state)
                if key is None and op.get("operation") == "remove":
                    # a retired resource (out/ and the state no longer know its integration): its copy of custom
                    # goes too, unless custom would then be inconsistent (see promote_custom)
                    unknown.add(sid)
                    sel[k].append(op)
                elif key in self.keys and (op.get("operation") == "remove"
                                           or (op.get("operation") == "update" and k == "integrations")):
                    sel[k].append(op)
        return sel, unknown

    def report_custom(self):
        """What of the tool stays in custom, and the step that removes it."""
        if self.r.dry_run:
            snap_custom = None
        else:
            refresh(self.client)
            snap_custom = Snapshot(self.client, ("custom",))
        left = []
        if snap_custom is None:
            for lid, e in sorted(self.state.resources.items()):
                if e.get("space") == "custom":
                    left.append("%s %s %s (%s)" % (e.get("type"), e.get("server_id"), e.get("title"), e.get("integration")))
        else:
            # from custom itself: the tool's marked documents too, when the state lost or retired them
            for rtype in DELETE_ORDER:
                for sid, doc in sorted(snap_custom.docs["custom"].get(rtype, {}).items()):
                    if not self.own.is_own(sid):
                        continue
                    key = _lid_integration(self.own.owned[sid], self.out, self.state)
                    left.append("%s %s %s (%s)" % (rtype, sid, doc_title(rtype, doc), key or "-"))
                    if key is None or key in self.keys:
                        self.custom_left += 1
        dets = sorted("detector %s %s" % (n, d.get("id")) for n, d in (self.state.data.get("detectors") or {}).items())
        if not left and not dets:
            return
        items = left + dets
        if self.yes:
            text = ("These resources of the tool stay in custom (wazuh4-base while its root decoder is the policy "
                    "root_decoder, or a removal that could not be promoted yet: run rollback --yes again).")
        else:
            text = ("These resources of the tool stay in custom, where the manager runs them, and its detectors stay "
                    "too. To remove them: rollback --yes (deletes the detectors, then promotes the removals "
                    "test -> custom; this changes what the manager runs).")
        self.sec["notes"].append("%s %s" % (text, "; ".join(items)))
        self.r.say("rollback: %s" % text)
        for it in items:
            self.r.say("  - %s" % it)

    def forget_removed(self, keep_base):
        """Forget what is no longer in draft, test nor custom."""
        refresh(self.client)
        snap = Snapshot(self.client)
        for lid, e in list(self.state.resources.items()):
            if e.get("integration") == BASE_KEY and keep_base:
                continue
            sid, rtype = e.get("server_id"), e.get("type")
            if any(sid in snap.docs[s].get(rtype, {}) for s in ("draft", "test", "custom")):
                continue
            self.state.forget(lid)
        self.state.data["set_aside"] = {}
        if not self.state.resources:
            # nothing of the tool is left: the next apply chooses its root again
            self.state.data["shared_root"] = None

    def check(self, changes, base_root):
        foreign = foreign_changes(changes, self.own, other_tool_ok=True)
        self.note_other_tool("draft", other_tool_changes(changes, self.own))
        pol = []
        if changes.get("policy"):
            refresh(self.client)
            pol = policy_differences(read_policy(self.client, "draft"), read_policy(self.client, "test"),
                                     self.own, base_root)
        if not foreign and not pol:
            return
        items = ["%s %s %s" % (f["operation"], f["type"], f["id"]) for f in foreign] + ["policy: %s" % d for d in pol]
        if self.yes and self.custom:
            raise Stop(stop_entry("RM-P-FOREIGN-POLICY-CHANGE" if pol else None, FOREIGN_YES_TEXT % "draft", items))
        if not self.include_foreign:
            raise Stop(stop_entry("RM-P-FOREIGN-POLICY-CHANGE" if pol else None, FOREIGN_TEXT, items))
        if not self.recorded and not self.r.dry_run:
            self.sec["operations"].append(self.state.operation("include-foreign-changes", "rollback", "; ".join(items)))
            self.recorded = True
