"""The translator.

``plan`` and ``build`` from the command line run it through
:func:`rmig.translate.pipeline.compute`; the library function
:func:`rmig.planner.compute` classifies only (``RM-X-PROVISIONAL-AUTO``).

Modules
-------

:mod:`.patterns`
    OS_Match, OS_Regex and PCRE2 to Sigma values (detector dialect) and RE2.
:mod:`.re_dialect`
    the validator every emitted ``|re`` passes.
:mod:`.sigma`
    boolean conditions over selections and their ``detection`` block.
:mod:`.decoders`
    decoders.
:mod:`.engine`
    rules, labels in decoders, lists, propagation.
:mod:`.package`, :mod:`.recipes`, :mod:`.meta`
    the ``out/`` package, recipes and monitors, metadata.

Interface kept from the core (one item at a time)
-------------------------------------------------

``translate_rule(effective_rule, ctx)`` and ``translate_decoder(decoder, ctx)``
return a :class:`TranslationResult` for one item of an already translated
classification (``ctx.translator`` is the :class:`.engine.Translator`).
"""

from .. import model4 as m
from .. import reasons as R


class TranslationContext:
    def __init__(self, items, plan_items, decisions, equivalence, wcs, translator=None):
        self.items = items
        self.plan_items = plan_items
        self.decisions = decisions
        self.equivalence = equivalence
        self.wcs = wcs
        self.translator = translator


class TranslationResult:
    __slots__ = ("resource", "reasons", "fidelity")

    def __init__(self, resource=None, reasons=None, fidelity="exact"):
        self.resource = resource
        self.reasons = list(reasons or [])
        self.fidelity = fidelity


def _result(tr, uid, resource):
    acc = tr.clf.acc[uid]
    reasons = [(c, "; ".join(d)) for c, d in sorted(acc.codes.items())]
    return TranslationResult(resource, reasons, R.fidelity_of(list(acc.codes)))


def translate_rule(effective_rule, ctx):
    tr = ctx.translator
    uid = effective_rule["uid"]
    r = tr.rules.get(uid)
    return _result(tr, uid, r.resource if r is not None and tr.emitted(uid) else None)


def translate_decoder(decoder, ctx):
    tr = ctx.translator
    uid = m.uid(decoder)
    pkg = tr.package
    resource = None
    for integ in pkg.integrations.values():
        for doc in integ["decoders"]:
            if doc["source"].get("kind") == "decoder" and doc["source"]["id"] == decoder["name"]:
                resource = doc["resource"]
    return _result(tr, uid, resource)


def available():
    """True: the translator is available."""
    return True
