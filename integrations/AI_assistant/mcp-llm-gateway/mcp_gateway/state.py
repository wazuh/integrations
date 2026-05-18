import time
import asyncio
from typing import Dict
from .models import PendingAction, WizardState, AgentsCache
from .config import ACTION_CONFIRM_TTL, WIZARD_TTL

PENDING: Dict[str, PendingAction] = {}
PENDING_LOCK = asyncio.Lock()

def _cleanup_pending():
    now = time.time()
    expired = [sid for sid, a in PENDING.items() if (now - a.created_at) > ACTION_CONFIRM_TTL]
    for sid in expired:
        PENDING.pop(sid, None)

WIZARDS: Dict[str, WizardState] = {}
WIZARDS_LOCK = asyncio.Lock()

def _cleanup_wizards():
    now = time.time()
    expired = [sid for sid, w in WIZARDS.items() if (now - w.created_at) > WIZARD_TTL]
    for sid in expired:
        WIZARDS.pop(sid, None)

_AGENTS_CACHE: Dict[str, AgentsCache] = {}
_AGENTS_CACHE_LOCK = asyncio.Lock()
