/* agent.js
 * Wazuh Copilot — the single unified AI assistant, backed by the agentic
 * tool-calling loop (agent_engine.py). Handles freeform Q&A (falls straight
 * to a text answer when it has nothing to call) and full investigate/fix
 * flows with an approval gate on anything that changes system state.
 * Talks to /agent/message, /agent/approve, /agent/reset, /agent/tools, /agent/brains.
 * Plain window.* globals, no framework, BASE_URL resolved by app.js's loadConfig().
 */

const AgentState = {
    sessionId: null,
    brain: "ollama",
    ollamaModels: [],
    model: null,
    sending: false,
    initialized: false,
};

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

function agentAvatarSvg() {
    return '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">' +
        '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/></svg>';
}

// ─────────────────────────────────────────────────────────────────────────────
// MARKDOWN RENDERER (lightweight, no external deps) — ported from copilot.js
// ─────────────────────────────────────────────────────────────────────────────

function renderMarkdown(text) {
    // Escape the raw text FIRST, then apply markdown formatting on the
    // escaped string — otherwise a compromised backend response or a
    // prompt-injected tool result could inject live HTML/JS via innerHTML.
    // None of the regexes below match &<>"', so escaping first doesn't
    // change how any of them match.
    text = escapeHtml(text);

    text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
        const langLabel = lang ? `<span class="copilot-code-lang">${lang}</span>` : "";
        return `<div class="copilot-code-block">
            <div class="copilot-code-header">${langLabel}
                <button class="copilot-copy-btn" onclick="agentCopyCode(this)" title="Copy">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    Copy
                </button>
            </div>
            <pre><code>${code.trim()}</code></pre>
        </div>`;
    });

    text = text.replace(/`([^`]+)`/g, '<code class="copilot-inline-code">$1</code>');
    text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    text = text.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "<em>$1</em>");
    text = text.replace(/^### (.+)$/gm, '<h4 class="copilot-h4">$1</h4>');
    text = text.replace(/^## (.+)$/gm,  '<h3 class="copilot-h3">$1</h3>');
    text = text.replace(/^# (.+)$/gm,   '<h2 class="copilot-h2">$1</h2>');
    text = text.replace(/^─{3,}$/gm, '<hr class="copilot-hr">');
    text = text.replace(/^-{3,}$/gm,  '<hr class="copilot-hr">');
    text = text.replace(/^[•\-\*] (.+)$/gm, '<li>$1</li>');
    text = text.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul class="copilot-ul">$1</ul>');
    text = text.replace(/<\/ul>\s*<ul class="copilot-ul">/g, "");
    text = text.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
    text = text.replace(/\n\n/g, '</p><p class="copilot-p">');
    text = '<p class="copilot-p">' + text + '</p>';
    text = text.replace(/<p class="copilot-p"><\/p>/g, "");

    return text;
}

function agentCopyCode(btn) {
    const pre = btn.closest(".copilot-code-block").querySelector("pre code");
    if (!pre) return;
    navigator.clipboard.writeText(pre.textContent).then(() => {
        btn.textContent = "Copied!";
        setTimeout(() => {
            btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`;
        }, 2000);
    });
}
window.agentCopyCode = agentCopyCode;

function summarizeResult(result) {
    let s;
    try {
        s = typeof result === "string" ? result : JSON.stringify(result);
    } catch (e) {
        s = String(result);
    }
    if (!s) s = "(empty)";
    return s.length > 220 ? s.slice(0, 220) + "…" : s;
}

// ── Lazy init ────────────────────────────────────────────────────────────────

function onAgentViewActivated() {
    if (AgentState.initialized) return;
    AgentState.initialized = true;
    loadAgentBrains();
    appendAgentGreeting();
}

function updateModelSelectVisibility() {
    const modelSel = document.getElementById("agent-model-select");
    if (!modelSel) return;
    if (AgentState.brain === "ollama" && AgentState.ollamaModels.length > 1) {
        modelSel.style.display = "inline-block";
    } else {
        modelSel.style.display = "none";
    }
}

function agentModelChanged() {
    const modelSel = document.getElementById("agent-model-select");
    AgentState.model = modelSel ? modelSel.value : null;
}

async function loadAgentBrains() {
    const statusBar = document.getElementById("agent-status-bar");
    const select = document.getElementById("agent-brain-select");
    const modelSel = document.getElementById("agent-model-select");

    try {
        const res = await fetch(`${window.BASE_URL}/agent/brains`);
        const data = await res.json();

        const ollamaOk = !!(data.ollama && data.ollama.available);
        const claudeOk = !!(data.claude && data.claude.available);

        const ollamaOpt = select.querySelector('option[value="ollama"]');
        const claudeOpt = select.querySelector('option[value="claude"]');

        ollamaOpt.textContent = "Ollama (local) — " + (data.ollama ? data.ollama.model : "?");
        ollamaOpt.disabled = false;

        if (claudeOk) {
            claudeOpt.textContent = "Claude (API) — " + data.claude.model;
            claudeOpt.disabled = false;
        } else {
            claudeOpt.textContent = "Claude (API) — not configured";
            claudeOpt.disabled = true;
        }

        if (!ollamaOk && claudeOk) {
            select.value = "claude";
            AgentState.brain = "claude";
        }

        AgentState.ollamaModels = (data.ollama && data.ollama.models) || [];
        if (modelSel) {
            modelSel.innerHTML = "";
            AgentState.ollamaModels.forEach(m => {
                const opt = document.createElement("option");
                opt.value = m;
                opt.textContent = m;
                if (m === (data.ollama && data.ollama.model)) opt.selected = true;
                modelSel.appendChild(opt);
            });
            AgentState.model = modelSel.value || null;
        }
        updateModelSelectVisibility();

        const anyOk = ollamaOk || claudeOk;
        statusBar.innerHTML =
            `<span class="agent-status-dot ${anyOk ? "online" : "offline"}"></span>` +
            `<span>${anyOk ? (ollamaOk ? "Ollama ready" : "Claude ready") : "No brain configured"}</span>`;
    } catch (e) {
        statusBar.innerHTML = '<span class="agent-status-dot offline"></span><span>Backend unreachable</span>';
    }
}


function agentBrainChanged() {
    AgentState.brain = document.getElementById("agent-brain-select").value;
    updateModelSelectVisibility();
}

// ── Message rendering ────────────────────────────────────────────────────────

function appendAgentGreeting() {
    const container = document.getElementById("agent-messages");
    const wrap = document.createElement("div");
    wrap.className = "agent-msg agent-msg-assistant";
    wrap.innerHTML =
        `<div class="agent-avatar">${agentAvatarSvg()}</div>` +
        `<div class="agent-turn"><div class="agent-bubble agent-bubble-ai">Describe what's wrong ` +
        `(e.g. "no alerts are showing on the dashboard") and I'll investigate — checking services, ` +
        `logs, cluster health and configuration — before proposing any fix. I'll always show you the ` +
        `exact action and ask before restarting a service or changing anything.</div></div>`;
    container.appendChild(wrap);
}

function appendUserBubble(text) {
    const container = document.getElementById("agent-messages");
    const wrap = document.createElement("div");
    wrap.className = "agent-msg agent-msg-user";
    const bubble = document.createElement("div");
    bubble.className = "agent-bubble-user";
    bubble.textContent = text;
    wrap.appendChild(bubble);
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
}

function appendAssistantTextBubble(text) {
    const container = document.getElementById("agent-messages");
    const wrap = document.createElement("div");
    wrap.className = "agent-msg agent-msg-assistant";
    const bubble = document.createElement("div");
    bubble.className = "agent-bubble agent-bubble-ai";
    bubble.innerHTML = renderMarkdown(text || "(no response)");
    wrap.appendChild(Object.assign(document.createElement("div"), { className: "agent-avatar", innerHTML: agentAvatarSvg() }));
    wrap.appendChild(bubble);
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
}

// ── History (saved chats — up to the 6 most recent) ─────────────────────────

function timeAgo(isoString) {
    const seconds = Math.floor((new Date() - new Date(isoString)) / 1000);
    if (seconds < 60) return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    return `${days}d`;
}

async function loadAgentHistory() {
    const panel = document.getElementById("agent-history-panel");
    panel.innerHTML = '<div class="agent-history-empty">Loading...</div>';
    try {
        const res = await fetch(`${window.BASE_URL}/agent/sessions`);
        const data = await res.json();
        const sessions = data.sessions || [];
        if (!sessions.length) {
            panel.innerHTML = '<div class="agent-history-empty">No saved conversations yet.</div>';
            return;
        }
        panel.innerHTML = "";
        sessions.forEach(s => {
            const row = document.createElement("div");
            row.className = "agent-history-row";
            row.innerHTML =
                `<span class="title" title="${escapeHtml(s.title)}">${escapeHtml(s.title)}</span>` +
                `<span class="time">${timeAgo(s.updated_at)}</span>` +
                `<button class="icon-btn" title="Rename" data-action="rename">` +
                `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg></button>` +
                `<button class="icon-btn" title="Delete" data-action="delete">` +
                `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg></button>`;

            row.addEventListener("click", (e) => {
                const action = e.target.closest("button")?.dataset.action;
                if (action === "rename") {
                    e.stopPropagation();
                    renameHistoryEntry(s.chat_id, s.title);
                } else if (action === "delete") {
                    e.stopPropagation();
                    deleteHistoryEntry(s.chat_id);
                } else {
                    resumeSessionFromHistory(s.chat_id);
                }
            });
            panel.appendChild(row);
        });
    } catch (e) {
        panel.innerHTML = '<div class="agent-history-empty">Failed to load history.</div>';
    }
}

function agentToggleHistory() {
    const panel = document.getElementById("agent-history-panel");
    const showing = panel.style.display === "none" || !panel.style.display;
    panel.style.display = showing ? "block" : "none";
    if (showing) loadAgentHistory();
}

document.addEventListener("click", (e) => {
    const panel = document.getElementById("agent-history-panel");
    const btn = document.getElementById("agent-history-btn");
    if (!panel || panel.style.display === "none") return;
    if (!panel.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
        panel.style.display = "none";
    }
});

function replayTurns(turns) {
    const container = document.getElementById("agent-messages");
    container.innerHTML = "";
    turns.forEach(t => {
        if (t.role === "user" && t.text) {
            appendUserBubble(t.text);
        } else if (t.role === "assistant" && t.text) {
            appendAssistantTextBubble(t.text);
        }
        // tool-call/tool-result turns are skipped in replay — this reconstructs
        // a clean readable transcript, not the original step-by-step trace.
    });
}

async function resumeSessionFromHistory(chatId) {
    try {
        const res = await fetch(`${window.BASE_URL}/agent/sessions/${encodeURIComponent(chatId)}`);
        const data = await res.json();
        if (!data.turns) {
            appendAgentError("Could not load that conversation — it may have been deleted.");
            return;
        }
        AgentState.sessionId = chatId;
        replayTurns(data.turns);
        updateInputLock(false);
        document.getElementById("agent-history-panel").style.display = "none";
    } catch (e) {
        appendAgentError("Failed to load conversation: " + e.message);
    }
}

async function deleteHistoryEntry(chatId) {
    try {
        await fetch(`${window.BASE_URL}/agent/sessions/${encodeURIComponent(chatId)}`, { method: "DELETE" });
        loadAgentHistory();
    } catch (e) { /* best-effort */ }
}

async function renameHistoryEntry(chatId, currentTitle) {
    const title = prompt("Rename conversation:", currentTitle);
    if (!title || !title.trim()) return;
    try {
        await fetch(`${window.BASE_URL}/agent/sessions/${encodeURIComponent(chatId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title: title.trim() }),
        });
        loadAgentHistory();
    } catch (e) { /* best-effort */ }
}

function appendThinkingBubble() {
    const container = document.getElementById("agent-messages");
    const wrap = document.createElement("div");
    wrap.className = "agent-msg agent-msg-assistant";
    wrap.innerHTML =
        `<div class="agent-avatar">${agentAvatarSvg()}</div>` +
        '<div class="agent-bubble-thinking"><span class="agent-dot"></span><span class="agent-dot"></span><span class="agent-dot"></span></div>';
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
    return wrap;
}

function appendAgentError(text) {
    const container = document.getElementById("agent-messages");
    const wrap = document.createElement("div");
    wrap.className = "agent-msg agent-msg-assistant";
    wrap.innerHTML =
        `<div class="agent-avatar">${agentAvatarSvg()}</div>` +
        `<div class="agent-turn"><div class="agent-bubble-error">${escapeHtml(text)}</div></div>`;
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
}

function renderTrace(trace) {
    const box = document.createElement("div");
    box.className = "agent-trace";

    for (let i = 0; i < trace.length; i++) {
        const item = trace[i];
        if (item.type !== "tool_call") continue;

        const result = trace[i + 1] && trace[i + 1].type === "tool_result" ? trace[i + 1] : null;
        const row = document.createElement("div");
        row.className = "agent-trace-step" + (result && result.error ? " error" : "");

        const argsStr = item.arguments && Object.keys(item.arguments).length ? JSON.stringify(item.arguments) : "";
        const resStr = result ? summarizeResult(result.result) : "…";
        const icon = result ? (result.error ? "✗" : "✓") : "…";

        row.innerHTML =
            `<span>${icon}</span> <span class="tool-name">${escapeHtml(item.tool)}</span>` +
            `<span class="tool-result">${escapeHtml(argsStr)} → ${escapeHtml(resStr)}</span>`;
        box.appendChild(row);
    }
    return box;
}

function renderApprovalCard(action) {
    const risk = action.risk || "medium";
    const card = document.createElement("div");
    card.className = "agent-approval-card risk-" + risk;
    card.innerHTML =
        `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">` +
        `<strong>Wants to run: <code>${escapeHtml(action.tool)}</code></strong>` +
        `<span class="agent-risk-badge ${escapeHtml(risk)}">${escapeHtml(risk)}</span></div>` +
        `<div style="color:var(--text-secondary);">${escapeHtml(action.description || "")}</div>` +
        `<div class="agent-approval-args">${escapeHtml(JSON.stringify(action.arguments || {}, null, 2))}</div>` +
        `<div class="agent-approval-actions">` +
        `<button class="agent-approve-btn" onclick="agentApprove(true, this)">Approve &amp; Run</button>` +
        `<button class="agent-reject-btn" onclick="agentApprove(false, this)">Reject</button></div>`;
    return card;
}

function updateInputLock(locked) {
    const input = document.getElementById("agent-input");
    const btn = document.getElementById("agent-send-btn");
    input.disabled = locked;
    btn.disabled = locked;
    btn.style.opacity = locked ? "0.5" : "1";
    input.placeholder = locked
        ? "Approve or reject the pending action above before continuing…"
        : "Describe the problem... (Enter to send, Shift+Enter for new line)";
}

function renderAgentTurn(data) {
    const container = document.getElementById("agent-messages");
    const wrap = document.createElement("div");
    wrap.className = "agent-msg agent-msg-assistant";

    const avatar = document.createElement("div");
    avatar.className = "agent-avatar";
    avatar.innerHTML = agentAvatarSvg();

    const turn = document.createElement("div");
    turn.className = "agent-turn";

    if (data.trace && data.trace.length) {
        turn.appendChild(renderTrace(data.trace));
    }

    if (data.status === "final") {
        const bubble = document.createElement("div");
        bubble.className = "agent-bubble agent-bubble-ai";
        bubble.innerHTML = renderMarkdown(data.message || "(no response)");
        turn.appendChild(bubble);
    } else if (data.status === "awaiting_approval") {
        turn.appendChild(renderApprovalCard(data.pending_action));
    } else {
        const bubble = document.createElement("div");
        bubble.className = "agent-bubble-error";
        bubble.textContent = data.message || "Unknown error.";
        turn.appendChild(bubble);
    }

    wrap.appendChild(avatar);
    wrap.appendChild(turn);
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;

    updateInputLock(data.status === "awaiting_approval");
}

// ── Actions ──────────────────────────────────────────────────────────────────

function setAgentSending(sending) {
    AgentState.sending = sending;
    const btn = document.getElementById("agent-send-btn");
    if (!sending) return; // updateInputLock() governs the "enabled" state otherwise
    btn.disabled = true;
    btn.style.opacity = "0.5";
}

async function agentSend() {
    const input = document.getElementById("agent-input");
    const text = input.value.trim();
    if (!text || AgentState.sending) return;

    appendUserBubble(text);
    input.value = "";
    if (window.copilotAutoResize) window.copilotAutoResize(input);

    const thinking = appendThinkingBubble();
    setAgentSending(true);

    try {
        const res = await fetch(`${window.BASE_URL}/agent/message`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: AgentState.sessionId, message: text, brain: AgentState.brain, model: AgentState.brain === "ollama" ? AgentState.model : null }),
        });
        const data = await res.json();
        AgentState.sessionId = data.session_id || AgentState.sessionId;
        thinking.remove();
        renderAgentTurn(data);
    } catch (e) {
        thinking.remove();
        appendAgentError("Request failed: " + e.message);
        updateInputLock(false);
    } finally {
        AgentState.sending = false;
        if (!document.getElementById("agent-input").disabled) {
            document.getElementById("agent-send-btn").style.opacity = "1";
        }
    }
}

async function agentApprove(approve, btnEl) {
    if (AgentState.sending) return;

    const card = btnEl.closest(".agent-approval-card");
    const actions = card.querySelector(".agent-approval-actions");
    actions.innerHTML =
        `<span class="agent-approval-resolved">${approve ? "Approved — running…" : "Rejected"}</span>`;

    AgentState.sending = true;
    updateInputLock(true);

    try {
        const res = await fetch(`${window.BASE_URL}/agent/approve`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: AgentState.sessionId, approve }),
        });
        const data = await res.json();
        renderAgentTurn(data);
    } catch (e) {
        appendAgentError("Approve request failed: " + e.message);
        updateInputLock(false);
    } finally {
        AgentState.sending = false;
    }
}

async function agentNewSession() {
    if (AgentState.sessionId) {
        try {
            await fetch(`${window.BASE_URL}/agent/reset`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ session_id: AgentState.sessionId }),
            });
        } catch (e) { /* best-effort */ }
    }
    AgentState.sessionId = null;
    document.getElementById("agent-messages").innerHTML = "";
    updateInputLock(false);
    appendAgentGreeting();
}

function agentInputKeydown(event) {
    if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        agentSend();
    }
}

function copilotAutoResize(el) {
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 200) + "px";
}
window.copilotAutoResize = copilotAutoResize;

window.onAgentViewActivated = onAgentViewActivated;
window.agentBrainChanged = agentBrainChanged;
window.agentModelChanged = agentModelChanged;
window.agentSend = agentSend;
window.agentApprove = agentApprove;
window.agentNewSession = agentNewSession;
window.agentInputKeydown = agentInputKeydown;
window.agentToggleHistory = agentToggleHistory;
