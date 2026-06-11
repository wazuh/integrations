/**
 * copilot.js
 * Wazuh Copilot — AI-powered expert assistant frontend.
 * Manages conversation history, renders markdown, handles quick action cards,
 * and communicates with the /copilot backend endpoint.
 */

// ─────────────────────────────────────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────────────────────────────────────

const CopilotState = {
    history:       [],       // [{role, content}, ...]
    includeEnv:    true,
    currentModel:  "",
    availModels:   [],
    streaming:     false,
    initialized:   false,
    sessionId:     "",       // unique chat session ID
};

// ─────────────────────────────────────────────────────────────────────────────
// QUICK ACTION CARDS  — clicking one pre-fills a prompt
// ─────────────────────────────────────────────────────────────────────────────

const QUICK_ACTIONS = [
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
        label: "Explain Rule",
        color: "blue",
        prompt: "Explain this Wazuh rule (paste it below):\n\n",
        placeholder: "Paste your Wazuh XML rule here and I'll explain every field..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>`,
        label: "Generate Rule",
        color: "green",
        prompt: "Generate a Wazuh rule that: ",
        placeholder: "Describe what you want to detect, e.g. 'SSH brute force from a single IP with 5+ failures in 60 seconds'..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`,
        label: "Review Rule",
        color: "yellow",
        prompt: "Review this Wazuh rule for correctness, best practices, and improvements:\n\n",
        placeholder: "Paste your rule XML here for a full technical review..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>`,
        label: "Generate Decoder",
        color: "purple",
        prompt: "Generate a Wazuh decoder for this log format:\n\n",
        placeholder: "Paste a sample log line you want to decode, e.g. a custom application log..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
        label: "Review Decoder",
        color: "orange",
        prompt: "Review this Wazuh decoder for correctness and improvements:\n\n",
        placeholder: "Paste your decoder XML here..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
        label: "Analyze Log",
        color: "teal",
        prompt: "Analyze this log and explain what Wazuh would do with it:\n\n",
        placeholder: "Paste raw log lines here — I'll explain what Wazuh detects, which decoders match, and what alerts fire..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        label: "Explain Alert",
        color: "red",
        prompt: "Explain this Wazuh alert and tell me what happened:\n\n",
        placeholder: "Paste the full alert JSON here..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
        label: "Generate Commands",
        color: "cyan",
        prompt: "Generate the Wazuh API / curl commands to: ",
        placeholder: "Describe what you want to do, e.g. 'list all disconnected agents' or 'restart manager via API'..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
        label: "Review Config",
        color: "slate",
        prompt: "Review this Wazuh configuration and identify issues, improvements, and best practices:\n\n",
        placeholder: "Paste ossec.conf, wazuh.yml, or any Wazuh config block here..."
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        label: "Ask a Question",
        color: "blue",
        prompt: "",
        placeholder: "Ask anything about Wazuh — architecture, deployment, features, troubleshooting, best practices..."
    },
];

const COLOR_MAP = {
    blue:   { bg: "rgba(0,188,255,0.08)",   border: "rgba(0,188,255,0.3)",   color: "#00bcff" },
    green:  { bg: "rgba(16,185,129,0.08)",  border: "rgba(16,185,129,0.3)",  color: "#10b981" },
    yellow: { bg: "rgba(245,158,11,0.08)",  border: "rgba(245,158,11,0.3)",  color: "#f59e0b" },
    purple: { bg: "rgba(139,92,246,0.08)",  border: "rgba(139,92,246,0.3)",  color: "#8b5cf6" },
    orange: { bg: "rgba(249,115,22,0.08)",  border: "rgba(249,115,22,0.3)",  color: "#f97316" },
    teal:   { bg: "rgba(20,184,166,0.08)",  border: "rgba(20,184,166,0.3)",  color: "#14b8a6" },
    red:    { bg: "rgba(244,63,94,0.08)",   border: "rgba(244,63,94,0.3)",   color: "#f43f5e" },
    cyan:   { bg: "rgba(6,182,212,0.08)",   border: "rgba(6,182,212,0.3)",   color: "#06b6d4" },
    slate:  { bg: "rgba(148,163,184,0.08)", border: "rgba(148,163,184,0.3)", color: "#94a3b8" },
};

// ─────────────────────────────────────────────────────────────────────────────
// INIT — called when the AI view is shown
// ─────────────────────────────────────────────────────────────────────────────

async function initCopilot() {
    if (CopilotState.initialized) return;
    CopilotState.initialized = true;
    CopilotState.sessionId = Math.random().toString(36).substring(2, 15);

    renderQuickActionCards();
    await loadCopilotStatus();
}

// ─────────────────────────────────────────────────────────────────────────────
// STATUS CHECK — fetch Ollama health and available models
// ─────────────────────────────────────────────────────────────────────────────

async function loadCopilotStatus() {
    const statusBar = document.getElementById("copilot-status-bar");
    const modelSel  = document.getElementById("copilot-model-select");

    if (statusBar) {
        statusBar.innerHTML = `<span style="color:var(--text-secondary);font-size:13px;">Connecting to Ollama...</span>`;
    }

    try {
        const res  = await fetch(`${window.BASE_URL}/copilot/status`);
        const data = await res.json();

        if (data.ollama_ok) {
            CopilotState.availModels  = data.models || [];
            CopilotState.currentModel = data.active_model || "";

            if (statusBar) {
                statusBar.innerHTML = `
                    <span class="copilot-status-dot online"></span>
                    <span style="color:var(--accent-green);font-size:13px;font-weight:600;">Ollama connected</span>
                    <span style="color:var(--text-secondary);font-size:12px;margin-left:8px;">Model: <b style="color:var(--accent-blue)">${data.active_model}</b></span>
                `;
            }

            // Populate model selector
            if (modelSel && CopilotState.availModels.length > 0) {
                modelSel.innerHTML = "";
                CopilotState.availModels.forEach(m => {
                    const opt = document.createElement("option");
                    opt.value = m;
                    opt.textContent = m;
                    if (m === CopilotState.currentModel) opt.selected = true;
                    modelSel.appendChild(opt);
                });
                modelSel.style.display = "inline-block";
            }

        } else {
            if (statusBar) {
                statusBar.innerHTML = `
                    <span class="copilot-status-dot offline"></span>
                    <span style="color:var(--accent-red);font-size:13px;font-weight:600;">Ollama not reachable</span>
                    <span style="color:var(--text-secondary);font-size:12px;margin-left:8px;">${data.error || "Check Ollama is running on port 11434"}</span>
                `;
            }
            appendCopilotMessage("system-error",
                "⚠ Ollama is not reachable.\n\n" +
                "To start it, run on your server:\n\n" +
                "  ollama serve\n\n" +
                "Then make sure the model is pulled:\n\n" +
                "  ollama pull qwen3:14b\n\n" +
                "Once Ollama is running, refresh this page."
            );
        }
    } catch (e) {
        if (statusBar) {
            statusBar.innerHTML = `<span style="color:var(--accent-red);font-size:13px;">⚠ Could not reach backend</span>`;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RENDER QUICK ACTION CARDS
// ─────────────────────────────────────────────────────────────────────────────

function renderQuickActionCards() {
    const grid = document.getElementById("copilot-quick-actions");
    if (!grid) return;
    grid.innerHTML = "";

    QUICK_ACTIONS.forEach(action => {
        const c = COLOR_MAP[action.color] || COLOR_MAP.blue;
        const card = document.createElement("button");
        card.className = "copilot-action-card";
        card.style.cssText = `
            background: ${c.bg};
            border: 1px solid ${c.border};
            color: ${c.color};
            border-radius: 10px;
            padding: 14px 16px;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 8px;
            text-align: left;
            transition: all 0.2s ease;
            font-family: var(--font-sans);
        `;

        card.innerHTML = `
            <div style="width:28px;height:28px;display:flex;align-items:center;justify-content:center;
                        background:rgba(255,255,255,0.05);border-radius:6px;">
                ${action.icon.replace('stroke="currentColor"', `stroke="${c.color}"`)}
            </div>
            <span style="font-size:13px;font-weight:600;">${action.label}</span>
        `;

        card.addEventListener("mouseenter", () => {
            card.style.transform = "translateY(-2px)";
            card.style.boxShadow = `0 4px 16px ${c.border}`;
        });
        card.addEventListener("mouseleave", () => {
            card.style.transform = "";
            card.style.boxShadow = "";
        });

        card.addEventListener("click", () => {
            const input = document.getElementById("copilot-input");
            if (input) {
                input.value = action.prompt;
                input.placeholder = action.placeholder;
                input.focus();
                // place cursor at end
                input.setSelectionRange(input.value.length, input.value.length);
            }
            // Scroll cards out of view on mobile
            document.getElementById("copilot-chat-area")?.scrollIntoView({ behavior: "smooth" });
        });

        grid.appendChild(card);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// CHAT MESSAGE RENDERING
// ─────────────────────────────────────────────────────────────────────────────

function appendCopilotMessage(role, content) {
    const container = document.getElementById("copilot-messages");
    if (!container) return;

    const wrapper = document.createElement("div");
    wrapper.className = `copilot-msg copilot-msg-${role}`;

    if (role === "assistant") {
        // Render markdown-ish formatting
        wrapper.innerHTML = `
            <div class="copilot-avatar" title="WazuhCopilot">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div class="copilot-bubble copilot-bubble-ai">${renderMarkdown(content)}</div>
        `;
    } else if (role === "user") {
        wrapper.innerHTML = `
            <div class="copilot-bubble copilot-bubble-user">${escapeHtml(content)}</div>
        `;
    } else if (role === "thinking") {
        wrapper.id = "copilot-thinking";
        wrapper.innerHTML = `
            <div class="copilot-avatar">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div class="copilot-bubble copilot-bubble-thinking">
                <span class="copilot-dot"></span>
                <span class="copilot-dot"></span>
                <span class="copilot-dot"></span>
            </div>
        `;
    } else if (role === "system-error") {
        wrapper.innerHTML = `
            <div class="copilot-bubble copilot-bubble-error">${escapeHtml(content)}</div>
        `;
    }

    container.appendChild(wrapper);
    container.scrollTop = container.scrollHeight;
    return wrapper;
}

function removeThinkingIndicator() {
    const el = document.getElementById("copilot-thinking");
    if (el) el.remove();
}

// ─────────────────────────────────────────────────────────────────────────────
// MARKDOWN RENDERER (lightweight, no external deps)
// ─────────────────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function renderMarkdown(text) {
    // Code blocks (must be before inline code)
    text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
        const langLabel = lang ? `<span class="copilot-code-lang">${escapeHtml(lang)}</span>` : "";
        return `<div class="copilot-code-block">
            <div class="copilot-code-header">${langLabel}
                <button class="copilot-copy-btn" onclick="copilotCopyCode(this)" title="Copy">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    Copy
                </button>
            </div>
            <pre><code>${escapeHtml(code.trim())}</code></pre>
        </div>`;
    });

    // Inline code
    text = text.replace(/`([^`]+)`/g, '<code class="copilot-inline-code">$1</code>');

    // Bold
    text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");

    // Italic (avoid conflicts with bold)
    text = text.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "<em>$1</em>");

    // Headers
    text = text.replace(/^### (.+)$/gm, '<h4 class="copilot-h4">$1</h4>');
    text = text.replace(/^## (.+)$/gm,  '<h3 class="copilot-h3">$1</h3>');
    text = text.replace(/^# (.+)$/gm,   '<h2 class="copilot-h2">$1</h2>');

    // Horizontal rule
    text = text.replace(/^─{3,}$/gm, '<hr class="copilot-hr">');
    text = text.replace(/^-{3,}$/gm,  '<hr class="copilot-hr">');

    // Unordered lists
    text = text.replace(/^[•\-\*] (.+)$/gm, '<li>$1</li>');
    text = text.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul class="copilot-ul">$1</ul>');
    // Collapse nested ul wrappers
    text = text.replace(/<\/ul>\s*<ul class="copilot-ul">/g, "");

    // Ordered lists
    text = text.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

    // Line breaks
    text = text.replace(/\n\n/g, '</p><p class="copilot-p">');
    text = '<p class="copilot-p">' + text + '</p>';
    text = text.replace(/<p class="copilot-p"><\/p>/g, "");

    return text;
}

function copilotCopyCode(btn) {
    const pre = btn.closest(".copilot-code-block").querySelector("pre code");
    if (!pre) return;
    navigator.clipboard.writeText(pre.textContent).then(() => {
        btn.textContent = "Copied!";
        setTimeout(() => {
            btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`;
        }, 2000);
    });
}
window.copilotCopyCode = copilotCopyCode;

// ─────────────────────────────────────────────────────────────────────────────
// SEND MESSAGE
// ─────────────────────────────────────────────────────────────────────────────

async function copilotSend() {
    const input   = document.getElementById("copilot-input");
    const sendBtn = document.getElementById("copilot-send-btn");

    if (!input) return;
    const userText = input.value.trim();
    if (!userText) return;
    if (CopilotState.streaming) return;

    // Show user bubble
    appendCopilotMessage("user", userText);

    // Update history
    CopilotState.history.push({ role: "user", content: userText });

    // Clear input
    input.value = "";
    input.placeholder = "Ask anything about Wazuh...";

    // Show thinking indicator
    appendCopilotMessage("thinking", "");

    // Disable send
    CopilotState.streaming = true;
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                <circle cx="12" cy="12" r="10" stroke-dasharray="31.4" stroke-dashoffset="10">
                    <animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/>
                </circle>
            </svg>`;
    }

    try {
        const modelSel     = document.getElementById("copilot-model-select");
        const envToggle    = document.getElementById("copilot-env-toggle");
        const selectedModel = modelSel ? modelSel.value : CopilotState.currentModel;
        const useEnv        = envToggle ? envToggle.checked : true;

        const res = await fetch(`${window.BASE_URL}/copilot/chat`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                messages:    CopilotState.history,
                model:       selectedModel,
                include_env: useEnv,
                session_id:  CopilotState.sessionId,
            }),
        });

        removeThinkingIndicator();

        if (!res.ok) {
            const errText = await res.text();
            appendCopilotMessage("system-error",
                `Error ${res.status}: ${errText.slice(0, 300)}`
            );
            CopilotState.history.pop(); // remove failed user msg from history
        } else {
            const data  = await res.json();
            const reply = data.reply || "(empty response)";

            // Add to history
            CopilotState.history.push({ role: "assistant", content: reply });

            // Render
            appendCopilotMessage("assistant", reply);
        }

    } catch (e) {
        removeThinkingIndicator();
        appendCopilotMessage("system-error",
            `Failed to reach backend: ${e.message}\n\nMake sure the FastAPI server is running on port 8000.`
        );
        CopilotState.history.pop();
    } finally {
        CopilotState.streaming = false;
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>`;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLEAR CONVERSATION
// ─────────────────────────────────────────────────────────────────────────────

function copilotClearChat() {
    CopilotState.history = [];
    CopilotState.sessionId = Math.random().toString(36).substring(2, 15);
    const container = document.getElementById("copilot-messages");
    if (container) {
        container.innerHTML = "";
        // Re-show welcome message
        appendCopilotMessage("assistant",
            "Hi! I can help you with Wazuh queries or general questions. If I'm unable to answer or understand your request, please contact the official Wazuh Community."
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KEYBOARD SHORTCUT
// ─────────────────────────────────────────────────────────────────────────────

function copilotInputKeydown(e) {
    // Ctrl+Enter or Cmd+Enter to send
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        copilotSend();
        return;
    }
    // Enter alone (no shift) sends only if textarea is single-line style
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        copilotSend();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTO-RESIZE TEXTAREA
// ─────────────────────────────────────────────────────────────────────────────

function copilotAutoResize(el) {
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 200) + "px";
}

// ─────────────────────────────────────────────────────────────────────────────
// VIEW ACTIVATION HOOK — called from app.js when view is switched
// ─────────────────────────────────────────────────────────────────────────────

function onCopilotViewActivated() {
    initCopilot().then(() => {
        // Show welcome message on first load
        const container = document.getElementById("copilot-messages");
        if (container && container.children.length === 0) {
            copilotClearChat();
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

window.copilotSend             = copilotSend;
window.copilotClearChat        = copilotClearChat;
window.copilotInputKeydown     = copilotInputKeydown;
window.copilotAutoResize       = copilotAutoResize;
window.onCopilotViewActivated  = onCopilotViewActivated;
window.initCopilot             = initCopilot;
