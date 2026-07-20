const chatMessages = document.getElementById("chat-messages");
const chatUserInput = document.getElementById("chat-user-input");
const chatOptionButtons = document.getElementById("chat-option-buttons");

let chatContext = {};
let libraryChatContext = {};
let libraryWizardId = null; // only set for library flows - dashboard quick-chat never saves history

// Helper: Get elements based on target ('dashboard' or 'library')
function getChatElements(target) {
    if (target === "library") {
        return {
            messages: document.getElementById("library-chat-messages"),
            userInput: document.getElementById("library-chat-user-input"),
            optionButtons: document.getElementById("library-chat-option-buttons")
        };
    } else {
        return {
            messages: document.getElementById("chat-messages"),
            userInput: document.getElementById("chat-user-input"),
            optionButtons: document.getElementById("chat-option-buttons")
        };
    }
}

// Print a bubble to the chat logs targeting dashboard or library
function printBubbleTarget(target, text, sender = "system") {
    const els = getChatElements(target);
    if (!els.messages) return;
    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${sender}`;
    bubble.textContent = text;
    els.messages.appendChild(bubble);
    els.messages.scrollTop = els.messages.scrollHeight;
}

function printBubble(text, sender = "system") {
    printBubbleTarget("dashboard", text, sender);
}

function printLibraryBubble(text, sender = "system") {
    printBubbleTarget("library", text, sender);
}

// Clear all active choices button panel
function clearOptionsTarget(target) {
    const els = getChatElements(target);
    if (els.optionButtons) {
        els.optionButtons.innerHTML = "";
    }
}

function clearOptions() {
    clearOptionsTarget("dashboard");
}

function clearLibraryOptions() {
    clearOptionsTarget("library");
}

// Render dynamic option buttons
function renderOptionsTarget(target, options, callback) {
    clearOptionsTarget(target);
    const els = getChatElements(target);
    if (!els.optionButtons) return;
    options.forEach(opt => {
        const btn = document.createElement("button");
        btn.className = "chat-option-btn";
        btn.textContent = opt;
        btn.onclick = () => {
            clearOptionsTarget(target);
            callback(opt);
        };
        els.optionButtons.appendChild(btn);
    });
    if (els.messages) {
        els.messages.scrollTop = els.messages.scrollHeight;
    }
}

function renderOptions(options, callback) {
    renderOptionsTarget("dashboard", options, callback);
}

function renderLibraryOptions(options, callback) {
    renderOptionsTarget("library", options, callback);
}

// Parse choice options from question strings: e.g. "Do X? (yes / no)" -> ["yes", "no"]
function parseQuestionOptions(question) {
    const regex = /\(([^)]+)\)\s*$/;
    const match = question.match(regex);
    if (match) {
        const optionsStr = match[1];
        // Split options by / or , and trim them
        const splitChar = optionsStr.includes('/') ? '/' : ',';
        const options = optionsStr.split(splitChar).map(o => o.trim()).filter(Boolean);
        
        // Return cleaned question (removing the trailing choices list) and options
        const cleanedQuestion = question.replace(regex, "").trim();
        return {
            question: cleanedQuestion,
            options: options
        };
    }
    return null;
}

// Handle sending messages to backend
async function sendChatMessageTarget(target, value) {
    // Print user text bubble
    printBubbleTarget(target, value, "user");
    
    // De-focus and show pending indicator
    clearOptionsTarget(target);
    
    if (target === "library" && !libraryWizardId) {
        libraryWizardId = Date.now().toString(36) + Math.random().toString(36).slice(2);
    }

    try {
        const currentContext = target === "library" ? libraryChatContext : chatContext;
        const res = await fetch(BASE_URL + "/assistant", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: value,
                context: currentContext,
                wizard_id: target === "library" ? libraryWizardId : undefined
            })
        });

        const text = await res.text();
        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            printBubbleTarget(target, "Error: Invalid JSON response received from backend API.", "system");
            console.error("JSON parse error:", e);
            return;
        }

        if (!data || !data.response) {
            printBubbleTarget(target, "Error: Empty reply received from diagnostics engine.", "system");
            return;
        }

        const r = data.response;

        if (r.type === "use_case") {
            if (target === "library") {
                libraryChatContext = r.context || {};
            } else {
                chatContext = r.context || {};
            }
            
            // Print main system display log
            if (r.display) {
                printBubbleTarget(target, r.display, "system");
            }
            
            // Parse options for any follow-up questions
            if (r.ask && r.ask.length > 0) {
                if (r.ask.length > 1) {
                    // Already a list of standalone option labels - render them
                    // directly as buttons, no parenthetical parsing needed.
                    renderOptionsTarget(target, r.ask, (selectedOpt) => {
                        sendChatMessageTarget(target, selectedOpt);
                    });
                } else {
                    const nextQuestion = r.ask[0];
                    const parsed = parseQuestionOptions(nextQuestion);

                    if (parsed && parsed.options.length > 0) {
                        printBubbleTarget(target, parsed.question, "system");
                        renderOptionsTarget(target, parsed.options, (selectedOpt) => {
                            sendChatMessageTarget(target, selectedOpt);
                        });
                    } else {
                        // No choices -> simple text input prompt
                        printBubbleTarget(target, nextQuestion, "system");
                    }
                }
            }

            if (r.done) {
                printBubbleTarget(target, "✔ Guided diagnostics flow has completed successfully.", "system");
                if (target === "library") {
                    libraryChatContext = {};
                    libraryWizardId = null; // saved to history server-side; next flow gets a fresh id
                    if (window.loadLibraryHistory) window.loadLibraryHistory();
                } else {
                    chatContext = {};
                }
            }
            
            return;
        }

        // Fallback text info response
        printBubbleTarget(target, r.message || "I did not find a matching troubleshooting guide. Please select an option from the library or provide more details.", "system");

    } catch (err) {
        console.error("Fetch error:", err);
        printBubbleTarget(target, "Error: Failed to connect to the backend troubleshooting service.", "system");
    }
}

function sendChatMessage(value) {
    sendChatMessageTarget("dashboard", value);
}

function sendLibraryChatMessage(value) {
    sendChatMessageTarget("library", value);
}

// Handle chat bar input text submission
function handleChatSubmit() {
    if (!chatUserInput) return;
    const value = chatUserInput.value.trim();
    chatUserInput.value = "";
    if (!value) return;

    sendChatMessage(value);
}

function handleLibraryChatSubmit() {
    const els = getChatElements("library");
    if (!els.userInput) return;
    const value = els.userInput.value.trim();
    els.userInput.value = "";
    if (!value) return;

    sendLibraryChatMessage(value);
}

// Run troubleshooting workflow from library selection or cards
function launchLibraryFlow(issueTitle) {
    // Clear library chat history
    const els = getChatElements("library");
    if (els.messages) {
        els.messages.innerHTML = "";
    }
    clearOptionsTarget("library");
    libraryChatContext = {}; // reset previous context
    libraryWizardId = null; // starting a new flow gets its own transcript/id

    printBubbleTarget("library", `Initializing Troubleshooting script for issue: "${issueTitle}"...`, "system");
    
    // Scroll smoothly to the Troubleshooting Library panel
    const chatPanel = document.getElementById("panel-library-troubleshooting");
    if (chatPanel) {
        chatPanel.scrollIntoView({ behavior: "smooth", block: "center" });
        // Flash/highlight border to guide user's eye
        chatPanel.style.transition = "outline 0.3s ease";
        chatPanel.style.outline = "2px solid var(--accent-blue)";
        setTimeout(() => {
            chatPanel.style.outline = "none";
        }, 1500);
    }
    
    // Send initial trigger keyword to route to the correct use case in library chat
    sendLibraryChatMessage(issueTitle);
}

// Function to reset assistant chat context
function resetChatContext() {
    chatContext = {};
    libraryChatContext = {};
    libraryWizardId = null;
}

// ── Previous Reports — download-only history, no resume ─────────────────────

function libEscapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

function libTimeAgo(isoString) {
    const seconds = Math.floor((new Date() - new Date(isoString)) / 1000);
    if (seconds < 60) return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    return `${days}d`;
}

async function loadLibraryHistory() {
    const panel = document.getElementById("library-history-panel");
    if (!panel) return;
    panel.innerHTML = '<div class="agent-history-empty">Loading...</div>';
    try {
        const res = await fetch(BASE_URL + "/assistant/history");
        const data = await res.json();
        const runs = data.runs || [];
        if (!runs.length) {
            panel.innerHTML = '<div class="agent-history-empty">No completed reports yet.</div>';
            return;
        }
        panel.innerHTML = "";
        runs.forEach(r => {
            const row = document.createElement("div");
            row.className = "agent-history-row";
            row.style.cursor = "default";
            row.innerHTML =
                `<span class="title" title="${libEscapeHtml(r.title)}">${libEscapeHtml(r.title)}</span>` +
                `<span class="time">${libTimeAgo(r.updated_at)}</span>` +
                `<button class="icon-btn" title="Download">` +
                `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></button>`;
            row.querySelector("button").addEventListener("click", () => {
                window.open(`${BASE_URL}/assistant/history/${encodeURIComponent(r.run_id)}/download`, "_blank");
            });
            panel.appendChild(row);
        });
    } catch (e) {
        panel.innerHTML = '<div class="agent-history-empty">Failed to load reports.</div>';
    }
}

function toggleLibraryHistory() {
    const panel = document.getElementById("library-history-panel");
    const showing = panel.style.display === "none" || !panel.style.display;
    panel.style.display = showing ? "block" : "none";
    if (showing) loadLibraryHistory();
}

document.addEventListener("click", (e) => {
    const panel = document.getElementById("library-history-panel");
    const btn = document.getElementById("library-history-btn");
    if (!panel || panel.style.display === "none") return;
    if (!panel.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
        panel.style.display = "none";
    }
});

// Bind to window for inline HTML callbacks and cross-file access
window.launchLibraryFlow = launchLibraryFlow;
window.sendChatMessage = sendChatMessage;
window.sendLibraryChatMessage = sendLibraryChatMessage;
window.printBubble = printBubble;
window.printLibraryBubble = printLibraryBubble;
window.clearOptions = clearOptions;
window.clearLibraryOptions = clearLibraryOptions;
window.renderOptions = renderOptions;
window.renderLibraryOptions = renderLibraryOptions;
window.resetChatContext = resetChatContext;
window.handleLibraryChatSubmit = handleLibraryChatSubmit;
window.toggleLibraryHistory = toggleLibraryHistory;
window.loadLibraryHistory = loadLibraryHistory;
window.handleChatSubmit = handleChatSubmit;

