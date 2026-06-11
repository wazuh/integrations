const chatMessages = document.getElementById("chat-messages");
const chatUserInput = document.getElementById("chat-user-input");
const chatOptionButtons = document.getElementById("chat-option-buttons");

let chatContext = {};
let libraryChatContext = {};

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
    
    try {
        const currentContext = target === "library" ? libraryChatContext : chatContext;
        const res = await fetch(BASE_URL + "/assistant", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: value,
                context: currentContext
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

            if (r.done) {
                printBubbleTarget(target, "✔ Guided diagnostics flow has completed successfully.", "system");
                if (target === "library") {
                    libraryChatContext = {};
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
}

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
window.handleChatSubmit = handleChatSubmit;

