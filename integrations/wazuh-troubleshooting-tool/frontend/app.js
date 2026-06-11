let BASE_URL = "http://localhost:8000"; // default fallback

async function loadConfig() {
    const savedUrl = localStorage.getItem("wazuh_api_url");
    if (savedUrl) {
        BASE_URL = savedUrl;
        window.BASE_URL = BASE_URL;
        return;
    }
    try {
        const response = await fetch("config.json");
        const config = await response.json();
        if (config.api_url) {
            BASE_URL = config.api_url;
            window.BASE_URL = BASE_URL;
        }
    } catch (e) {
        const host = window.location.hostname || "localhost";
        BASE_URL = `http://${host}:8000`;
        window.BASE_URL = BASE_URL;
    }
}
let AUTO_CHECK = localStorage.getItem("wazuh_auto_check") !== "false"; // default true
let REFRESH_INTERVAL = parseInt(localStorage.getItem("wazuh_refresh_interval") || "30"); // default 30s

let activeIssues = [];
let lastCheckSnapshot = null;

// Session details (stable for session lifetime)
const SESSION_ID = Math.random().toString(36).substring(2, 10).toUpperCase();
const SESSION_START = new Date();

// Initialize header toolbar details
document.getElementById("sessionId").textContent = SESSION_ID;
document.getElementById("sessionStarted").textContent = SESSION_START.toLocaleString();

// Background timer for auto-refresh
let refreshTimerId = null;

// -------------------------------------------------------
// CLIENT ROUTING (SPA VIEW SWITCHER)
// -------------------------------------------------------
function setView(viewName) {
    document.querySelectorAll(".view").forEach(view => {
        view.classList.toggle("active", view.id === "view-" + viewName);
    });

    document.querySelectorAll(".sidebar-item").forEach(item => {
        item.classList.toggle("active", item.dataset.view === viewName);
    });
}

// Bind navigation click handlers
document.querySelectorAll(".sidebar-item").forEach(item => {
    item.addEventListener("click", (e) => {
        const view = item.dataset.view;
        if (view) setView(view);
    });
});

// -------------------------------------------------------
// HEALTH CHECK LOGGING
// -------------------------------------------------------
function logPrint(text) {
    const el = document.getElementById("logs");
    if (!el) return;
    el.textContent += text + "\n";
    el.scrollTop = el.scrollHeight;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// -------------------------------------------------------
// METRICS RENDERING
// -------------------------------------------------------
function updateServices(checks) {
    const el = document.getElementById("services");
    el.innerHTML = "";
    checks.forEach(c => {
        let badgeClass = "warning";
        if (c.status === "active" || c.status === "ok") badgeClass = "healthy";
        else if (c.status === "inactive" || c.status === "error") badgeClass = "critical";
        
        el.innerHTML += `
            <div class="health-item">
                <span class="health-item-name">${c.name}</span>
                <span class="badge ${badgeClass}">${c.status}</span>
            </div>`;
    });
}

function updateCluster(c) {
    const statusEl = document.getElementById("cluster-status-text");
    const nodesEl = document.getElementById("cluster-nodes");
    const shardsEl = document.getElementById("cluster-shards");
    const unassignedEl = document.getElementById("cluster-unassigned");
    const cardStatusEl = document.getElementById("card-cluster-status");

    if (!c) {
        statusEl.textContent = "No data";
        return;
    }

    let statusText = c.status.toUpperCase();
    statusEl.textContent = statusText;
    cardStatusEl.textContent = statusText;
    
    if (c.status === "green") {
        statusEl.style.color = "var(--accent-green)";
        cardStatusEl.style.color = "var(--accent-green)";
    } else if (c.status === "yellow") {
        statusEl.style.color = "var(--accent-yellow)";
        cardStatusEl.style.color = "var(--accent-yellow)";
    } else {
        statusEl.style.color = "var(--accent-red)";
        cardStatusEl.style.color = "var(--accent-red)";
    }

    nodesEl.textContent = c.number_of_nodes;
    shardsEl.textContent = c.active_shards;
    unassignedEl.textContent = c.unassigned_shards;
}

function updateMemory(m) {
    document.getElementById("mem-total").textContent = `${m.total} MB`;
    document.getElementById("mem-used").textContent = `${m.used} MB`;
    document.getElementById("mem-free").textContent = `${m.free} MB`;

    const percent = m.total > 0 ? Math.round((m.used / m.total) * 100) : 0;
    document.getElementById("mem-percent").textContent = `${percent}%`;
    document.getElementById("mem-progress").style.width = `${percent}%`;
}

function updateIssues(list) {
    const el = document.getElementById("issues");
    const countEl = document.getElementById("card-active-issues");
    
    if (!list || list.length === 0) {
        countEl.textContent = "0";
        countEl.style.color = "var(--accent-green)";
        el.innerHTML = `
            <div style="color: var(--accent-green); text-align: center; padding: 20px 0; font-weight: 500;">
                ✔ No issues detected. System is running healthy.
            </div>`;
        return;
    }

    countEl.textContent = list.length;
    countEl.style.color = "var(--accent-red)";
    
    el.innerHTML = list.map((issue, idx) => `
        <div class="issue-card">
            <div class="issue-card-desc">
                <svg class="issue-card-icon" viewBox="0 0 24 24" fill="none" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <span class="issue-card-text"><b>${issue}</b> is NOT running</span>
            </div>
            <button class="primary" onclick="launchManualTroubleshooting('${issue}')">Troubleshoot</button>
        </div>
    `).join("");
}

// -------------------------------------------------------
// SYSTEM DIAGNOSTICS CHECK
// -------------------------------------------------------
async function startCheck() {
    const logsEl = document.getElementById("logs");
    const overallStatusEl = document.getElementById("card-overall-status");
    const onlineEl = document.getElementById("card-services-online");

    logsEl.textContent = "";
    logPrint("Starting system health checks...\n");

    try {
        let res = await fetch(BASE_URL + "/check");
        let data = await res.json();

        activeIssues = data.issues || [];
        const checkTime = new Date().toLocaleString();
        
        lastCheckSnapshot = {
            time: checkTime,
            checks: data.checks,
            cluster: data.cluster_details,
            memory: data.memory,
            issues: activeIssues
        };

        // Update last check in top toolbar
        document.getElementById("sessionLastCheck").textContent = checkTime;

        // Render UI
        updateServices(data.checks);
        updateCluster(data.cluster_details);
        updateMemory(data.memory);
        updateIssues(activeIssues);

        // Update overall service statistics
        const healthyCount = data.checks.filter(c => c.status === "active" || c.status === "ok").length;
        onlineEl.textContent = `${healthyCount} of ${data.checks.length}`;
        
        if (activeIssues.length === 0) {
            overallStatusEl.textContent = "HEALTHY";
            overallStatusEl.style.color = "var(--accent-green)";
            document.getElementById("sessionStatusPill").className = "status-pill";
        } else {
            overallStatusEl.textContent = "DEGRADED";
            overallStatusEl.style.color = "var(--accent-red)";
            document.getElementById("sessionStatusPill").className = "status-pill offline";
        }

        // Print interactive logs
        for (const c of data.checks) {
            logPrint(`Checking ${c.name}...`);
            await sleep(150);
            logPrint(`Status: ${c.status.toUpperCase()}\n`);
        }

        if (activeIssues.length === 0) {
            logPrint("[OK] All checks completed. No errors found.");
        } else {
            logPrint(`[WARNING] Completed checks. Found ${activeIssues.length} service issue(s).`);
        }

    } catch (e) {
        logPrint("[ERROR] Failed to fetch system checks from backend api. Ensure the backend uvicorn server is running.");
        console.error(e);
        overallStatusEl.textContent = "OFFLINE";
        overallStatusEl.style.color = "var(--accent-red)";
        document.getElementById("sessionStatusPill").className = "status-pill offline";
    }
}

// -------------------------------------------------------
// QUICK SYSTEM ACTIONS
// -------------------------------------------------------
async function quickRestart(service) {
    setView("home");
    const logsEl = document.getElementById("logs");
    logsEl.textContent = "";
    logPrint(`Executing system restart command for service: ${service}...`);
    
    try {
        let res = await fetch(BASE_URL + "/fix?service=" + service);
        let data = await res.json();
        logPrint(`Backend response:\n${data.message}`);
        // Run check to refresh UI
        startCheck();
    } catch (e) {
        logPrint("[ERROR] Failed to execute restart action.");
        console.error(e);
    }
}

async function checkFilebeat() {
    setView("home");
    const logsEl = document.getElementById("logs");
    logsEl.textContent = "";
    logPrint("Testing Filebeat configurations and server output connectivity...");
    
    try {
        let res = await fetch(BASE_URL + "/filebeat-test");
        let data = await res.json();
        logPrint(data.output);
    } catch (e) {
        logPrint("[ERROR] Failed to query Filebeat output test.");
        console.error(e);
    }
}

// -------------------------------------------------------
// SETTINGS PERSISTENCE
// -------------------------------------------------------
function loadSettings() {
    document.getElementById("settings-api-url").value = BASE_URL;
    document.getElementById("settings-auto-check").checked = AUTO_CHECK;
    document.getElementById("settings-refresh").value = REFRESH_INTERVAL;

    // Start background auto-refresh
    setupAutoRefresh();
}

function saveSettings() {
    const apiInput = document.getElementById("settings-api-url").value.trim();
    const autoCheckInput = document.getElementById("settings-auto-check").checked;
    const refreshInput = document.getElementById("settings-refresh").value;

    BASE_URL = apiInput;
    AUTO_CHECK = autoCheckInput;
    REFRESH_INTERVAL = parseInt(refreshInput);

    localStorage.setItem("wazuh_api_url", BASE_URL);
    localStorage.setItem("wazuh_auto_check", AUTO_CHECK);
    localStorage.setItem("wazuh_refresh_interval", REFRESH_INTERVAL);

    // Save alerts Dash source url as well
    const iframe = document.getElementById("reports-iframe");
    if (iframe) iframe.src = "about:blank"; // force reload on next click

    setupAutoRefresh();
    alert("Settings saved successfully!");
    setView("home");
    
    if (AUTO_CHECK) {
        startCheck();
    }
}

function setupAutoRefresh() {
    if (refreshTimerId) {
        clearInterval(refreshTimerId);
        refreshTimerId = null;
    }

    if (REFRESH_INTERVAL > 0) {
        refreshTimerId = setInterval(() => {
            console.log("Automated background check running...");
            startCheck();
        }, REFRESH_INTERVAL * 1000);
    }
}

// -------------------------------------------------------
// REPORT DOWNLOADING & GENERATING
// -------------------------------------------------------
async function downloadReport() {
    const downloadBtn = document.getElementById("btn-toolbar-download");
    let originalBtnContent = "";
    if (downloadBtn) {
        originalBtnContent = downloadBtn.innerHTML;
        downloadBtn.disabled = true;
        downloadBtn.innerHTML = `
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
            </svg>
            <span>Summarizing...</span>
        `;
    }

    const now = new Date();
    const duration = Math.round((now - SESSION_START) / 1000);
    const mins = Math.floor(duration / 60);
    const secs = duration % 60;

    let checkSection = "No system diagnostics health check was run in this session.";
    if (lastCheckSnapshot) {
        const s = lastCheckSnapshot;
        const servicesLines = (s.checks || [])
            .map(c => `  ${c.name.padEnd(20)} : ${c.status.toUpperCase()}`)
            .join("\n");
        const issuesLines = s.issues.length === 0
            ? "  None"
            : s.issues.map(i => `  - ${i} is NOT running`).join("\n");

        checkSection =
`Check Timestamp : ${s.time}

Monitored Services:
-------------------
${servicesLines}

Indexer Cluster Metrics:
-----------------------
  Health Status   : ${s.cluster.status.toUpperCase()}
  Nodes Count     : ${s.cluster.number_of_nodes}
  Active Shards   : ${s.cluster.active_shards}
  Unassigned      : ${s.cluster.unassigned_shards}

System Memory Info:
------------------
  Total Memory    : ${s.memory.total} MB
  Used Memory     : ${s.memory.used} MB
  Free Memory     : ${s.memory.free} MB

Active Issues Detected:
----------------------
${issuesLines}`;
    }

    // Capture the troubleshooting logs from screen
    const chatLogs = Array.from(document.querySelectorAll("#chat-messages .chat-bubble"))
        .map(bubble => {
            const sender = bubble.classList.contains("user") ? "User" : "System";
            const cleanedText = bubble.innerText.trim().replace(/\s+/g, ' ');
            return `[${sender}] ${cleanedText}`;
        })
        .join("\n\n");

    const libraryChatLogs = Array.from(document.querySelectorAll("#library-chat-messages .chat-bubble"))
        .map(bubble => {
            const sender = bubble.classList.contains("user") ? "User" : "System";
            const cleanedText = bubble.innerText.trim().replace(/\s+/g, ' ');
            return `[${sender}] ${cleanedText}`;
        })
        .join("\n\n");

    let conversationSection = "";
    if (chatLogs.trim()) {
        conversationSection += `--- Wizard Chat Logs (Dashboard) ---\n${chatLogs}\n\n`;
    }
    if (libraryChatLogs.trim()) {
        conversationSection += `--- Library Diagnostics Logs (Troubleshooting Library) ---\n${libraryChatLogs}\n\n`;
    }

    conversationSection = conversationSection.trim();
    const hasConversation = chatLogs.trim() || libraryChatLogs.trim();

    // Determine issue title
    let issueTitle = "No active service issue detected";
    if (libraryChatLogs.trim()) {
        const initMatch = libraryChatLogs.match(/Initializing Troubleshooting script for issue: "([^"]+)"/);
        if (initMatch) {
            issueTitle = initMatch[1];
        } else {
            const lines = libraryChatLogs.split("\n");
            for (const line of lines) {
                if (line.startsWith("[User] ")) {
                    issueTitle = line.replace("[User] ", "").trim();
                    break;
                }
            }
        }
    } else if (chatLogs.trim()) {
        const detectMatch = chatLogs.match(/I detected that ([^ ]+) is not running/);
        if (detectMatch) {
            issueTitle = `${detectMatch[1]} is not running`;
        } else {
            issueTitle = "System health troubleshooting";
        }
    }

    // -------------------------------------------------------
    // AI SUMMARY via /summarize endpoint
    // -------------------------------------------------------
    let summaryText = "No troubleshooting conversation in this session.";
    if (hasConversation) {
        try {
            const res = await fetch(BASE_URL + "/summarize", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    conversation: conversationSection,
                    system_info: lastCheckSnapshot ? `
Cluster Health : ${lastCheckSnapshot.cluster.status.toUpperCase()}
Cluster Nodes  : ${lastCheckSnapshot.cluster.number_of_nodes}
Active Shards  : ${lastCheckSnapshot.cluster.active_shards}
Unassigned     : ${lastCheckSnapshot.cluster.unassigned_shards}
Total RAM      : ${lastCheckSnapshot.memory.total} MB
Used RAM       : ${lastCheckSnapshot.memory.used} MB
Free RAM       : ${lastCheckSnapshot.memory.free} MB
Services       : ${lastCheckSnapshot.checks.map(c => c.name + '=' + c.status).join(', ')}
                    `.trim() : "Not available."
                })
	    });
            if (res.ok) {
                const data = await res.json();
                summaryText = data.summary || "Summary unavailable.";
            } else {
                summaryText = "Summary unavailable (backend error).";
            }
        } catch (e) {
            summaryText = "Summary unavailable (could not reach backend).";
        }
    }

    let finalConversationBlock = "";
    if (hasConversation) {
        finalConversationBlock = `The issue is : ${issueTitle}

Summary : ${summaryText}

Detailed Conversation :
${conversationSection}`;
    } else {
        finalConversationBlock = "No active troubleshooting dialog sessions in this run.";
    }

    const report =
`================================================================================
  WAZUH TROUBLESHOOTING PORTAL - DIAGNOSTICS REPORT
================================================================================

Session Identification : ${SESSION_ID}
Session Started        : ${SESSION_START.toLocaleString()}
Report Generated       : ${now.toLocaleString()}
Session Active Time    : ${mins}m ${secs}s

================================================================================
  SYSTEM CHECK DIAGNOSTIC SNAPSHOT
================================================================================

${checkSection}

================================================================================
  INTERACTIVE TROUBLESHOOTING CONVERSATION LOGS
================================================================================

${finalConversationBlock}

================================================================================
  END OF DIAGNOSTIC EXPORT
================================================================================
`;

    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `wazuh-diagnostics-report-${SESSION_ID}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    if (downloadBtn) {
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = originalBtnContent;
    }
}

// -------------------------------------------------------
// ON INITIAL PAGE LOAD
// -------------------------------------------------------
window.addEventListener("DOMContentLoaded", async () => {
    await loadConfig();
    loadSettings();
    if (AUTO_CHECK) {
        startCheck();
    }
});

// Export globally accessible functions to window object
window.setView = setView;
window.updateServices = updateServices;
window.updateCluster = updateCluster;
window.updateMemory = updateMemory;
window.updateIssues = updateIssues;
window.startCheck = startCheck;
window.downloadReport = downloadReport;
window.SESSION_ID = SESSION_ID;
window.BASE_URL = BASE_URL;
