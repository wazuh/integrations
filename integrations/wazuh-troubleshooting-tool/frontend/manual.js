// Start manual troubleshooting restart flow in the chat
function launchManualTroubleshooting(serviceName) {
    // Navigate to Dashboard using window.setView
    window.setView("home");
    
    // Clear chat history
    const chatMessages = document.getElementById("chat-messages");
    if (chatMessages) {
        chatMessages.innerHTML = "";
    }
    
    // Clear options panel
    if (window.clearOptions) {
        window.clearOptions();
    }
    
    // Reset assistant context
    if (window.resetChatContext) {
        window.resetChatContext();
    }
    
    // Scroll smoothly to chat wizard
    const chatPanel = document.getElementById("panel-troubleshooting-wizard");
    if (chatPanel) {
        chatPanel.scrollIntoView({ behavior: "smooth", block: "center" });
        chatPanel.style.transition = "outline 0.3s ease";
        chatPanel.style.outline = "2px solid var(--accent-blue)";
        setTimeout(() => {
            chatPanel.style.outline = "none";
        }, 1500);
    }
    
    if (window.printBubble) {
        window.printBubble(`I detected that ${serviceName} is not running. Would you like me to restart it now?`, "system");
    }
    
    if (window.renderOptions) {
        window.renderOptions(["Yes", "No"], (choice) => {
            handleManualChoice(serviceName, choice);
        });
    }
}

async function handleManualChoice(serviceName, choice) {
    if (window.printBubble) {
        window.printBubble(choice, "user");
    }
    if (window.clearOptions) {
        window.clearOptions();
    }
    
    if (choice === "Yes") {
        if (window.printBubble) {
            window.printBubble(`Attempting to restart ${serviceName}...`, "system");
        }
        
        try {
            // Call backend fix endpoint
            let res = await fetch(window.BASE_URL + "/fix?service=" + serviceName);
            let data = await res.json();
            
            // Check status (polling for up to 30 seconds if the service is starting/activating)
            let isFixed = (data.status_after_fix === "active" || data.status_after_fix === "ok");
            let checkData = null;
            
            if (!isFixed) {
                for (let attempt = 0; attempt < 10; attempt++) {
                    let checkRes = await fetch(window.BASE_URL + "/check");
                    checkData = await checkRes.json();
                    
                    // Refresh dashboard panels
                    if (window.updateServices) window.updateServices(checkData.checks);
                    if (window.updateCluster) window.updateCluster(checkData.cluster_details);
                    if (window.updateMemory) window.updateMemory(checkData.memory);
                    if (window.updateIssues) window.updateIssues(checkData.issues || []);
                    
                    const serviceStatus = checkData.checks.find(c => c.name === serviceName);
                    const currentStatus = serviceStatus ? serviceStatus.status : "";
                    
                    if (currentStatus === "active" || currentStatus === "ok") {
                        isFixed = true;
                        break;
                    }
                    
                    // If it's not active and not activating (e.g. failed/inactive/error) after 3 attempts, break early
                    if (currentStatus !== "activating" && attempt > 2) {
                        break;
                    }
                    
                    // Wait 3 seconds before next check
                    await new Promise(r => setTimeout(r, 3000));
                }
            } else {
                // If immediately active, do a quick status update to refresh the dashboard panels
                let checkRes = await fetch(window.BASE_URL + "/check");
                checkData = await checkRes.json();
                if (window.updateServices) window.updateServices(checkData.checks);
                if (window.updateCluster) window.updateCluster(checkData.cluster_details);
                if (window.updateMemory) window.updateMemory(checkData.memory);
                if (window.updateIssues) window.updateIssues(checkData.issues || []);
            }
            
            if (isFixed) {
                if (window.printBubble) {
                    window.printBubble(`✔ ${serviceName} restarted successfully and is now running!`, "system");
                }
            } else {
                if (window.printBubble) {
                    window.printBubble(data.message || `FAILED: ${serviceName} failed to start.`, "system");
                    window.printBubble(`✖ Failed to restart ${serviceName}. The service is still inactive.\nWould you like to search the Troubleshooting Library or share/download the diagnostics report to get help from the official Wazuh Community?`, "system");
                }
                if (window.renderOptions) {
                    window.renderOptions(["Troubleshooting Library", "Share with Wazuh Community"], (fallbackChoice) => {
                        handleFallbackChoice(fallbackChoice);
                    });
                }
            }
        } catch (e) {
            console.error(e);
            if (window.printBubble) {
                window.printBubble(`Error: Failed to communicate with backend to restart ${serviceName}.`, "system");
            }
            if (window.renderOptions) {
                window.renderOptions(["Troubleshooting Library", "Share with Wazuh Community"], (fallbackChoice) => {
                    handleFallbackChoice(fallbackChoice);
                });
            }
        }
    } else {
        if (window.printBubble) {
            window.printBubble(`Restart cancelled. If you want to perform deep diagnostics, you can search the Troubleshooting Library or share/download the diagnostics report to get help from the official Wazuh Community.`, "system");
        }
        if (window.renderOptions) {
            window.renderOptions(["Troubleshooting Library", "Share with Wazuh Community"], (fallbackChoice) => {
                handleFallbackChoice(fallbackChoice);
            });
        }
    }
}

function handleFallbackChoice(choice) {
    if (window.printBubble) {
        window.printBubble(choice, "user");
    }
    if (window.clearOptions) {
        window.clearOptions();
    }
    if (choice === "Troubleshooting Library") {
        window.setView("library");
    } else if (choice === "Share with Wazuh Community") {
        if (window.downloadReport) {
            window.downloadReport();
        }
        if (window.printBubble) {
            window.printBubble("I have generated and downloaded your diagnostics report. Please upload it and share your issue on the official Wazuh community forum at https://wazuh.com/community/ to get help from experts.", "system");
        }
    }
}

// Bind to window for inline HTML callbacks and cross-file access
window.launchManualTroubleshooting = launchManualTroubleshooting;
window.handleManualChoice = handleManualChoice;
window.handleFallbackChoice = handleFallbackChoice;

