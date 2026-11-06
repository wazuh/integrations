// Reports & Operations Center Javascript Engine

let activeReportData = null;
let activeReportType = "";

// View switcher functions
function backToReportsHub() {
    document.getElementById("reports-hub").style.display = "block";
    document.getElementById("report-view-container").style.display = "none";
}

function showCustomReportBuilder() {
    document.getElementById("custom-builder-panel").style.display = "block";
}

function hideCustomReportBuilder() {
    document.getElementById("custom-builder-panel").style.display = "none";
}

// Global reports generator entry point
async function generateReport(type) {
    activeReportType = type;
    const bodyEl = document.getElementById("report-document-body");
    bodyEl.replaceChildren();
    
    const loading = document.createElement("div");
    loading.style.textAlign = "center";
    loading.style.padding = "40px";
    loading.style.color = "var(--text-secondary)";
    loading.textContent = "Connecting to Wazuh API and generating report data...";
    bodyEl.appendChild(loading);
    
    document.getElementById("reports-hub").style.display = "none";
    document.getElementById("report-view-container").style.display = "block";
    
    try {
        const res = await fetch(`${window.BASE_URL}/reports?type=${type}`);
        const data = await res.json();
        activeReportData = data;
        
        renderReportDocument(type, data, bodyEl);
    } catch (e) {
        console.error(e);
        bodyEl.replaceChildren();
        const errCard = document.createElement("div");
        errCard.className = "issue-card";
        errCard.style.background = "rgba(244, 63, 94, 0.1)";
        errCard.style.borderColor = "var(--accent-red)";
        
        const errText = document.createElement("span");
        errText.className = "issue-card-text";
        errText.textContent = `Error generating report: Failed to communicate with reports backend API.`;
        errCard.appendChild(errText);
        bodyEl.appendChild(errCard);
    }
}

async function generateCustomReport() {
    activeReportType = "custom";
    const bodyEl = document.getElementById("report-document-body");
    bodyEl.replaceChildren();
    
    const sections = [];
    if (document.getElementById("cb-section-agents").checked) sections.push("agents");
    if (document.getElementById("cb-section-dashboard").checked) sections.push("dashboard");
    if (document.getElementById("cb-section-dataflow").checked) sections.push("dataflow");
    if (document.getElementById("cb-section-cluster").checked) sections.push("cluster");
    if (document.getElementById("cb-section-api").checked) sections.push("api");
    if (document.getElementById("cb-section-environment").checked) sections.push("environment");
    if (document.getElementById("cb-section-security").checked) sections.push("security");
    
    if (sections.length === 0) {
        alert("Please select at least one section to include in the report.");
        return;
    }
    
    const loading = document.createElement("div");
    loading.style.textAlign = "center";
    loading.style.padding = "40px";
    loading.style.color = "var(--text-secondary)";
    loading.textContent = "Compiling customized operational report...";
    bodyEl.appendChild(loading);
    
    document.getElementById("reports-hub").style.display = "none";
    document.getElementById("report-view-container").style.display = "block";
    
    try {
        const res = await fetch(`${window.BASE_URL}/reports?type=custom&sections=${sections.join(",")}`);
        const data = await res.json();
        activeReportData = data;
        
        renderReportDocument("custom", data, bodyEl);
    } catch (e) {
        console.error(e);
        bodyEl.replaceChildren();
        const errCard = document.createElement("div");
        errCard.className = "issue-card";
        errCard.textContent = "Error: Failed to generate custom report.";
        bodyEl.appendChild(errCard);
    }
}

// Document layout dispatch
function renderReportDocument(type, data, container) {
    container.replaceChildren();
    
    // Header Info
    const header = document.createElement("div");
    header.style.borderBottom = "1px solid rgba(255,255,255,0.1)";
    header.style.paddingBottom = "20px";
    header.style.marginBottom = "30px";
    
    const title = document.createElement("h2");
    title.style.fontSize = "26px";
    title.style.fontWeight = "700";
    title.style.color = "var(--accent-blue)";
    title.className = "report-title";
    
    const subtitle = document.createElement("p");
    subtitle.style.color = "var(--text-secondary)";
    subtitle.style.fontSize = "13.5px";
    subtitle.style.marginTop = "5px";
    subtitle.className = "report-meta";
    
    const timestampStr = new Date().toLocaleString();
    
    if (type === "agent") {
        title.textContent = "Wazuh Agent Fleet Health Report";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Registered Wazuh endpoint agents`;
    } else if (type === "dashboard") {
        title.textContent = "Wazuh Dashboard Health & Performance";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Kibana/Dashboard service metrics`;
    } else if (type === "dataflow") {
        title.textContent = "Alert Ingestion & Data Pipeline Diagnostics";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Indexer ingestion data flow`;
    } else if (type === "cluster") {
        title.textContent = "Wazuh Indexer Database Cluster Report";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Cluster nodes and shard allocation`;
    } else if (type === "environment") {
        title.textContent = "Wazuh Environment Operational Assessment";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Platform integrity and security risks`;
    } else if (type === "security") {
        title.textContent = "Wazuh Security Events Report";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Historical security alert trends and rule distributions`;
    } else if (type === "custom") {
        title.textContent = "Consolidated Wazuh Custom Operational Report";
        subtitle.textContent = `Generated: ${timestampStr} | Scope: Selected environment sections`;
    }
    
    header.appendChild(title);
    header.appendChild(subtitle);
    container.appendChild(header);
    
    // If fallback warnings exist, display them
    if (data.status === "warning" || data.connection_error) {
        const warn = document.createElement("div");
        warn.style.background = "rgba(245,158,11,0.1)";
        warn.style.border = "1px solid rgba(245,158,11,0.3)";
        warn.style.borderRadius = "8px";
        warn.style.padding = "12px 18px";
        warn.style.marginBottom = "25px";
        warn.style.color = "var(--accent-yellow)";
        warn.style.fontSize = "13.5px";
        warn.textContent = "⚠ Warning: Connection to the live API timed out or failed. Displaying simulated cached snapshot metrics.";
        container.appendChild(warn);
    }
    
    // Render specific sections
    if (type === "agent") {
        renderAgentSection(data, container);
    } else if (type === "dashboard") {
        renderDashboardSection(data, container);
    } else if (type === "dataflow") {
        renderDataflowSection(data, container);
    } else if (type === "cluster") {
        renderClusterSection(data, container);
    } else if (type === "environment") {
        renderEnvironmentSection(data, container);
    } else if (type === "security") {
        renderSecuritySection(data, container);
    } else if (type === "custom") {
        if (data.agents) {
            const h = document.createElement("h3");
            h.textContent = "Section 1: Agent Fleet Health";
            h.style.color = "var(--accent-blue)";
            h.style.marginTop = "40px";
            container.appendChild(h);
            renderAgentSection(data.agents, container);
        }
        if (data.dashboard) {
            const h = document.createElement("h3");
            h.textContent = "Section 2: Dashboard Health";
            h.style.color = "var(--accent-blue)";
            h.style.marginTop = "40px";
            container.appendChild(h);
            renderDashboardSection(data.dashboard, container);
        }
        if (data.dataflow) {
            const h = document.createElement("h3");
            h.textContent = "Section 3: Indexing & Data Pipeline";
            h.style.color = "var(--accent-blue)";
            h.style.marginTop = "40px";
            container.appendChild(h);
            renderDataflowSection(data.dataflow, container);
        }
        if (data.cluster) {
            const h = document.createElement("h3");
            h.textContent = "Section 4: Database Cluster Health";
            h.style.color = "var(--accent-blue)";
            h.style.marginTop = "40px";
            container.appendChild(h);
            renderClusterSection(data.cluster, container);
        }
        if (data.environment) {
            const h = document.createElement("h3");
            h.textContent = "Section 5: Environmental Assessment findings";
            h.style.color = "var(--accent-blue)";
            h.style.marginTop = "40px";
            container.appendChild(h);
            renderEnvironmentSection(data.environment, container);
        }
        if (data.security) {
            const h = document.createElement("h3");
            h.textContent = "Section 6: Security Events Analysis";
            h.style.color = "var(--accent-blue)";
            h.style.marginTop = "40px";
            container.appendChild(h);
            renderSecuritySection(data.security, container);
        }
    }
}

// 1. Agent Section Renderer
function renderAgentSection(data, container) {
    // Metrics layout
    const grid = document.createElement("div");
    grid.className = "metric-row";
    grid.style.display = "grid";
    grid.style.gridTemplateColumns = "repeat(4, 1fr)";
    grid.style.gap = "15px";
    grid.style.marginBottom = "30px";
    
    const cards = [
        { label: "Total Agents", val: data.summary.total, color: "var(--accent-blue)" },
        { label: "Active", val: data.summary.active, color: "var(--accent-green)" },
        { label: "Disconnected", val: data.summary.disconnected, color: "var(--accent-red)" },
        { label: "Never Connected", val: data.summary.never_connected, color: "var(--text-secondary)" }
    ];
    
    cards.forEach(c => {
        const card = document.createElement("div");
        card.className = "metric-card";
        card.style.background = "rgba(255,255,255,0.02)";
        card.style.border = "1px solid rgba(255,255,255,0.06)";
        card.style.padding = "15px";
        card.style.borderRadius = "8px";
        card.style.textAlign = "center";
        
        const lbl = document.createElement("div");
        lbl.textContent = c.label;
        lbl.style.fontSize = "12px";
        lbl.style.color = "var(--text-secondary)";
        
        const val = document.createElement("div");
        val.className = "metric-value";
        val.textContent = c.val;
        val.style.fontSize = "26px";
        val.style.fontWeight = "700";
        val.style.marginTop = "5px";
        val.style.color = c.color;
        
        card.appendChild(lbl);
        card.appendChild(val);
        grid.appendChild(card);
    });
    container.appendChild(grid);
    
    // Distribution row
    const row = document.createElement("div");
    row.style.display = "grid";
    row.style.gridTemplateColumns = "1fr 1fr";
    row.style.gap = "25px";
    row.style.marginBottom = "30px";
    
    // Left: OS breakdown bar chart
    const left = document.createElement("div");
    left.className = "report-section";
    const leftTitle = document.createElement("h4");
    leftTitle.className = "section-title";
    leftTitle.textContent = "Agent Fleet Operating Systems";
    leftTitle.style.marginBottom = "15px";
    leftTitle.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
    leftTitle.style.paddingBottom = "5px";
    left.appendChild(leftTitle);
    
    if (data.os_breakdown && Object.keys(data.os_breakdown).length > 0) {
        const chart = renderBarChart(data.os_breakdown);
        left.appendChild(chart);
    } else {
        const placeholder = document.createElement("div");
        placeholder.textContent = "No OS distribution data available.";
        placeholder.style.color = "var(--text-secondary)";
        left.appendChild(placeholder);
    }
    row.appendChild(left);
    
    // Right: Communication Issues
    const right = document.createElement("div");
    right.className = "report-section";
    const rightTitle = document.createElement("h4");
    rightTitle.className = "section-title";
    rightTitle.textContent = "Agent Communication & Uptime Alerts";
    rightTitle.style.marginBottom = "15px";
    rightTitle.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
    rightTitle.style.paddingBottom = "5px";
    right.appendChild(rightTitle);
    
    if (data.communication_issues && data.communication_issues.length > 0) {
        const table = document.createElement("table");
        table.style.width = "100%";
        table.style.borderCollapse = "collapse";
        
        const thead = document.createElement("thead");
        const trHead = document.createElement("tr");
        ["Agent ID", "Name", "IP Address", "Last Seen"].forEach(hText => {
            const th = document.createElement("th");
            th.textContent = hText;
            th.style.padding = "8px";
            th.style.borderBottom = "1px solid rgba(255,255,255,0.1)";
            th.style.textAlign = "left";
            th.style.fontSize = "13px";
            trHead.appendChild(th);
        });
        thead.appendChild(trHead);
        table.appendChild(thead);
        
        const tbody = document.createElement("tbody");
        data.communication_issues.forEach(issue => {
            const tr = document.createElement("tr");
            [issue.id, issue.name, issue.ip, new Date(issue.lastKeepAlive).toLocaleString()].forEach(cellVal => {
                const td = document.createElement("td");
                td.textContent = cellVal;
                td.style.padding = "8px";
                td.style.fontSize = "13px";
                td.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        right.appendChild(table);
    } else {
        const healthy = document.createElement("div");
        healthy.style.color = "var(--accent-green)";
        healthy.style.fontWeight = "600";
        healthy.style.fontSize = "14px";
        healthy.style.padding = "20px 0";
        healthy.textContent = "✔ No agent communication anomalies or alerts identified.";
        right.appendChild(healthy);
    }
    row.appendChild(right);
    container.appendChild(row);
}

// 2. Dashboard Section Renderer
function renderDashboardSection(data, container) {
    const grid = document.createElement("div");
    grid.style.display = "grid";
    grid.style.gridTemplateColumns = "1fr 1fr";
    grid.style.gap = "25px";
    grid.style.marginBottom = "30px";
    
    // Left: Dashboard Service status
    const left = document.createElement("div");
    left.className = "report-section";
    const leftTitle = document.createElement("h4");
    leftTitle.className = "section-title";
    leftTitle.textContent = "Dashboard Daemon Status";
    leftTitle.style.marginBottom = "15px";
    left.appendChild(leftTitle);
    
    const svc = document.createElement("div");
    svc.style.display = "flex";
    svc.style.alignItems = "center";
    svc.style.gap = "12px";
    svc.style.background = "rgba(255,255,255,0.02)";
    svc.style.padding = "15px";
    svc.style.borderRadius = "8px";
    svc.style.border = "1px solid rgba(255,255,255,0.06)";
    
    const label = document.createElement("span");
    label.textContent = "wazuh-dashboard status:";
    label.style.fontWeight = "600";
    
    const badge = document.createElement("span");
    badge.className = `badge ${data.dashboard_service === "active" ? "healthy" : "critical"}`;
    badge.textContent = data.dashboard_service.toUpperCase();
    
    svc.appendChild(label);
    svc.appendChild(badge);
    left.appendChild(svc);
    
    // Memory/CPU progress bars
    const metricsDiv = document.createElement("div");
    metricsDiv.style.marginTop = "20px";
    metricsDiv.style.display = "flex";
    metricsDiv.style.flexDirection = "column";
    metricsDiv.style.gap = "15px";
    
    // CPU
    const cpuDiv = document.createElement("div");
    const cpuLbl = document.createElement("div");
    cpuLbl.style.display = "flex";
    cpuLbl.style.justifyContent = "space-between";
    cpuLbl.style.fontSize = "13px";
    cpuLbl.style.color = "var(--text-secondary)";
    cpuLbl.innerHTML = `<span>Manager CPU Usage</span><span>${data.system_metrics.cpu_usage}%</span>`;
    cpuDiv.appendChild(cpuLbl);
    
    const cpuBg = document.createElement("div");
    cpuBg.className = "progress-bar-bg";
    const cpuFill = document.createElement("div");
    cpuFill.className = "progress-bar-fill";
    cpuFill.style.width = `${data.system_metrics.cpu_usage}%`;
    cpuBg.appendChild(cpuFill);
    cpuDiv.appendChild(cpuBg);
    metricsDiv.appendChild(cpuDiv);
    
    // RAM
    const ramDiv = document.createElement("div");
    const ramLbl = document.createElement("div");
    ramLbl.style.display = "flex";
    ramLbl.style.justifyContent = "space-between";
    ramLbl.style.fontSize = "13px";
    ramLbl.style.color = "var(--text-secondary)";
    ramLbl.innerHTML = `<span>Manager Memory Usage</span><span>${data.system_metrics.memory_utilization}% (${data.system_metrics.memory_usage_mb} MB / ${data.system_metrics.memory_total_mb} MB)</span>`;
    ramDiv.appendChild(ramLbl);
    
    const ramBg = document.createElement("div");
    ramBg.className = "progress-bar-bg";
    const ramFill = document.createElement("div");
    ramFill.className = "progress-bar-fill";
    ramFill.style.width = `${data.system_metrics.memory_utilization}%`;
    ramBg.appendChild(ramFill);
    ramDiv.appendChild(ramBg);
    metricsDiv.appendChild(ramDiv);
    
    left.appendChild(metricsDiv);
    grid.appendChild(left);
    
    // Right: Uptime trends chart
    const right = document.createElement("div");
    right.className = "report-section";
    const rightTitle = document.createElement("h4");
    rightTitle.className = "section-title";
    rightTitle.textContent = "Dashboard UI Availability Trends";
    rightTitle.style.marginBottom = "15px";
    right.appendChild(rightTitle);
    
    const trendContainer = document.createElement("div");
    trendContainer.className = "chart-container";
    
    const lineChart = renderLineChart(data.uptime_trends, "day", "uptime");
    trendContainer.appendChild(lineChart);
    right.appendChild(trendContainer);
    
    grid.appendChild(right);
    container.appendChild(grid);
}

// 3. Data Flow Section Renderer
function renderDataflowSection(data, container) {
    const row = document.createElement("div");
    row.style.display = "grid";
    row.style.gridTemplateColumns = "1fr 1fr";
    row.style.gap = "25px";
    row.style.marginBottom = "30px";
    
    // Left: Ingestion trends line chart
    const left = document.createElement("div");
    left.className = "report-section";
    const leftTitle = document.createElement("h4");
    leftTitle.className = "section-title";
    leftTitle.textContent = "24-Hour Alert Ingestion Rate";
    leftTitle.style.marginBottom = "15px";
    left.appendChild(leftTitle);
    
    const trend = renderLineChart(data.ingestion_trends, "time", "alerts");
    left.appendChild(trend);
    row.appendChild(left);
    
    // Right: Indexer indices list
    const right = document.createElement("div");
    right.className = "report-section";
    const rightTitle = document.createElement("h4");
    rightTitle.className = "section-title";
    rightTitle.textContent = "Active Daily Elasticsearch / Opensearch Indices";
    rightTitle.style.marginBottom = "15px";
    right.appendChild(rightTitle);
    
    const table = document.createElement("table");
    table.style.width = "100%";
    table.style.borderCollapse = "collapse";
    
    const thead = document.createElement("thead");
    const trHead = document.createElement("tr");
    ["Index Pattern", "Health", "Status", "Doc Count", "Size"].forEach(hText => {
        const th = document.createElement("th");
        th.textContent = hText;
        th.style.padding = "8px";
        th.style.borderBottom = "1px solid rgba(255,255,255,0.1)";
        th.style.fontSize = "13px";
        th.style.textAlign = "left";
        trHead.appendChild(th);
    });
    thead.appendChild(trHead);
    table.appendChild(thead);
    
    const tbody = document.createElement("tbody");
    data.indices.forEach(idx => {
        const tr = document.createElement("tr");
        const nameCell = document.createElement("td");
        nameCell.textContent = idx.index;
        nameCell.style.padding = "8px";
        nameCell.style.fontSize = "12px";
        nameCell.style.fontFamily = "var(--font-mono)";
        tr.appendChild(nameCell);
        
        const healthCell = document.createElement("td");
        const b = document.createElement("span");
        b.className = `badge ${idx.health === "green" ? "healthy" : (idx.health === "yellow" ? "warning" : "critical")}`;
        b.textContent = idx.health.toUpperCase();
        healthCell.appendChild(b);
        healthCell.style.padding = "8px";
        tr.appendChild(healthCell);
        
        [idx.status, idx["docs.count"], idx["store.size"]].forEach(val => {
            const td = document.createElement("td");
            td.textContent = val;
            td.style.padding = "8px";
            td.style.fontSize = "12.5px";
            tr.appendChild(td);
        });
        
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    right.appendChild(table);
    row.appendChild(right);
    
    container.appendChild(row);
}

// 4. Cluster Section Renderer
function renderClusterSection(data, container) {
    const grid = document.createElement("div");
    grid.style.display = "grid";
    grid.style.gridTemplateColumns = "1fr 1fr";
    grid.style.gap = "25px";
    grid.style.marginBottom = "30px";
    
    // Left: Shard allocations
    const left = document.createElement("div");
    left.className = "report-section";
    const leftTitle = document.createElement("h4");
    leftTitle.className = "section-title";
    leftTitle.textContent = "Cluster Health & Shard Status";
    leftTitle.style.marginBottom = "15px";
    left.appendChild(leftTitle);
    
    const table = document.createElement("table");
    table.style.width = "100%";
    table.style.borderCollapse = "collapse";
    
    const details = data.cluster_details;
    const rows = [
        { label: "Cluster Name", val: details.cluster_name },
        { label: "Health Status", val: details.status.toUpperCase(), isBadge: true },
        { label: "Number of Nodes", val: details.number_of_nodes },
        { label: "Active Shards", val: details.active_shards },
        { label: "Unassigned Shards", val: details.unassigned_shards }
    ];
    
    const tbody = document.createElement("tbody");
    rows.forEach(r => {
        const tr = document.createElement("tr");
        const tdLabel = document.createElement("td");
        tdLabel.textContent = r.label;
        tdLabel.style.padding = "10px";
        tdLabel.style.color = "var(--text-secondary)";
        tr.appendChild(tdLabel);
        
        const tdVal = document.createElement("td");
        tdVal.style.textAlign = "right";
        tdVal.style.padding = "10px";
        tdVal.style.fontWeight = "600";
        
        if (r.isBadge) {
            const b = document.createElement("span");
            b.className = `badge ${r.val === "GREEN" ? "healthy" : (r.val === "YELLOW" ? "warning" : "critical")}`;
            b.textContent = r.val;
            tdVal.appendChild(b);
        } else {
            tdVal.textContent = r.val;
        }
        
        tr.appendChild(tdVal);
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    left.appendChild(table);
    grid.appendChild(left);
    
    // Right: Node statistics
    const right = document.createElement("div");
    right.className = "report-section";
    const rightTitle = document.createElement("h4");
    rightTitle.className = "section-title";
    rightTitle.textContent = "Indexer Database Nodes Status";
    rightTitle.style.marginBottom = "15px";
    right.appendChild(rightTitle);
    
    const nodeTable = document.createElement("table");
    nodeTable.style.width = "100%";
    nodeTable.style.borderCollapse = "collapse";
    
    const thead = document.createElement("thead");
    const trHead = document.createElement("tr");
    ["Node Name", "IP Address", "Status", "JVM Memory", "Disk Free"].forEach(hText => {
        const th = document.createElement("th");
        th.textContent = hText;
        th.style.padding = "8px";
        th.style.borderBottom = "1px solid rgba(255,255,255,0.1)";
        th.style.fontSize = "13px";
        th.style.textAlign = "left";
        trHead.appendChild(th);
    });
    thead.appendChild(trHead);
    nodeTable.appendChild(thead);
    
    const nodeTbody = document.createElement("tbody");
    data.node_status.forEach(node => {
        const tr = document.createElement("tr");
        const nodeCell = document.createElement("td");
        nodeCell.textContent = node.node;
        nodeCell.style.padding = "8px";
        nodeCell.style.fontSize = "13px";
        tr.appendChild(nodeCell);
        
        const ipCell = document.createElement("td");
        ipCell.textContent = node.ip;
        ipCell.style.padding = "8px";
        ipCell.style.fontSize = "13px";
        tr.appendChild(ipCell);
        
        const statusCell = document.createElement("td");
        const b = document.createElement("span");
        b.className = `badge ${node.status === "online" ? "healthy" : "critical"}`;
        b.textContent = node.status.toUpperCase();
        statusCell.appendChild(b);
        statusCell.style.padding = "8px";
        tr.appendChild(statusCell);
        
        const memCell = document.createElement("td");
        memCell.textContent = node.jvm_memory;
        memCell.style.padding = "8px";
        memCell.style.fontSize = "13px";
        tr.appendChild(memCell);
        
        const diskCell = document.createElement("td");
        diskCell.textContent = node.disk_free;
        diskCell.style.padding = "8px";
        diskCell.style.fontSize = "13px";
        tr.appendChild(diskCell);
        
        nodeTbody.appendChild(tr);
    });
    nodeTable.appendChild(nodeTbody);
    right.appendChild(nodeTable);
    grid.appendChild(right);
    
    container.appendChild(grid);
}

// 5. Environment Section Renderer
function renderEnvironmentSection(data, container) {
    // Health Score Circular Display
    const scoreDiv = document.createElement("div");
    scoreDiv.style.display = "flex";
    scoreDiv.style.flexDirection = "column";
    scoreDiv.style.alignItems = "center";
    scoreDiv.style.padding = "25px";
    scoreDiv.style.background = "rgba(255,255,255,0.01)";
    scoreDiv.style.borderRadius = "12px";
    scoreDiv.style.border = "1px solid rgba(255,255,255,0.05)";
    scoreDiv.style.marginBottom = "30px";
    
    const scoreLabel = document.createElement("div");
    scoreLabel.textContent = "OVERALL PLATFORM HEALTH SCORE";
    scoreLabel.style.fontSize = "11px";
    scoreLabel.style.letterSpacing = "1.5px";
    scoreLabel.style.color = "var(--text-secondary)";
    scoreDiv.appendChild(scoreLabel);
    
    const scoreVal = document.createElement("div");
    scoreVal.textContent = `${data.overall_health_score} / 100`;
    scoreVal.style.fontSize = "46px";
    scoreVal.style.fontWeight = "800";
    scoreVal.style.marginTop = "10px";
    
    // Dynamically color based on score
    if (data.overall_health_score >= 80) {
        scoreVal.style.color = "var(--accent-green)";
    } else if (data.overall_health_score >= 50) {
        scoreVal.style.color = "var(--accent-yellow)";
    } else {
        scoreVal.style.color = "var(--accent-red)";
    }
    scoreDiv.appendChild(scoreVal);
    container.appendChild(scoreDiv);
    
    // Findings and Observations
    const row = document.createElement("div");
    row.style.display = "grid";
    row.style.gridTemplateColumns = "1fr 1fr";
    row.style.gap = "25px";
    row.style.marginBottom = "30px";
    
    // Left: Findings
    const left = document.createElement("div");
    left.className = "report-section";
    const leftTitle = document.createElement("h4");
    leftTitle.className = "section-title";
    leftTitle.textContent = "Operational Findings";
    leftTitle.style.marginBottom = "15px";
    left.appendChild(leftTitle);
    
    const findUl = document.createElement("ul");
    findUl.style.paddingLeft = "20px";
    findUl.style.display = "flex";
    findUl.style.flexDirection = "column";
    findUl.style.gap = "10px";
    data.findings.forEach(f => {
        const li = document.createElement("li");
        li.className = "finding-item";
        li.textContent = f;
        findUl.appendChild(li);
    });
    left.appendChild(findUl);
    row.appendChild(left);
    
    // Right: Observations
    const right = document.createElement("div");
    right.className = "report-section";
    const rightTitle = document.createElement("h4");
    rightTitle.className = "section-title";
    rightTitle.textContent = "Environment Observations";
    rightTitle.style.marginBottom = "15px";
    right.appendChild(rightTitle);
    
    const obsUl = document.createElement("ul");
    obsUl.style.paddingLeft = "20px";
    obsUl.style.display = "flex";
    obsUl.style.flexDirection = "column";
    obsUl.style.gap = "10px";
    data.observations.forEach(o => {
        const li = document.createElement("li");
        li.className = "finding-item";
        li.textContent = o;
        obsUl.appendChild(li);
    });
    right.appendChild(obsUl);
    row.appendChild(right);
    container.appendChild(row);
    
    // Risks & Recommendations Table
    const risksSection = document.createElement("div");
    risksSection.className = "report-section";
    const risksTitle = document.createElement("h4");
    risksTitle.className = "section-title";
    risksTitle.textContent = "Deployment Risks & Proactive Remediation Steps";
    risksTitle.style.marginBottom = "15px";
    risksSection.appendChild(risksTitle);
    
    if (data.risks.length > 0) {
        const table = document.createElement("table");
        table.style.width = "100%";
        table.style.borderCollapse = "collapse";
        
        const thead = document.createElement("thead");
        const trHead = document.createElement("tr");
        ["Severity", "Identified Security / Operational Risk", "Recommended Corrective Action"].forEach(hText => {
            const th = document.createElement("th");
            th.textContent = hText;
            th.style.padding = "8px";
            th.style.borderBottom = "1px solid rgba(255,255,255,0.1)";
            th.style.fontSize = "13px";
            th.style.textAlign = "left";
            trHead.appendChild(th);
        });
        thead.appendChild(trHead);
        table.appendChild(thead);
        
        const tbody = document.createElement("tbody");
        for (let i = 0; i < data.risks.length; i++) {
            const tr = document.createElement("tr");
            
            const sevCell = document.createElement("td");
            const b = document.createElement("span");
            b.className = "badge critical";
            b.textContent = "MEDIUM";
            b.style.background = "rgba(245,158,11,0.15)";
            b.style.color = "var(--accent-yellow)";
            b.style.border = "1px solid rgba(245,158,11,0.3)";
            sevCell.appendChild(b);
            sevCell.style.padding = "10px";
            tr.appendChild(sevCell);
            
            const riskCell = document.createElement("td");
            riskCell.textContent = data.risks[i];
            riskCell.style.padding = "10px";
            riskCell.style.fontSize = "13px";
            tr.appendChild(riskCell);
            
            const recCell = document.createElement("td");
            recCell.textContent = data.recommendations[i] || "N/A";
            recCell.style.padding = "10px";
            recCell.style.fontSize = "13px";
            recCell.style.color = "var(--accent-blue)";
            tr.appendChild(recCell);
            
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        risksSection.appendChild(table);
    } else {
        const healthy = document.createElement("div");
        healthy.style.color = "var(--accent-green)";
        healthy.style.fontWeight = "600";
        healthy.style.fontSize = "14px";
        healthy.style.padding = "20px 0";
        healthy.textContent = "✔ Congratulations! No high or medium operational risks detected in this environment configuration.";
        risksSection.appendChild(healthy);
    }
    container.appendChild(risksSection);
}

// 6. Security Events Section Renderer
function renderSecuritySection(data, container) {
    // Metrics layout
    const grid = document.createElement("div");
    grid.className = "metric-row";
    grid.style.display = "grid";
    grid.style.gridTemplateColumns = "repeat(4, 1fr)";
    grid.style.gap = "15px";
    grid.style.marginBottom = "30px";
    
    const cards = [
        { label: "Total Security Alerts", val: data.summary.total, color: "var(--accent-blue)" },
        { label: "High Severity Alerts (>=7)", val: data.summary.high, color: "var(--accent-red)" },
        { label: "Reporting Agents", val: data.summary.agents, color: "var(--accent-green)" },
        { label: "Unique Source IPs", val: data.summary.ips, color: "var(--accent-yellow)" }
    ];
    
    cards.forEach(c => {
        const card = document.createElement("div");
        card.className = "metric-card";
        card.style.background = "rgba(255,255,255,0.02)";
        card.style.border = "1px solid rgba(255,255,255,0.06)";
        card.style.padding = "15px";
        card.style.borderRadius = "8px";
        card.style.textAlign = "center";
        
        const lbl = document.createElement("div");
        lbl.textContent = c.label;
        lbl.style.fontSize = "12px";
        lbl.style.color = "var(--text-secondary)";
        
        const val = document.createElement("div");
        val.className = "metric-value";
        val.textContent = c.val;
        val.style.fontSize = "26px";
        val.style.fontWeight = "700";
        val.style.marginTop = "5px";
        val.style.color = c.color;
        
        card.appendChild(lbl);
        card.appendChild(val);
        grid.appendChild(card);
    });
    container.appendChild(grid);
    
    // Row 1: Timeline & Top Rules
    const row1 = document.createElement("div");
    row1.style.display = "grid";
    row1.style.gridTemplateColumns = "1fr 1fr";
    row1.style.gap = "25px";
    row1.style.marginBottom = "30px";
    
    // Left: Timeline
    const left1 = document.createElement("div");
    left1.className = "report-section";
    const left1Title = document.createElement("h4");
    left1Title.className = "section-title";
    left1Title.textContent = "24-Hour Alert Ingestion Timeline";
    left1Title.style.marginBottom = "15px";
    left1Title.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
    left1Title.style.paddingBottom = "5px";
    left1.appendChild(left1Title);
    
    if (data.timeline && data.timeline.length > 0) {
        const chart = renderLineChart(data.timeline, "time", "alerts");
        left1.appendChild(chart);
    } else {
        const placeholder = document.createElement("div");
        placeholder.textContent = "No timeline data available.";
        placeholder.style.color = "var(--text-secondary)";
        left1.appendChild(placeholder);
    }
    row1.appendChild(left1);
    
    // Right: Top Rules
    const right1 = document.createElement("div");
    right1.className = "report-section";
    const right1Title = document.createElement("h4");
    right1Title.className = "section-title";
    right1Title.textContent = "Top Triggered Rules";
    right1Title.style.marginBottom = "15px";
    right1Title.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
    right1Title.style.paddingBottom = "5px";
    right1.appendChild(right1Title);
    
    if (data.top_rules && Object.keys(data.top_rules).length > 0) {
        const chart = renderBarChart(data.top_rules);
        right1.appendChild(chart);
    } else {
        const placeholder = document.createElement("div");
        placeholder.textContent = "No rules trigger data available.";
        placeholder.style.color = "var(--text-secondary)";
        right1.appendChild(placeholder);
    }
    row1.appendChild(right1);
    container.appendChild(row1);
    
    // Row 2: Severity Distribution & Top Source IPs
    const row2 = document.createElement("div");
    row2.style.display = "grid";
    row2.style.gridTemplateColumns = "1fr 1fr";
    row2.style.gap = "25px";
    row2.style.marginBottom = "30px";
    
    // Left: Severity Distribution
    const left2 = document.createElement("div");
    left2.className = "report-section";
    const left2Title = document.createElement("h4");
    left2Title.className = "section-title";
    left2Title.textContent = "Rule Severity Level Distribution";
    left2Title.style.marginBottom = "15px";
    left2Title.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
    left2Title.style.paddingBottom = "5px";
    left2.appendChild(left2Title);
    
    if (data.level_counts && Object.keys(data.level_counts).length > 0) {
        const sortedLevels = {};
        Object.keys(data.level_counts)
            .sort((a, b) => parseInt(a) - parseInt(b))
            .forEach(k => {
                sortedLevels[`Lvl ${k}`] = data.level_counts[k];
            });
        const chart = renderBarChart(sortedLevels);
        left2.appendChild(chart);
    } else {
        const placeholder = document.createElement("div");
        placeholder.textContent = "No severity distribution data available.";
        placeholder.style.color = "var(--text-secondary)";
        left2.appendChild(placeholder);
    }
    row2.appendChild(left2);
    
    // Right: Top Source IPs
    const right2 = document.createElement("div");
    right2.className = "report-section";
    const right2Title = document.createElement("h4");
    right2Title.className = "section-title";
    right2Title.textContent = "Top Source IPs";
    right2Title.style.marginBottom = "15px";
    right2Title.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
    right2Title.style.paddingBottom = "5px";
    right2.appendChild(right2Title);
    
    if (data.top_ips && Object.keys(data.top_ips).length > 0) {
        const chart = renderBarChart(data.top_ips);
        right2.appendChild(chart);
    } else {
        const healthy = document.createElement("div");
        healthy.style.color = "var(--accent-green)";
        healthy.style.fontWeight = "600";
        healthy.style.fontSize = "14px";
        healthy.style.padding = "20px 0";
        healthy.textContent = "✔ No source IP address details found.";
        right2.appendChild(healthy);
    }
    row2.appendChild(right2);
    container.appendChild(row2);
}

// ---------------------------------------------------------
// SVG Graphic Rendering Engines (Vanilla Vector Charting)
// ---------------------------------------------------------

function renderBarChart(dataMap) {
    const keys = Object.keys(dataMap);
    const values = Object.values(dataMap);
    const maxVal = Math.max(...values, 1);
    
    // Draw SVG
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "220");
    svg.style.background = "rgba(0,0,0,0.15)";
    svg.style.borderRadius = "8px";
    svg.style.padding = "15px";
    
    // Axis line
    const axisY = document.createElementNS("http://www.w3.org/2000/svg", "line");
    axisY.setAttribute("x1", "50");
    axisY.setAttribute("y1", "20");
    axisY.setAttribute("x2", "50");
    axisY.setAttribute("y2", "170");
    axisY.setAttribute("stroke", "rgba(255,255,255,0.15)");
    axisY.setAttribute("stroke-width", "2");
    svg.appendChild(axisY);
    
    const axisX = document.createElementNS("http://www.w3.org/2000/svg", "line");
    axisX.setAttribute("x1", "50");
    axisX.setAttribute("y1", "170");
    axisX.setAttribute("x2", "350");
    axisX.setAttribute("y2", "170");
    axisX.setAttribute("stroke", "rgba(255,255,255,0.15)");
    axisX.setAttribute("stroke-width", "2");
    svg.appendChild(axisX);
    
    // Render Bars
    const barWidth = 35;
    const gap = 20;
    
    for (let i = 0; i < keys.length; i++) {
        const x = 70 + i * (barWidth + gap);
        const barHeight = (values[i] / maxVal) * 130;
        const y = 170 - barHeight;
        
        // Rect
        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", x.toString());
        rect.setAttribute("y", y.toString());
        rect.setAttribute("width", barWidth.toString());
        rect.setAttribute("height", barHeight.toString());
        rect.setAttribute("fill", "url(#barGradient)");
        rect.setAttribute("rx", "3");
        svg.appendChild(rect);
        
        // X Label
        const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
        label.setAttribute("x", (x + barWidth / 2).toString());
        label.setAttribute("y", "190");
        label.setAttribute("fill", "var(--text-secondary)");
        label.setAttribute("font-size", "11");
        label.setAttribute("text-anchor", "middle");
        label.textContent = keys[i].slice(0, 8);
        svg.appendChild(label);
        
        // Value Text
        const valText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        valText.setAttribute("x", (x + barWidth / 2).toString());
        valText.setAttribute("y", (y - 5).toString());
        valText.setAttribute("fill", "var(--accent-blue)");
        valText.setAttribute("font-size", "11");
        valText.setAttribute("font-weight", "600");
        valText.setAttribute("text-anchor", "middle");
        valText.textContent = values[i].toString();
        svg.appendChild(valText);
    }
    
    // Gradient definitions
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    const grad = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    grad.setAttribute("id", "barGradient");
    grad.setAttribute("x1", "0%");
    grad.setAttribute("y1", "0%");
    grad.setAttribute("x2", "0%");
    grad.setAttribute("y2", "100%");
    
    const stop1 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
    stop1.setAttribute("offset", "0%");
    stop1.setAttribute("stop-color", "var(--accent-blue)");
    
    const stop2 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
    stop2.setAttribute("offset", "100%");
    stop2.setAttribute("stop-color", "#5b21b6");
    
    grad.appendChild(stop1);
    grad.appendChild(stop2);
    defs.appendChild(grad);
    svg.appendChild(defs);
    
    return svg;
}

function renderLineChart(trends, xKey, yKey) {
    const maxVal = Math.max(...trends.map(t => t[yKey]), 1);
    
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "220");
    svg.style.background = "rgba(0,0,0,0.15)";
    svg.style.borderRadius = "8px";
    svg.style.padding = "15px";
    
    // Grid Lines and Axes
    const axisY = document.createElementNS("http://www.w3.org/2000/svg", "line");
    axisY.setAttribute("x1", "50");
    axisY.setAttribute("y1", "20");
    axisY.setAttribute("x2", "50");
    axisY.setAttribute("y2", "170");
    axisY.setAttribute("stroke", "rgba(255,255,255,0.15)");
    axisY.setAttribute("stroke-width", "2");
    svg.appendChild(axisY);
    
    const axisX = document.createElementNS("http://www.w3.org/2000/svg", "line");
    axisX.setAttribute("x1", "50");
    axisX.setAttribute("y1", "170");
    axisX.setAttribute("x2", "380");
    axisX.setAttribute("y2", "170");
    axisX.setAttribute("stroke", "rgba(255,255,255,0.15)");
    axisX.setAttribute("stroke-width", "2");
    svg.appendChild(axisX);
    
    // Construct polyline points
    const width = 310;
    const stepX = width / (trends.length - 1 || 1);
    let points = "";
    
    for (let i = 0; i < trends.length; i++) {
        const x = 60 + i * stepX;
        const val = trends[i][yKey];
        const y = 170 - (val / maxVal) * 130;
        points += `${x},${y} `;
        
        // Every 4th tick for labels to avoid overlaps
        if (trends.length < 10 || i % 4 === 0 || i === trends.length - 1) {
            const tickLbl = document.createElementNS("http://www.w3.org/2000/svg", "text");
            tickLbl.setAttribute("x", x.toString());
            tickLbl.setAttribute("y", "190");
            tickLbl.setAttribute("fill", "var(--text-secondary)");
            tickLbl.setAttribute("font-size", "10");
            tickLbl.setAttribute("text-anchor", "middle");
            
            // Format labels
            let txt = trends[i][xKey];
            if (txt.includes(" ")) txt = txt.split(" ")[1]; // extract time
            tickLbl.textContent = txt;
            svg.appendChild(tickLbl);
        }
        
        // Draw little node circle
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", x.toString());
        circle.setAttribute("cy", y.toString());
        circle.setAttribute("r", "3");
        circle.setAttribute("fill", "var(--accent-blue)");
        svg.appendChild(circle);
    }
    
    // Draw the trend line
    const polyline = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    polyline.setAttribute("fill", "none");
    polyline.setAttribute("stroke", "var(--accent-blue)");
    polyline.setAttribute("stroke-width", "3");
    polyline.setAttribute("points", points.trim());
    svg.appendChild(polyline);
    
    return svg;
}

// ---------------------------------------------------------
// EXPORT HANDLERS (Standalone Document Builders)
// ---------------------------------------------------------

function exportReportHTML() {
    if (!activeReportData) return;
    
    const bodyHTML = document.getElementById("report-document-body").innerHTML;
    
    const styles = `
        body {
            background-color: #0b101c;
            color: #f1f5f9;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 40px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .report-title { font-size: 28px; font-weight: 700; color: #00bcff; margin-bottom: 5px; }
        .report-meta { font-size: 13.5px; color: #94a3b8; margin-bottom: 30px; }
        .metric-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
        .metric-card { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08); padding: 20px; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 28px; font-weight: 700; margin-top: 5px; }
        .report-section { margin-top: 40px; }
        .section-title { font-size: 18px; font-weight: 600; margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid rgba(255,255,255,0.08); padding: 12px; text-align: left; }
        th { background-color: rgba(255,255,255,0.03); font-weight: 600; color: #94a3b8; }
        .badge { padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; display: inline-block; text-transform: uppercase; }
        .healthy { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .critical { background: rgba(244, 63, 94, 0.15); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.3); }
        .warning { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        .progress-bar-bg { height: 8px; background: rgba(255,255,255,0.08); border-radius: 4px; overflow: hidden; margin-top: 6px; }
        .progress-bar-fill { height: 100%; background: linear-gradient(90deg, #00bcff, #5b21b6); border-radius: 4px; }
        svg { background: rgba(0,0,0,0.15); border-radius: 8px; margin-top: 10px; }
        svg text { fill: #94a3b8 !important; }
        ul { display: flex; flex-direction: column; gap: 10px; padding-left: 20px; }
        .finding-item { font-size: 14px; line-height: 1.5; color: #cbd5e1; }
    `;
    
    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Operations Center Diagnostic Report</title>
    <style>${styles}</style>
</head>
<body>
    ${bodyHTML}
</body>
</html>`;
    
    const blob = new Blob([htmlContent], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `wazuh-operations-report-${activeReportType}-${Math.random().toString(36).substring(2, 7).toUpperCase()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportReportPDF() {
    const reportHTML = document.getElementById("report-document-body").innerHTML;
    const printWindow = window.open("", "_blank");
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Wazuh Diagnostic Report - PDF Export</title>
            <style>
                body {
                    background: #ffffff !important;
                    color: #000000 !important;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    padding: 40px;
                }
                .report-title { font-size: 26px; font-weight: bold; margin-bottom: 5px; color: #007bc0; }
                .report-meta { font-size: 13px; color: #666666; margin-bottom: 30px; }
                .metric-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
                .metric-card { border: 1px solid #dddddd; padding: 15px; border-radius: 8px; text-align: center; background: #fafafa; }
                .metric-value { font-size: 24px; font-weight: bold; margin-top: 5px; color: #222222; }
                .report-section { margin-top: 30px; }
                .section-title { font-size: 16px; font-weight: bold; margin-bottom: 15px; border-bottom: 2px solid #eeeeee; padding-bottom: 5px; color: #222222; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                th, td { border: 1px solid #dddddd; padding: 10px; text-align: left; }
                th { background-color: #f7f7f7; font-weight: bold; color: #555555; }
                .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; display: inline-block; text-transform: uppercase; }
                .healthy { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                .critical { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                .warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
                .progress-bar-bg { height: 10px; background: #eeeeee; border-radius: 4px; overflow: hidden; margin-top: 6px; }
                .progress-bar-fill { height: 100%; background: #007bc0; border-radius: 4px; }
                svg { background: #fdfdfd !important; border: 1px solid #e0e0e0; border-radius: 8px; margin-top: 10px; }
                svg text { fill: #444444 !important; }
                svg line, svg path { stroke: #dddddd; }
                svg polyline { stroke: #007bc0 !important; }
                svg rect { fill: #007bc0 !important; }
                ul { padding-left: 20px; display: flex; flex-direction: column; gap: 8px; }
                .finding-item { font-size: 13.5px; line-height: 1.4; color: #333333; }
                @media print {
                    body { padding: 0; }
                    .no-print { display: none; }
                }
            </style>
        </head>
        <body>
            ${reportHTML}
            <script>
                window.onload = function() {
                    window.print();
                    setTimeout(function() { window.close(); }, 500);
                };
            </script>
        </body>
        </html>
    `);
    printWindow.document.close();
}

// Bind callbacks globally
window.generateReport = generateReport;
window.showCustomReportBuilder = showCustomReportBuilder;
window.hideCustomReportBuilder = hideCustomReportBuilder;
window.generateCustomReport = generateCustomReport;
window.backToReportsHub = backToReportsHub;
window.exportReportHTML = exportReportHTML;
window.exportReportPDF = exportReportPDF;
