/**
 * ServiceNow Security Operations (SecOps) Interactive Application
 */

const INITIAL_INCIDENTS = [
  {
    id: "SEC0010482",
    priority: "1 - Critical",
    title: "Cobalt Strike C2 Beaconing from Domain Controller",
    state: "Containment",
    category: "Malware",
    assignedTo: "Lane Kuhlman",
    ci: "DC-PROD-01.corp",
    sla: "0h 42m remaining",
    slaStatus: "danger",
    riskScore: 96,
    assignmentGroup: "Tier 3 SecOps Escalation",
    iocs: ["194.26.29.112", "update-microsoft-azure.cc", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    playbook: [
      { id: 1, text: "Isolate host from production VLAN", done: true },
      { id: 2, text: "Dump memory & kill PID 4812 (rundll32.exe)", done: true },
      { id: 3, text: "Push perimeter firewall block for IP 194.26.29.112", done: false },
      { id: 4, text: "Force Kerberos krbtgt password rotation", done: false }
    ],
    notes: [
      { author: "System Automation", time: "12 mins ago", text: "Playbook task 'Isolate Host' dispatched to CrowdStrike Falcon API." },
      { author: "Lane Kuhlman", time: "8 mins ago", text: "Confirmed outbound traffic to Russian autonomous system. Initiated memory forensics." }
    ]
  },
  {
    id: "SEC0010485",
    priority: "1 - Critical",
    title: "Ransomware Canary Alert: Rapid encryption pattern on File Cluster",
    state: "Analysis",
    category: "Ransomware",
    assignedTo: "Lane Kuhlman",
    ci: "FS-EAST-CLUST-02",
    sla: "1h 15m remaining",
    slaStatus: "danger",
    riskScore: 92,
    assignmentGroup: "Incident Response Emergency",
    iocs: ["45.145.66.19", "*.lockbit3.onion", "wannapwn.exe"],
    playbook: [
      { id: 1, text: "Sever SMB shares & cluster node network adapters", done: true },
      { id: 2, text: "Capture volume shadow copy snapshots", done: false },
      { id: 3, text: "Identify patient-zero via Active Directory logon audit", done: false }
    ],
    notes: [
      { author: "SOC SIEM Ingestion", time: "25 mins ago", text: "File rename event threshold exceeded: > 500 files modified per minute with extension .lockbit" }
    ]
  },
  {
    id: "SEC0010478",
    priority: "2 - High",
    title: "Executive Spear-Phishing credential harvest attempt",
    state: "Eradication",
    category: "Phishing",
    assignedTo: "Sarah Connor",
    ci: "O365-TENANT-PROD",
    sla: "3h 20m remaining",
    slaStatus: "normal",
    riskScore: 78,
    assignmentGroup: "Tier 2 Security Operations",
    iocs: ["security-login-servicenow.info", "hr-benefits-update.pdf"],
    playbook: [
      { id: 1, text: "Purge phishing email from all recipient inboxes (M365)", done: true },
      { id: 2, text: "Revoke active OAuth sessions for targeted accounts", done: true },
      { id: 3, text: "Add URL to Cloudflare Zero Trust gateway blocklist", done: true }
    ],
    notes: [
      { author: "Sarah Connor", time: "1 hour ago", text: "Purged email across 34 user mailboxes. 2 clicks identified, MFA blocked credential reuse." }
    ]
  },
  {
    id: "SEC0010469",
    priority: "2 - High",
    title: "Anomalous API token creation in AWS Production IAM",
    state: "Analysis",
    category: "Unauthorized Access",
    assignedTo: "Lane Kuhlman",
    ci: "AWS-IAM-ROOT",
    sla: "4h 50m remaining",
    slaStatus: "normal",
    riskScore: 84,
    assignmentGroup: "Cloud Security SecOps",
    iocs: ["185.220.101.5", "AKIAIOSFODNN7EXAMPLE"],
    playbook: [
      { id: 1, text: "Deactivate compromised AWS Access Key ID", done: true },
      { id: 2, text: "Review CloudTrail logs for unauthorized S3 bucket access", done: false }
    ],
    notes: [
      { author: "AWS GuardDuty", time: "2 hours ago", text: "IAMUser/UnusualAccessKeyCreation from TOR exit node." }
    ]
  },
  {
    id: "SEC0010450",
    priority: "3 - Moderate",
    title: "Port scan & brute force detected against Public Bastion Host",
    state: "Closed",
    category: "Unauthorized Access",
    assignedTo: "David Miller",
    ci: "BASTION-DMZ-01",
    sla: "Completed (Met SLA)",
    slaStatus: "normal",
    riskScore: 45,
    assignmentGroup: "Tier 1 SOC Monitoring",
    iocs: ["103.251.167.20"],
    playbook: [
      { id: 1, text: "Automatic rate limit triggered at edge firewall", done: true },
      { id: 2, text: "Verify SSH key-only authentication remains enforced", done: true }
    ],
    notes: [
      { author: "David Miller", time: "Yesterday", text: "No successful logins observed. IP permanently blacklisted at AWS WAF." }
    ]
  }
];

const VULNERABILITIES = [
  {
    cve: "CVE-2024-3400",
    title: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
    cvss: "10.0 Critical",
    asset: "PANW-EDGE-FW-01",
    status: "In Remediation",
    patchDueDate: "Today (Urgent)"
  },
  {
    cve: "CVE-2024-21413",
    title: "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)",
    cvss: "9.8 Critical",
    asset: "1,240 Enterprise Endpoints",
    status: "Patch Deployed (82%)",
    patchDueDate: "In 2 days"
  },
  {
    cve: "CVE-2024-1709",
    title: "ConnectWise ScreenConnect Authentication Bypass",
    cvss: "10.0 Critical",
    asset: "REMOTE-MGMT-SRV",
    status: "Remediated & Verified",
    patchDueDate: "Completed"
  }
];

const MITRE_MATRIX = [
  {
    tactic: "Initial Access",
    techniques: [
      { id: "T1566", name: "Phishing: Spearphishing Link", hit: true },
      { id: "T1190", name: "Exploit Public Facing Application", hit: false },
      { id: "T1078", name: "Valid Accounts", hit: true }
    ]
  },
  {
    tactic: "Execution",
    techniques: [
      { id: "T1059.001", name: "PowerShell Execution", hit: true },
      { id: "T1204", name: "User Execution: Malicious File", hit: true },
      { id: "T1053", name: "Scheduled Task / Job", hit: false }
    ]
  },
  {
    tactic: "Persistence",
    techniques: [
      { id: "T1098", name: "Account Manipulation (AWS IAM)", hit: true },
      { id: "T1547", name: "Boot or Logon Autostart", hit: false },
      { id: "T1136", name: "Create Account", hit: true }
    ]
  },
  {
    tactic: "Command & Control",
    techniques: [
      { id: "T1071.001", name: "Web Protocols C2 (Cobalt Strike)", hit: true },
      { id: "T1573", name: "Encrypted Channel", hit: true },
      { id: "T1105", name: "Ingress Tool Transfer", hit: false }
    ]
  }
];

// State Store
let incidents = [...INITIAL_INCIDENTS];
let activeFilter = "all";
let searchQuery = "";
let selectedIncidentId = incidents[0].id;
let currentTab = "incidents";

// Helpers
function showToast(msg) {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = "toast-message";
  el.innerHTML = `
    <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
      <path d="M8 0a8 8 0 1 0 8 8A8 8 0 0 0 8 0zm3.5 5.5l-4.5 5a.75.75 0 0 1-1.1 0l-2-2a.75.75 0 1 1 1.1-1.1L6.5 8.9l3.95-4.4a.75.75 0 1 1 1.05 1z"/>
    </svg>
    <span>${msg}</span>
  `;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

function updateClock() {
  const now = new Date();
  const el = document.getElementById("utc-clock");
  if (el) {
    el.textContent = `UTC ${now.toUTCString().slice(17, 25)}`;
  }
}
setInterval(updateClock, 1000);
updateClock();

// Render Incidents Table
function renderIncidentsTable() {
  const tbody = document.getElementById("incidents-tbody");
  if (!tbody) return;

  let filtered = incidents.filter(inc => {
    if (activeFilter === "p1" && !inc.priority.includes("1 - Critical")) return false;
    if (activeFilter === "containment" && inc.state !== "Containment") return false;
    if (activeFilter === "my" && inc.assignedTo !== "Lane Kuhlman") return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matched = inc.id.toLowerCase().includes(q) ||
        inc.title.toLowerCase().includes(q) ||
        inc.ci.toLowerCase().includes(q) ||
        inc.category.toLowerCase().includes(q) ||
        inc.iocs.some(ioc => ioc.toLowerCase().includes(q));
      if (!matched) return false;
    }
    return true;
  });

  tbody.innerHTML = "";

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:28px; color:#888;">No security incidents match the current filter or search criteria.</td></tr>`;
    return;
  }

  filtered.forEach(inc => {
    const tr = document.createElement("tr");
    tr.className = `clickable ${inc.id === selectedIncidentId ? "selected" : ""}`;
    
    // Priority badge class
    let pClass = "p3";
    if (inc.priority.includes("1")) pClass = "p1";
    else if (inc.priority.includes("2")) pClass = "p2";
    else if (inc.priority.includes("4")) pClass = "p4";

    // State class
    const stateClass = inc.state.toLowerCase();

    tr.innerHTML = `
      <td onclick="event.stopPropagation()">
        <input type="checkbox" />
      </td>
      <td><span class="inc-number">${inc.id}</span></td>
      <td><span class="p-badge ${pClass}">${inc.priority}</span></td>
      <td><div class="inc-desc" title="${inc.title}">${inc.title}</div></td>
      <td><span class="state-pill ${stateClass}">${inc.state}</span></td>
      <td>${inc.category}</td>
      <td>${inc.assignedTo}</td>
      <td><code>${inc.ci}</code></td>
      <td><span class="sla-badge ${inc.slaStatus}">${inc.sla}</span></td>
    `;

    tr.addEventListener("click", () => {
      selectIncident(inc.id);
    });

    tbody.appendChild(tr);
  });

  // Update counter badges
  document.getElementById("incidents-count").textContent = incidents.length;
  const p1Count = incidents.filter(i => i.priority.includes("1") && i.state !== "Closed").length;
  const p2Count = incidents.filter(i => (i.priority.includes("2") || i.priority.includes("3")) && i.state !== "Closed").length;
  document.getElementById("kpi-p1-count").textContent = p1Count;
  document.getElementById("kpi-p2-count").textContent = p2Count;
}

// Select & Populate Detail Drawer
function selectIncident(id) {
  selectedIncidentId = id;
  renderIncidentsTable();

  const inc = incidents.find(i => i.id === id);
  if (!inc) return;

  const drawer = document.getElementById("incident-drawer");
  drawer.classList.remove("hidden");

  document.getElementById("drawer-incident-number").textContent = inc.id;
  document.getElementById("drawer-title").textContent = inc.title;
  document.getElementById("drawer-ci").textContent = inc.ci;
  document.getElementById("drawer-analyst").textContent = inc.assignedTo;
  document.getElementById("drawer-group").textContent = inc.assignmentGroup || "SecOps Core";
  document.getElementById("drawer-risk").textContent = `${inc.riskScore} / 100`;

  // Priority badge
  const pBadge = document.getElementById("drawer-priority-badge");
  pBadge.textContent = inc.priority;
  pBadge.className = `p-badge ${inc.priority.includes("1") ? "p1" : inc.priority.includes("2") ? "p2" : "p3"}`;

  // Stepper highlights
  const lifecycle = ["Draft", "Analysis", "Containment", "Eradication", "Closed"];
  const curIndex = lifecycle.indexOf(inc.state);
  const steps = document.querySelectorAll("#lifecycle-stepper .step");
  steps.forEach((st, idx) => {
    st.className = "step";
    if (idx < curIndex) st.classList.add("completed");
    else if (idx === curIndex) st.classList.add("active");
  });

  // State progression button text
  const advanceBtn = document.getElementById("btn-advance-state");
  if (inc.state === "Draft") advanceBtn.textContent = "Advance to Analysis →";
  else if (inc.state === "Analysis") advanceBtn.textContent = "Advance to Containment →";
  else if (inc.state === "Containment") advanceBtn.textContent = "Advance to Eradication →";
  else if (inc.state === "Eradication") advanceBtn.textContent = "Resolve & Close Incident →";
  else advanceBtn.textContent = "Re-open Security Incident";

  // Playbook list
  renderPlaybookTasks(inc);

  // IOC list
  const iocContainer = document.getElementById("drawer-ioc-list");
  iocContainer.innerHTML = "";
  inc.iocs.forEach(ioc => {
    const pill = document.createElement("div");
    pill.className = "ioc-pill";
    pill.innerHTML = `
      <span>${ioc}</span>
      <button title="Block observable via SOAR">[Block]</button>
    `;
    pill.querySelector("button").addEventListener("click", (e) => {
      e.stopPropagation();
      showToast(`Observable ${ioc} submitted to Edge Firewall blocklist`);
    });
    iocContainer.appendChild(pill);
  });

  // Journal Feed
  renderJournal(inc);
}

function renderPlaybookTasks(inc) {
  const pbList = document.getElementById("playbook-tasks-list");
  pbList.innerHTML = "";

  const total = inc.playbook.length;
  const completed = inc.playbook.filter(t => t.done).length;
  document.getElementById("playbook-status-badge").textContent = `${completed} of ${total} Done`;

  inc.playbook.forEach(t => {
    const row = document.createElement("div");
    row.className = "pb-task-item";
    row.innerHTML = `
      <div class="pb-task-label">
        <span class="pb-status-icon ${t.done ? "done" : "pending"}">${t.done ? "✓" : "○"}</span>
        <span style="${t.done ? "text-decoration: line-through; color: #888;" : ""}">${t.text}</span>
      </div>
      <div>
        ${!t.done ? `<button class="pb-btn-action">Execute</button>` : `<span style="color:#198038; font-size:11px;">Verified</span>`}
      </div>
    `;
    if (!t.done) {
      row.querySelector(".pb-btn-action").addEventListener("click", () => {
        t.done = true;
        renderPlaybookTasks(inc);
        const totalPb = parseInt(document.getElementById("kpi-playbooks-count").textContent) + 1;
        document.getElementById("kpi-playbooks-count").textContent = totalPb;
        showToast(`Playbook step executed: "${t.text}"`);
      });
    }
    pbList.appendChild(row);
  });
}

function renderJournal(inc) {
  const feed = document.getElementById("drawer-journal-feed");
  feed.innerHTML = "";
  inc.notes.forEach(n => {
    const item = document.createElement("div");
    item.className = "journal-item";
    item.innerHTML = `
      <div class="journal-meta">
        <strong>${n.author}</strong>
        <span>${n.time}</span>
      </div>
      <div>${n.text}</div>
    `;
    feed.appendChild(item);
  });
}

// Render Vulnerabilities Tab
function renderVulnerabilities() {
  const container = document.getElementById("vuln-cards-list");
  container.innerHTML = "";
  VULNERABILITIES.forEach(v => {
    const card = document.createElement("div");
    card.className = "vuln-card";
    card.innerHTML = `
      <div class="vuln-top">
        <span class="cve-badge">${v.cve}</span>
        <span class="cvss-score">CVSS ${v.cvss}</span>
      </div>
      <div style="font-weight:600; font-size:13px;">${v.title}</div>
      <div style="font-size:11.5px; color:#525252;"><strong>Target CI / Asset:</strong> ${v.asset}</div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
        <span class="state-pill containment">${v.status}</span>
        <button class="action-btn secondary" style="padding:3px 8px; font-size:11px;">Trigger Patch Task</button>
      </div>
    `;
    card.querySelector("button").addEventListener("click", () => {
      showToast(`Automated Change Request created for ${v.cve}`);
    });
    container.appendChild(card);
  });
}

// Render Threat Intelligence Tab
function renderThreatIntel() {
  const tbody = document.getElementById("threat-tbody");
  tbody.innerHTML = "";
  
  const observables = [
    { type: "IP Address", val: "194.26.29.112", source: "AlienVault OTX & Recorded Future", score: "98 / 100", inc: "SEC0010482" },
    { type: "C2 Domain", val: "update-microsoft-azure.cc", source: "Mandiant Threat Intel", score: "100 / 100", inc: "SEC0010482" },
    { type: "IPv4", val: "45.145.66.19", source: "AbuseIPDB Threat Intelligence", score: "95 / 100", inc: "SEC0010485" },
    { type: "SHA256", val: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", source: "VirusTotal Enterprise (58/72)", score: "92 / 100", inc: "SEC0010482" },
    { type: "Phishing URL", val: "security-login-servicenow.info", source: "ServiceNow Security Phishing Radar", score: "99 / 100", inc: "SEC0010478" }
  ];

  observables.forEach(obs => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="p-badge p4">${obs.type}</span></td>
      <td><code>${obs.val}</code></td>
      <td>${obs.source}</td>
      <td><span class="badge-risk-score">${obs.score}</span></td>
      <td><a href="#" class="inc-number">${obs.inc}</a></td>
      <td><button class="action-btn secondary" style="padding:2px 8px; font-size:11px;">Deploy Block</button></td>
    `;
    tr.querySelector("button").addEventListener("click", () => {
      showToast(`Rule pushed to Palo Alto PAN-OS Firewalls for ${obs.val}`);
    });
    tr.querySelector(".inc-number").addEventListener("click", (e) => {
      e.preventDefault();
      switchTab("incidents");
      selectIncident(obs.inc);
    });
    tbody.appendChild(tr);
  });
}

// Render MITRE Matrix
function renderMitreMatrix() {
  const matrix = document.getElementById("mitre-matrix");
  matrix.innerHTML = "";
  MITRE_MATRIX.forEach(col => {
    const colEl = document.createElement("div");
    colEl.className = "mitre-column";
    colEl.innerHTML = `
      <div class="mitre-col-title">${col.tactic}</div>
      <div class="mitre-tech-list">
        ${col.techniques.map(t => `
          <div class="mitre-technique ${t.hit ? "hit" : ""}">
            <span class="tech-id">${t.id}</span>
            <strong>${t.name}</strong>
            ${t.hit ? `<div style="color:#da1e28; font-size:10px; margin-top:2px;">● Detected in Active SIR</div>` : ""}
          </div>
        `).join("")}
      </div>
    `;
    matrix.appendChild(colEl);
  });
}

// Tab Switching
function switchTab(tabKey) {
  currentTab = tabKey;
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabKey);
  });

  const views = {
    "incidents": document.getElementById("view-incidents"),
    "vulnerabilities": document.getElementById("view-vulnerabilities"),
    "threat-intel": document.getElementById("view-threat-intel"),
    "mitre": document.getElementById("view-mitre")
  };

  Object.keys(views).forEach(key => {
    if (views[key]) {
      views[key].classList.toggle("hidden", key !== tabKey);
    }
  });

  const drawer = document.getElementById("incident-drawer");
  if (tabKey !== "incidents") {
    drawer.classList.add("hidden");
  } else {
    drawer.classList.remove("hidden");
  }
}

// Setup Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  renderIncidentsTable();
  selectIncident(selectedIncidentId);
  renderVulnerabilities();
  renderThreatIntel();
  renderMitreMatrix();

  // Tab buttons
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Filter chips
  document.querySelectorAll(".chip").forEach(chip => {
    chip.addEventListener("click", () => {
      document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      activeFilter = chip.dataset.filter;
      renderIncidentsTable();
    });
  });

  // Search
  const searchInput = document.getElementById("global-search");
  searchInput.addEventListener("input", (e) => {
    searchQuery = e.target.value.trim();
    renderIncidentsTable();
  });

  // Keyboard shortcut Ctrl+K
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });

  // Close drawer button
  document.getElementById("btn-close-drawer").addEventListener("click", () => {
    document.getElementById("incident-drawer").classList.add("hidden");
  });

  // Advance state button
  document.getElementById("btn-advance-state").addEventListener("click", () => {
    const inc = incidents.find(i => i.id === selectedIncidentId);
    if (!inc) return;
    const states = ["Draft", "Analysis", "Containment", "Eradication", "Closed"];
    const curr = states.indexOf(inc.state);
    if (curr < states.length - 1) {
      inc.state = states[curr + 1];
    } else {
      inc.state = "Analysis";
    }
    inc.notes.unshift({
      author: "Lane Kuhlman",
      time: "Just now",
      text: `Updated state to [${inc.state}] via Incident Workspace.`
    });
    selectIncident(inc.id);
    showToast(`${inc.id} transitioned to stage: ${inc.state}`);
  });

  // Isolate Host EDR button
  document.getElementById("btn-isolate-host").addEventListener("click", () => {
    const inc = incidents.find(i => i.id === selectedIncidentId);
    if (!inc) return;
    showToast(`CrowdStrike network containment signal dispatched to ${inc.ci}`);
    inc.notes.unshift({
      author: "EDR Integration",
      time: "Just now",
      text: `Host ${inc.ci} network isolated. Inbound/outbound non-forensic telemetry blocked.`
    });
    renderJournal(inc);
  });

  // Post work note
  document.getElementById("btn-post-note").addEventListener("click", () => {
    const input = document.getElementById("new-work-note");
    const text = input.value.trim();
    if (!text) return;
    const inc = incidents.find(i => i.id === selectedIncidentId);
    if (!inc) return;
    inc.notes.unshift({
      author: "Lane Kuhlman",
      time: "Just now",
      text
    });
    input.value = "";
    renderJournal(inc);
    showToast("Work note recorded to audit trail");
  });

  // Modal Create Incident
  const modal = document.getElementById("create-incident-modal");
  const openModal = () => modal.classList.remove("hidden");
  const closeModal = () => modal.classList.add("hidden");

  document.getElementById("btn-quick-new").addEventListener("click", openModal);
  document.getElementById("btn-create-modal-trigger").addEventListener("click", openModal);
  document.getElementById("btn-modal-cancel").addEventListener("click", closeModal);
  document.getElementById("btn-cancel-form").addEventListener("click", closeModal);

  document.getElementById("create-incident-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const title = document.getElementById("form-title").value.trim();
    const priority = document.getElementById("form-priority").value;
    const category = document.getElementById("form-category").value;
    const ci = document.getElementById("form-ci").value.trim();
    const assignee = document.getElementById("form-assignee").value.trim() || "Lane Kuhlman";
    const ioc = document.getElementById("form-ioc").value.trim();

    const newId = `SEC00${Math.floor(10490 + Math.random() * 500)}`;
    const newIncident = {
      id: newId,
      priority,
      title,
      state: "Analysis",
      category,
      assignedTo: assignee,
      ci,
      sla: "2h 00m remaining",
      slaStatus: priority.includes("1") ? "danger" : "normal",
      riskScore: priority.includes("1") ? 90 : 65,
      assignmentGroup: "Security Operations Tier 2",
      iocs: ioc ? [ioc] : ["10.0.12.84"],
      playbook: [
        { id: 1, text: "Verify asset criticality in ServiceNow CMDB", done: true },
        { id: 2, text: "Conduct host memory & disk capture", done: false },
        { id: 3, text: "Identify threat actor command origin", done: false }
      ],
      notes: [
        { author: assignee, time: "Just now", text: "Incident created manually via SecOps Workspace." }
      ]
    };

    incidents.unshift(newIncident);
    closeModal();
    document.getElementById("create-incident-form").reset();
    switchTab("incidents");
    selectIncident(newId);
    showToast(`Created new Security Incident ${newId}`);
  });

  // Refresh button simulation
  document.getElementById("btn-refresh").addEventListener("click", () => {
    showToast("Syncing with ServiceNow SecOps Gateway & SIEM Feeds...");
    setTimeout(() => {
      showToast("All data up to date.");
    }, 600);
  });
});