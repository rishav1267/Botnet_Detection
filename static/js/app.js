/**
 * IoT Botnet Detection System — Master Application Controller (app.js)
 * Manages state, routing, real-time telemetry streaming, notifications, and UI responsiveness.
 */

window.App = {
  state: {
    activeView: "overview",
    devices: [],
    flows: [],
    rules: [],
    alerts: [],
    mlModel: null,
    kpis: {
      total_devices: 8,
      normal_count: 5,
      suspicious_count: 1,
      high_risk_count: 2,
      quarantined_count: 1,
      unresolved_alerts: 3,
      health_score: 82,
      current_pps: 1073.0,
      current_mbps: 3.26,
      packets_analyzed_total: 148293,
      bytes_analyzed_total: 89421048
    },
    streamInterval: 1000,
    streamTimer: null,
    isStreaming: true,
    isOnline: false,
    sidebarCollapsed: false,
    notificationsOpen: false,
    unreadAlertsCount: 3
  },

  async init() {
    console.log("[NETGUARD IoT] Initializing Master Application Controller...");

    // Setup DOM Listeners & Navigation
    this.setupNavigation();
    this.setupTopBar();

    // Load initial data (Try API, fall back to seed dataset)
    await this.loadInitialData();

    // Render default view
    this.navigateTo("overview");

    // Start Real-Time Stream
    this.startStreaming();

    // Check reduced motion preference
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      console.log("[NETGUARD IoT] Reduced motion preference active.");
    }
  },

  async loadInitialData() {
    try {
      const [resHealth, resDevices, resTraffic, resRules, resAlerts, resModel] = await Promise.all([
        window.ApiClient.health.get(),
        window.ApiClient.devices.list(),
        window.ApiClient.traffic.getRecentFlows(50),
        window.ApiClient.detection.getRules(),
        window.ApiClient.alerts.list(),
        window.ApiClient.ml.getModel()
      ]);

      this.state.isOnline = true;
      this.state.devices = resDevices.devices;
      this.state.kpis = resDevices.summary;
      this.state.flows = resTraffic.flows;
      this.state.rules = resRules.rules;
      this.state.alerts = resAlerts.alerts;
      this.state.mlModel = resModel;
      this.updateStatusBadge(true);
      console.log("[NETGUARD IoT] Connected to live Python REST Backend.");
      this.initRealtimeStream();
    } catch (err) {
      console.warn("[NETGUARD IoT] Live server unavailable, loading resilient seed data:", err);
      this.state.isOnline = false;
      this.loadFallbackData();
      this.updateStatusBadge(false);
    }

    this.updateNotificationCount();
  },

  loadFallbackData() {
    const data = window.IOT_FALLBACK_DATA || {};
    this.state.devices = data.devices || [];
    this.state.rules = data.rules || [];
    this.state.mlModel = data.mlModel || {};
    this.state.alerts = (data.alerts && data.alerts.length > 0) ? JSON.parse(JSON.stringify(data.alerts)) : [];

    // Seed 20 synthetic flows
    this.state.flows = [];
    for (let i = 0; i < 20; i++) {
      this.tickOfflineFlow();
    }
  },

  setupNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
      item.addEventListener("click", () => {
        const view = item.getAttribute("data-view");
        if (view) this.navigateTo(view);
      });
    });

    // Mobile Menu Toggle
    const mobileMenuBtn = document.getElementById("mobile-menu-btn");
    const sidebar = document.querySelector(".sidebar");
    if (mobileMenuBtn && sidebar) {
      mobileMenuBtn.addEventListener("click", () => {
        sidebar.classList.toggle("mobile-open");
      });
    }

    // Sidebar Collapse Toggle (Desktop)
    const collapseBtn = document.getElementById("sidebar-collapse-btn");
    if (collapseBtn && sidebar) {
      collapseBtn.addEventListener("click", () => {
        this.state.sidebarCollapsed = !this.state.sidebarCollapsed;
        sidebar.classList.toggle("collapsed", this.state.sidebarCollapsed);
      });
    }
  },

  setupTopBar() {
    // Global Search
    const searchInput = document.getElementById("global-search-input");
    if (searchInput) {
      searchInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          const query = searchInput.value.trim().toLowerCase();
          if (query) {
            this.handleGlobalSearch(query);
          }
        }
      });
    }

    // Notifications Dropdown Toggle
    const bellBtn = document.getElementById("notification-bell-btn");
    const notifDropdown = document.getElementById("notification-dropdown");
    if (bellBtn && notifDropdown) {
      bellBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.state.notificationsOpen = !this.state.notificationsOpen;
        notifDropdown.style.display = this.state.notificationsOpen ? "block" : "none";
        this.renderNotificationsDropdown();
      });

      document.addEventListener("click", () => {
        if (this.state.notificationsOpen) {
          this.state.notificationsOpen = false;
          notifDropdown.style.display = "none";
        }
      });

      notifDropdown.addEventListener("click", (e) => e.stopPropagation());
    }

    // User Profile Dropdown Toggle
    const profileBtn = document.getElementById("user-profile-btn");
    const profileDropdown = document.getElementById("user-profile-dropdown");
    if (profileBtn && profileDropdown) {
      profileBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const isOpen = profileDropdown.style.display === "block";
        profileDropdown.style.display = isOpen ? "none" : "block";
        // Close notif if open
        if (notifDropdown) notifDropdown.style.display = "none";
      });

      document.addEventListener("click", () => {
        if (profileDropdown) profileDropdown.style.display = "none";
      });

      profileDropdown.addEventListener("click", (e) => e.stopPropagation());

      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          document.querySelectorAll(".modal-backdrop.open").forEach(m => m.classList.remove("open"));
          if (profileDropdown) profileDropdown.style.display = "none";
          if (notifDropdown) notifDropdown.style.display = "none";
        }
      });
    }
  },

  animateCountUp(elementId, targetValue, duration = 600, prefix = "", suffix = "") {
    const el = document.getElementById(elementId);
    if (!el) return;
    const startValue = parseFloat(el.getAttribute("data-val") || 0);
    el.setAttribute("data-val", targetValue);
    const startTime = performance.now();

    const update = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      const ease = 1 - Math.pow(1 - progress, 3);
      const current = startValue + (targetValue - startValue) * ease;
      const formatted = Number.isInteger(targetValue) ? Math.round(current) : current.toFixed(1);
      el.textContent = `${prefix}${Number(formatted).toLocaleString()}${suffix}`;
      if (progress < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  },

  handleGlobalSearch(query) {
    const q = (query || "").trim().toLowerCase();
    if (["traffic", "live", "flows", "stream"].includes(q)) {
      this.navigateTo("traffic");
      if (window.TrafficView) TrafficView.setSearchQuery("");
      return;
    }
    if (["device", "devices", "inventory", "endpoints"].includes(q)) {
      this.navigateTo("devices");
      if (window.DevicesView) DevicesView.setSearchQuery("");
      return;
    }
    if (["threat", "threats", "rules", "signatures"].includes(q)) {
      this.navigateTo("threats");
      return;
    }
    if (["ml", "machine learning", "model"].includes(q)) {
      this.navigateTo("ml");
      return;
    }
    if (["alert", "alerts", "incidents"].includes(q)) {
      this.navigateTo("alerts");
      return;
    }
    if (["overview", "dashboard", "home"].includes(q)) {
      this.navigateTo("overview");
      return;
    }

    // Check if query matches a device
    const matchedDev = this.state.devices.find(d => 
      d.name.toLowerCase().includes(q) || d.ip.includes(q) || d.id.toLowerCase().includes(q)
    );
    if (matchedDev) {
      this.navigateTo("devices");
      if (window.DevicesView) {
        DevicesView.setSearchQuery(q);
      }
      this.showToast(`Found device: ${matchedDev.name}`, "info");
      return;
    }

    // Default to traffic search
    this.navigateTo("traffic");
    if (window.TrafficView) {
      TrafficView.setSearchQuery(q);
    }
    this.showToast(`Searching flows for: "${q}"`, "info");
  },

  navigateTo(viewName) {
    this.state.activeView = viewName;

    // Update Sidebar Navigation state
    document.querySelectorAll(".nav-item").forEach(item => {
      const match = item.getAttribute("data-view") === viewName;
      item.classList.toggle("active", match);
    });

    // Update Topbar Breadcrumbs
    const viewTitles = {
      overview: "Overview Dashboard",
      traffic: "Live Traffic Stream",
      devices: "IoT Device Inventory",
      threats: "Threat Detection Engine",
      ml: "Machine-Learning Analysis",
      alerts: "Security Alerts & Incidents",
      analytics: "Threat Intelligence & Analytics",
      settings: "Settings & System Health"
    };

    const breadcrumbEl = document.getElementById("topbar-breadcrumb-view");
    if (breadcrumbEl) {
      breadcrumbEl.textContent = viewTitles[viewName] || "Dashboard";
    }

    // Toggle View Containers
    document.querySelectorAll(".view-container").forEach(c => {
      c.classList.remove("active");
    });

    const targetContainer = document.getElementById(`view-${viewName}`);
    if (targetContainer) {
      targetContainer.classList.add("active");
      window.scrollTo(0, 0);
      const wrapper = document.querySelector(".main-wrapper");
      if (wrapper) wrapper.scrollTop = 0;

      // Trigger view render
      switch (viewName) {
        case "overview":
          if (window.OverviewView) OverviewView.render(targetContainer);
          break;
        case "traffic":
          if (window.TrafficView) TrafficView.render(targetContainer);
          break;
        case "devices":
          if (window.DevicesView) DevicesView.render(targetContainer);
          break;
        case "threats":
          if (window.ThreatsView) ThreatsView.render(targetContainer);
          break;
        case "ml":
          if (window.MLModuleView) MLModuleView.render(targetContainer);
          break;
        case "alerts":
          if (window.AlertsView) AlertsView.render(targetContainer);
          break;
        case "analytics":
          if (window.AnalyticsView) AnalyticsView.render(targetContainer);
          break;
        case "settings":
          if (window.SettingsView) SettingsView.render(targetContainer);
          break;
      }
    }

    // Close mobile sidebar if open
    const sidebar = document.querySelector(".sidebar");
    if (sidebar) sidebar.classList.remove("mobile-open");
  },

  startStreaming() {
    if (this.state.streamTimer) clearInterval(this.state.streamTimer);
    this.state.streamTimer = setInterval(() => {
      this.tickStream();
    }, this.state.streamInterval);
  },

  setStreamInterval(ms) {
    this.state.streamInterval = parseInt(ms, 10);
    this.startStreaming();
    this.showToast(`Telemetry cadence: ${ms}ms`, "info");
  },

  async tickStream() {
    if (!this.state.isStreaming) return;
    if (window.TrafficView && window.TrafficView.isPaused) return;

    if (this.state.isOnline) {
      try {
        const data = await window.ApiClient.traffic.tickStream();
        if (data.new_flow) {
          this.state.flows.unshift(data.new_flow);
          if (this.state.flows.length > 100) this.state.flows.pop();

          if (data.kpis) {
            this.state.kpis = data.kpis;
          }

          if (data.new_alert) {
            const exists = this.state.alerts.some(a => a.id === data.new_alert.id);
            if (!exists) {
              this.state.alerts.unshift(data.new_alert);
              this.updateNotificationCount();
              this.renderNotificationsDropdown();
              if (this.state.activeView === "alerts" && window.AlertsView) {
                window.AlertsView.render();
              }
            }
          }

          this.onNewFlowArrived(data.new_flow);
        }
      } catch (e) {
        // Fallback to local tick
        this.tickOfflineFlow();
      }
    } else {
      this.tickOfflineFlow();
    }
  },

  tickOfflineFlow(forcedScenario = null) {
    const devices = this.state.devices;
    if (!devices || devices.length === 0) return;

    const dev = devices[Math.floor(Math.random() * devices.length)];
    const isHigh = forcedScenario === 'mirai_telnet' || forcedScenario === 'syn_flood' || (!forcedScenario && dev.status === 'High-Risk' && !dev.quarantined);
    const isSusp = forcedScenario === 'c2_beacon' || (!forcedScenario && dev.status === 'Suspicious');

    const pps = isHigh ? 380 + Math.random() * 400 : (isSusp ? 65 + Math.random() * 80 : 2 + Math.random() * 25);
    const status = isHigh ? "High-Risk" : (isSusp ? "Suspicious" : "Normal");

    const flow = {
      flow_id: `FLW-${Math.floor(100000 + Math.random() * 900000)}`,
      timestamp: new Date().toTimeString().split(' ')[0],
      device_id: dev.id,
      device_name: dev.name,
      source_ip: dev.ip,
      dest_ip: isHigh ? "185.193.64.12" : (isSusp ? "45.142.213.9" : "192.168.1.1"),
      dest_port: isHigh ? 23 : (isSusp ? 4444 : 443),
      protocol: isHigh ? "TCP" : (isSusp ? "UDP" : "TCP"),
      status,
      raw_features: {
        packet_rate: pps,
        byte_rate: pps * 128,
        conn_freq: isHigh ? 24.5 : (isSusp ? 11.2 : 2.0),
        syn_ratio: isHigh ? 0.94 : (isSusp ? 0.35 : 0.05),
        payload_entropy: isHigh ? 7.4 : 4.1,
        flow_duration: 1.5
      },
      rule_matches: isHigh ? [{ rule_id: "R01", name: "Telnet Brute Force Sweep", severity: "High-Risk", reason: "Targeting port 23 at high frequency" }] : [],
      ml_prediction: {
        risk_score: isHigh ? 0.95 : (isSusp ? 0.58 : 0.04),
        probabilities: {
          Normal: isHigh ? 0.02 : 0.95,
          Suspicious: isHigh ? 0.03 : 0.04,
          "High-Risk": isHigh ? 0.95 : 0.01
        }
      }
    };

    this.state.flows.unshift(flow);
    if (this.state.flows.length > 100) this.state.flows.pop();

    // Auto-alert trigger on High-Risk
    if (isHigh && Math.random() > 0.6) {
      const alertId = `ALT-${Math.floor(9100 + Math.random() * 800)}`;
      if (!this.state.alerts.some(a => a.id === alertId)) {
        this.state.alerts.unshift({
          id: alertId,
          timestamp: flow.timestamp,
          device_id: dev.id,
          device_name: dev.name,
          source_ip: dev.ip || flow.source_ip || "192.168.1.100",
          flow_id: flow.id || `FLW-${Math.floor(10000 + Math.random() * 90000)}`,
          severity: "Critical",
          detection_source: "Dual-Fused Heuristics",
          classification: "Botnet Incursion / Credential Access",
          title: "Mirai Botnet Telnet Incursion",
          reason: `Port 23 dictionary brute force detected at ${pps.toFixed(1)} pps`,
          details: `Port 23 dictionary brute force detected at ${pps.toFixed(1)} pps targeting ${flow.dest_ip}`,
          traffic_indicators: {
            packet_rate: pps,
            byte_rate: pps * 128,
            dest_port: flow.dest_port || 23,
            dest_ip: flow.dest_ip || "194.26.29.11",
            syn_ratio: (flow.features && flow.features.syn_ratio) || 0.85,
            conn_freq: (flow.features && flow.features.conn_freq) || 24.5,
            payload_entropy: (flow.features && flow.features.payload_entropy) || 6.8
          },
          suggested_action: "Quarantine affected device and audit port activity.",
          status: "New",
          resolved: false,
          mitre_technique: "T1110.001 Password Guessing",
          analyst_notes: [
            {
              author: "System AI Sensor",
              timestamp: flow.timestamp,
              note: "Automated trigger from offline heuristic anomaly stream."
            }
          ],
          action_taken: "Alert Dispatched"
        });
        this.updateNotificationCount();
        this.renderNotificationsDropdown();
        this.showToast(`🚨 High-Risk Botnet Incursion: ${dev.name}`, "danger");
      }
    }

    this.onNewFlowArrived(flow);
  },

  onNewFlowArrived(flow) {
    // If overview active, update pulse canvas
    if (this.state.activeView === "overview" && window.OverviewView) {
      if (OverviewView.addCanvasPoint) {
        OverviewView.addCanvasPoint(flow.raw_features ? flow.raw_features.packet_rate : flow.packet_rate);
      }
      OverviewView.updateData();
    }

    // If traffic view active, re-render stream
    if (this.state.activeView === "traffic" && window.TrafficView) {
      TrafficView.renderFlows();
    }
  },

  async quarantineDevice(deviceId, isQuarantined) {
    const dev = this.state.devices.find(d => d.id === deviceId);
    if (!dev) return;

    dev.quarantined = isQuarantined;
    if (isQuarantined) {
      dev.pps = 0.0;
      dev.status = "High-Risk";
      this.showToast(`🛡️ Device ${dev.name} successfully quarantined and isolated`, "success");
    } else {
      dev.status = "Suspicious";
      this.showToast(`Device ${dev.name} port reconnected to network`, "info");
    }

    // Recalculate KPIs
    const high = this.state.devices.filter(d => d.status === "High-Risk" && !d.quarantined).length;
    const susp = this.state.devices.filter(d => d.status === "Suspicious").length;
    this.state.kpis.high_risk_count = high;
    this.state.kpis.suspicious_count = susp;
    this.state.kpis.quarantined_count = this.state.devices.filter(d => d.quarantined).length;

    // Sync with server if online
    if (this.state.isOnline) {
      try {
        const data = await window.ApiClient.devices.quarantine(deviceId, isQuarantined);
        if (data.devices) this.state.devices = data.devices;
        if (data.kpis) this.state.kpis = data.kpis;
      } catch (e) {
        console.warn("[App] Quarantine sync error:", e);
      }
    }

    // Re-render current view
    this.navigateTo(this.state.activeView);
  },

  updateNotificationCount() {
    const unread = this.state.alerts.filter(a => !a.resolved).length;
    this.state.unreadAlertsCount = unread;
    const badge = document.getElementById("notif-badge-count");
    if (badge) {
      badge.textContent = unread;
      badge.style.display = unread > 0 ? "inline-block" : "none";
    }
    const navAlertsBadge = document.getElementById("nav-alerts-badge");
    if (navAlertsBadge) {
      navAlertsBadge.textContent = unread;
      navAlertsBadge.style.display = unread > 0 ? "inline-block" : "none";
    }
  },

  renderNotificationsDropdown() {
    const dropdown = document.getElementById("notification-dropdown");
    if (!dropdown) return;

    const unread = this.state.alerts.filter(a => !a.resolved);

    dropdown.innerHTML = `
      <div style="padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
        <strong style="color: var(--text-main); font-size: 13px;">Security Notifications (${unread.length})</strong>
        <a href="#" style="font-size: 11px; color: var(--highlight-mint);" onclick="App.navigateTo('alerts');">View All</a>
      </div>
      <div style="max-height: 280px; overflow-y: auto;">
        ${unread.length === 0 ? `
          <div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 12px;">No active alerts. System healthy.</div>
        ` : unread.slice(0, 5).map(a => `
          <div style="padding: 10px 14px; border-bottom: 1px solid var(--border-subtle); cursor: pointer;" onclick="App.navigateTo('alerts');">
            <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
              <span class="badge badge-sev-${(a.severity || 'info').toLowerCase()}" style="font-size: 10px; font-weight: 700;">${a.severity}</span>
              <span class="mono" style="font-size: 10px; color: var(--text-muted);">${a.timestamp}</span>
            </div>
            <div style="font-weight: 600; font-size: 12px; color: var(--text-main);">${a.title}</div>
            <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${a.device_name} (${a.device_id})</div>
          </div>
        `).join("")}
      </div>
    `;
  },

  updateStatusBadge(isOnline) {
    const badge = document.getElementById("topbar-status-indicator");
    if (badge) {
      if (isOnline) {
        badge.innerHTML = `<span class="pulse-indicator"></span> <span>Live REST API Connected</span>`;
        badge.className = "ip-chip";
        badge.style.color = "var(--highlight-mint)";
      } else {
        badge.innerHTML = `<span class="pulse-indicator" style="background: var(--state-warning);"></span> <span>Demo Simulator Mode</span>`;
        badge.className = "ip-chip";
        badge.style.color = "var(--state-warning)";
      }
    }
  },

  initRealtimeStream() {
    if (this._sseConnected || !window.ApiClient || !window.ApiClient.stream) return;
    try {
      this._sseSource = window.ApiClient.stream.connect(
        (eventType, data) => {
          this.handleRealtimeEvent(eventType, data);
        },
        (err) => {
          console.debug("[NETGUARD SSE] Stream reconnection status:", err);
        }
      );
      this._sseConnected = true;
      console.log("[NETGUARD SSE] Connected to /api/stream/events push channel.");
    } catch (e) {
      console.warn("[NETGUARD SSE] SSE initialization skipped:", e);
    }
  },

  handleRealtimeEvent(eventType, data) {
    if (!data) return;

    if (eventType === "detection") {
      const flowRecord = {
        flow_id: data.flow_id,
        timestamp: data.timestamp || new Date().toISOString().slice(11, 19),
        device_id: data.device_id,
        device_name: data.device_name || data.device_id,
        source_ip: data.source_ip,
        dest_ip: data.destination_ip || data.dest_ip,
        dest_port: data.destination_port || data.dest_port,
        protocol: data.protocol,
        packet_rate: data.packet_rate || 0,
        byte_rate: data.byte_rate || 0,
        payload_entropy: data.payload_entropy || 4.2,
        status: data.verdict || "Normal",
        risk_score: data.risk_score || 0,
        rule_matches: data.rules_triggered || [],
        is_demo: Boolean(data.is_demo),
        data_source: data.data_source || "collector",
        ml_prediction: {
          verdict: data.verdict || "Normal",
          risk_score: (data.risk_score || 0) / 100,
          confidence: 0.95
        }
      };

      const idx = (this.state.flows || []).findIndex(f => f.flow_id === data.flow_id);
      if (idx === -1) {
        this.state.flows.unshift(flowRecord);
        if (this.state.flows.length > 100) this.state.flows.pop();
        if (this.state.activeView === "traffic" && window.TrafficView) {
          window.TrafficView.renderFlows();
        }
      }
    } else if (eventType === "alert") {
      const exists = (this.state.alerts || []).some(a => a.id === data.id);
      if (!exists) {
        this.state.alerts.unshift(data);
        this.updateNotificationCount();
        this.renderNotificationsDropdown();
        if (this.state.activeView === "alerts" && window.AlertsView) {
          window.AlertsView.render();
        }
        this.showToast(`🚨 ALERT [${data.severity}]: ${data.title}`, data.severity === "High-Risk" ? "danger" : "warning");
      }
    } else if (eventType === "risk_change") {
      const dev = (this.state.devices || []).find(d => d.id === data.device_id);
      if (dev) {
        dev.risk_score = data.risk_score;
        dev.status = data.status;
        if (this.state.activeView === "devices" && window.DevicesView) {
          window.DevicesView.renderDevices();
        }
      }
    } else if (eventType === "traffic_aggregate") {
      if (data.kpis) {
        this.state.kpis = Object.assign({}, this.state.kpis, data.kpis);
      }
    }
  },

  showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type === 'danger' ? 'danger' : (type === 'success' ? 'success' : 'info')}`;

    let iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    if (type === "danger") {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else if (type === "success") {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    }

    toast.innerHTML = `
      <div style="color: ${type === 'danger' ? 'var(--state-danger)' : (type === 'success' ? 'var(--primary-accent)' : 'var(--highlight-mint)')}; flex-shrink: 0;">
        ${iconSvg}
      </div>
      <div style="flex: 1; font-size: 12px; color: var(--text-main); font-weight: 500;">${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(30px)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 3800);
  }
};

// Start application when DOM loaded
window.addEventListener("DOMContentLoaded", () => {
  App.init();
});
