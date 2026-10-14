/**
 * IoT Botnet Detection System — Security Alerts & Incident Management Module (Part 5)
 * Multi-criteria filtering, severity mapping, status triage (New, Acknowledged, In Progress, Resolved, Reopened),
 * bulk actions with device isolation, deep forensic inspection modal with live analyst notes thread, and CSV/JSON export.
 */

window.AlertsView = {
  searchQuery: "",
  filterSeverity: "all",
  filterStatus: "all",
  filterSource: "all",
  filterDevice: "all",
  sortBy: "timestamp_desc",
  selectedAlertIds: new Set(),

  render(container) {
    container = container || document.getElementById("view-alerts");
    if (!container) return;

    // In-place refresh if DOM structure is already rendered to preserve input state
    if (document.getElementById("alerts-log-tbody")) {
      this.updateKpis();
      this.renderAlerts();
      return;
    }

    const alerts = App.state.alerts || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.alerts : []);
    const devices = App.state.devices || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.devices : []);

    const newCount = alerts.filter(a => a.status === "New").length;
    const unresolvedCount = alerts.filter(a => !a.resolved).length;
    const criticalCount = alerts.filter(a => a.severity === "Critical").length;

    container.innerHTML = `
      <!-- Incident KPI Summary Bar -->
      <div class="grid-4" style="margin-bottom: var(--space-xl);">
        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">New / Unread Incidents</span>
            <div class="kpi-icon-wrapper warning">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            </div>
          </div>
          <div class="kpi-value" style="color: #93c5fd;" id="alerts-kpi-new">${newCount}</div>
          <div class="kpi-subtext">Awaiting initial analyst triage</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">Active / Unresolved</span>
            <div class="kpi-icon-wrapper danger">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            </div>
          </div>
          <div class="kpi-value" style="color: var(--state-danger);" id="alerts-kpi-unresolved">${unresolvedCount}</div>
          <div class="kpi-subtext highlight-danger">Requiring mitigation</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">Critical Severity Threats</span>
            <div class="kpi-icon-wrapper danger">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
            </div>
          </div>
          <div class="kpi-value" style="color: #f87171;" id="alerts-kpi-critical">${criticalCount}</div>
          <div class="kpi-subtext">Immediate containment needed</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <span class="kpi-label">Total Logged Dossiers</span>
            <div class="kpi-icon-wrapper">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            </div>
          </div>
          <div class="kpi-value" style="color: var(--highlight-mint);" id="alerts-kpi-total">${alerts.length}</div>
          <div class="kpi-subtext">MITRE ATT&CK Correlated</div>
        </div>
      </div>

      <!-- Filter and Search Action Toolbar -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 16px 20px;">
        <!-- Top Row: Search and Quick Exports -->
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; margin-bottom: 14px;">
          <!-- Search Input -->
          <div style="position: relative; flex: 1; min-width: 280px; max-width: 480px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" style="position: absolute; left: 12px; top: 11px; color: var(--text-muted);"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="alerts-search-input" class="cyber-input" placeholder="Search by Alert ID, asset name, IP, MITRE code, or description..."
                   value="${this.searchQuery}" oninput="AlertsView.handleSearch(this.value)" style="padding-left: 36px; width: 100%;" />
          </div>

          <!-- Sort Selector and Exports -->
          <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <label style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Sort By:</label>
            <select class="cyber-select" onchange="AlertsView.setSort(this.value)" style="font-size: 12px; padding: 6px 12px;">
              <option value="timestamp_desc" ${this.sortBy === 'timestamp_desc' ? 'selected' : ''}>Newest First</option>
              <option value="timestamp_asc" ${this.sortBy === 'timestamp_asc' ? 'selected' : ''}>Oldest First</option>
              <option value="severity_desc" ${this.sortBy === 'severity_desc' ? 'selected' : ''}>Severity (High &rarr; Low)</option>
              <option value="severity_asc" ${this.sortBy === 'severity_asc' ? 'selected' : ''}>Severity (Low &rarr; High)</option>
              <option value="status" ${this.sortBy === 'status' ? 'selected' : ''}>Status (New &rarr; Resolved)</option>
            </select>

            <button class="btn btn-secondary btn-sm" onclick="AlertsView.exportAlerts('json')">Export JSON</button>
            <button class="btn btn-secondary btn-sm" onclick="AlertsView.exportAlerts('csv')">Export CSV</button>
          </div>
        </div>

        <!-- Filter Pills Row -->
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; border-top: 1px solid var(--border-subtle); padding-top: 12px;">
          <!-- Severity Filter Buttons -->
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            <span style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-right: 4px;">Severity:</span>
            <button class="btn ${this.filterSeverity === 'all' ? 'btn-primary' : 'btn-secondary'} btn-sm" onclick="AlertsView.setFilterSeverity('all')">All</button>
            <button class="btn ${this.filterSeverity === 'Critical' ? 'btn-danger' : 'btn-secondary'} btn-sm" onclick="AlertsView.setFilterSeverity('Critical')">Critical</button>
            <button class="btn ${this.filterSeverity === 'High' ? 'btn-secondary' : 'btn-secondary'} btn-sm" onclick="AlertsView.setFilterSeverity('High')" style="${this.filterSeverity === 'High' ? 'border-color: #fb923c; color: #fb923c;' : ''}">High</button>
            <button class="btn ${this.filterSeverity === 'Medium' ? 'btn-secondary' : 'btn-secondary'} btn-sm" onclick="AlertsView.setFilterSeverity('Medium')" style="${this.filterSeverity === 'Medium' ? 'border-color: #fcd34d; color: #fcd34d;' : ''}">Medium</button>
            <button class="btn ${this.filterSeverity === 'Low' ? 'btn-secondary' : 'btn-secondary'} btn-sm" onclick="AlertsView.setFilterSeverity('Low')" style="${this.filterSeverity === 'Low' ? 'border-color: #7dd3fc; color: #7dd3fc;' : ''}">Low</button>
            <button class="btn ${this.filterSeverity === 'Informational' ? 'btn-secondary' : 'btn-secondary'} btn-sm" onclick="AlertsView.setFilterSeverity('Informational')">Info</button>
          </div>

          <!-- Secondary Filters: Status, Source, Device -->
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <!-- Status Dropdown -->
            <select class="cyber-select" onchange="AlertsView.setFilterStatus(this.value)" style="font-size: 12px; padding: 6px 10px;">
              <option value="all" ${this.filterStatus === 'all' ? 'selected' : ''}>All Statuses</option>
              <option value="New" ${this.filterStatus === 'New' ? 'selected' : ''}>New (Unread)</option>
              <option value="Acknowledged" ${this.filterStatus === 'Acknowledged' ? 'selected' : ''}>Acknowledged</option>
              <option value="In Progress" ${this.filterStatus === 'In Progress' ? 'selected' : ''}>In Progress</option>
              <option value="Resolved" ${this.filterStatus === 'Resolved' ? 'selected' : ''}>Resolved</option>
              <option value="Reopened" ${this.filterStatus === 'Reopened' ? 'selected' : ''}>Reopened</option>
            </select>

            <!-- Detection Source Dropdown -->
            <select class="cyber-select" onchange="AlertsView.setFilterSource(this.value)" style="font-size: 12px; padding: 6px 10px;">
              <option value="all" ${this.filterSource === 'all' ? 'selected' : ''}>All Sources</option>
              <option value="Rule-based Engine" ${this.filterSource === 'Rule-based Engine' ? 'selected' : ''}>Rule-Based Engine</option>
              <option value="ML Classifier" ${this.filterSource === 'ML Classifier' ? 'selected' : ''}>ML Classifier</option>
              <option value="Dual-Fused Heuristics" ${this.filterSource === 'Dual-Fused Heuristics' ? 'selected' : ''}>Dual-Fused Heuristics</option>
            </select>

            <!-- Device Filter Dropdown -->
            <select class="cyber-select" onchange="AlertsView.setFilterDevice(this.value)" style="font-size: 12px; padding: 6px 10px;">
              <option value="all" ${this.filterDevice === 'all' ? 'selected' : ''}>All Assets</option>
              ${devices.map(d => `<option value="${d.id}" ${this.filterDevice === d.id ? 'selected' : ''}>${d.name} (${d.id})</option>`).join("")}
            </select>

            ${(this.filterSeverity !== 'all' || this.filterStatus !== 'all' || this.filterSource !== 'all' || this.filterDevice !== 'all' || this.searchQuery) ? `
              <button class="btn btn-secondary btn-sm" onclick="AlertsView.resetFilters()">Reset</button>
            ` : ''}
          </div>
        </div>
      </div>

      <!-- Bulk Actions Bar (Visible when rows selected) -->
      <div id="alerts-bulk-bar" class="bulk-actions-bar" style="display: ${this.selectedAlertIds.size > 0 ? 'flex' : 'none'};">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="font-weight: 700; color: var(--highlight-mint); font-family: var(--font-mono); font-size: 13px;">
            <span id="bulk-selected-count">${this.selectedAlertIds.size}</span> Incident(s) Selected
          </span>
          <button class="btn btn-secondary btn-sm" onclick="AlertsView.clearSelection()" style="padding: 2px 8px; font-size: 11px;">Deselect All</button>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary btn-sm" onclick="AlertsView.executeBulkAction('acknowledge')">Mark Acknowledged</button>
          <button class="btn btn-secondary btn-sm" onclick="AlertsView.executeBulkAction('in_progress')">Mark In Progress</button>
          <button class="btn btn-secondary btn-sm" onclick="AlertsView.executeBulkAction('resolve')">Mark Resolved</button>
          <button class="btn btn-danger btn-sm" onclick="AlertsView.executeBulkAction('isolate')">Isolate Affected Devices</button>
        </div>
      </div>

      <!-- Alerts List Table Card -->
      <div class="card" style="padding: 0; overflow: hidden;">
        <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 0;">
          <div class="card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Active Security Incidents & Threat Triage Log
          </div>
          <span style="font-size: 12px; color: var(--text-secondary); font-family: var(--font-mono);">
            Displaying <strong style="color: var(--highlight-mint);" id="alerts-displayed-count">0</strong> incidents
          </span>
        </div>

        <div class="table-wrapper" style="border: none;">
          <table class="cyber-table">
            <thead>
              <tr>
                <th style="width: 36px; text-align: center;">
                  <input type="checkbox" id="check-select-all-alerts" onchange="AlertsView.toggleSelectAll(this.checked)" />
                </th>
                <th>Alert ID & Time</th>
                <th>Severity</th>
                <th>Affected Asset</th>
                <th>Threat Signature & Attribution</th>
                <th>MITRE ATT&CK</th>
                <th>Status</th>
                <th style="text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody id="alerts-log-tbody">
              <!-- Rendered dynamically -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Deep Forensic Investigation Modal -->
      <div id="incident-modal" class="modal-backdrop" onclick="if(event.target === this) this.classList.remove('open')">
        <div class="cyber-modal" id="incident-modal-content" style="max-width: 720px;">
          <!-- Rendered on Details click -->
        </div>
      </div>
    `;

    this.renderAlerts();
  },

  updateKpis() {
    const alerts = App.state.alerts || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.alerts : []);
    const newCount = alerts.filter(a => a.status === "New").length;
    const unresolvedCount = alerts.filter(a => !a.resolved).length;
    const criticalCount = alerts.filter(a => a.severity === "Critical").length;

    const elNew = document.getElementById("alerts-kpi-new");
    if (elNew) elNew.textContent = newCount;
    const elUnres = document.getElementById("alerts-kpi-unresolved");
    if (elUnres) elUnres.textContent = unresolvedCount;
    const elCrit = document.getElementById("alerts-kpi-critical");
    if (elCrit) elCrit.textContent = criticalCount;
    const elTotal = document.getElementById("alerts-kpi-total");
    if (elTotal) elTotal.textContent = alerts.length;
  },

  handleSearch(query) {
    this.searchQuery = query.toLowerCase().trim();
    this.renderAlerts();
  },

  setFilterSeverity(sev) {
    this.filterSeverity = sev;
    this.render(document.getElementById("view-alerts"));
  },

  setFilterStatus(status) {
    this.filterStatus = status;
    this.renderAlerts();
  },

  setFilterSource(source) {
    this.filterSource = source;
    this.renderAlerts();
  },

  setFilterDevice(devId) {
    this.filterDevice = devId;
    this.renderAlerts();
  },

  setSort(sortBy) {
    this.sortBy = sortBy;
    this.renderAlerts();
  },

  resetFilters() {
    this.searchQuery = "";
    this.filterSeverity = "all";
    this.filterStatus = "all";
    this.filterSource = "all";
    this.filterDevice = "all";
    this.sortBy = "timestamp_desc";
    const container = document.getElementById("view-alerts");
    if (container) {
      container.innerHTML = "";
      this.render(container);
    }
  },

  toggleSelectAll(checked) {
    const alerts = this.getFilteredAlerts();
    if (checked) {
      alerts.forEach(a => this.selectedAlertIds.add(a.id));
    } else {
      this.selectedAlertIds.clear();
    }
    this.updateBulkBar();
    this.renderAlerts();
  },

  toggleSelectRow(alertId, checked) {
    if (checked) {
      this.selectedAlertIds.add(alertId);
    } else {
      this.selectedAlertIds.delete(alertId);
    }
    this.updateBulkBar();
  },

  clearSelection() {
    this.selectedAlertIds.clear();
    const selectAllBox = document.getElementById("check-select-all-alerts");
    if (selectAllBox) selectAllBox.checked = false;
    this.updateBulkBar();
    this.renderAlerts();
  },

  updateBulkBar() {
    const bar = document.getElementById("alerts-bulk-bar");
    const countEl = document.getElementById("bulk-selected-count");
    if (bar && countEl) {
      const count = this.selectedAlertIds.size;
      countEl.textContent = count;
      bar.style.display = count > 0 ? "flex" : "none";
    }
  },

  getFilteredAlerts() {
    let alerts = [...(App.state.alerts || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.alerts : []))];

    // Text search
    if (this.searchQuery) {
      alerts = alerts.filter(a => {
        const hay = `${a.id} ${a.device_name} ${a.device_id} ${a.source_ip || ''} ${a.title} ${a.details || ''} ${a.reason || ''} ${a.mitre_technique || ''}`.toLowerCase();
        return hay.includes(this.searchQuery);
      });
    }

    // Severity filter
    if (this.filterSeverity !== "all") {
      alerts = alerts.filter(a => (a.severity || "").toLowerCase() === this.filterSeverity.toLowerCase());
    }

    // Status filter
    if (this.filterStatus !== "all") {
      alerts = alerts.filter(a => a.status === this.filterStatus);
    }

    // Detection Source filter
    if (this.filterSource !== "all") {
      alerts = alerts.filter(a => a.detection_source === this.filterSource);
    }

    // Device filter
    if (this.filterDevice !== "all") {
      alerts = alerts.filter(a => a.device_id === this.filterDevice);
    }

    // Sort
    const sevRank = { "Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1 };
    alerts.sort((a, b) => {
      if (this.sortBy === "timestamp_desc") {
        return (b.timestamp || "").localeCompare(a.timestamp || "");
      } else if (this.sortBy === "timestamp_asc") {
        return (a.timestamp || "").localeCompare(b.timestamp || "");
      } else if (this.sortBy === "severity_desc") {
        return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
      } else if (this.sortBy === "severity_asc") {
        return (sevRank[a.severity] || 0) - (sevRank[b.severity] || 0);
      } else if (this.sortBy === "status") {
        return (a.status || "").localeCompare(b.status || "");
      }
      return 0;
    });

    return alerts;
  },

  renderAlerts() {
    this.updateKpis();
    const alerts = this.getFilteredAlerts();
    const tbody = document.getElementById("alerts-log-tbody");
    const countEl = document.getElementById("alerts-displayed-count");
    if (countEl) countEl.textContent = alerts.length;
    if (!tbody) return;

    if (alerts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 48px;">
            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px;">
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" style="opacity: 0.5;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <div style="font-size: 14px; font-weight: 600; color: var(--text-secondary);">No Security Incidents Found</div>
              <div style="font-size: 12px; color: var(--text-muted); max-width: 360px;">No incidents match the active search query or filter criteria.</div>
              <button class="btn btn-secondary btn-sm" onclick="AlertsView.resetFilters()" style="margin-top: 8px;">Reset All Filters</button>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const isSelected = this.selectedAlertIds.has(a.id);
      const sevClass = `badge-sev-${(a.severity || 'info').toLowerCase()}`;
      const statusClass = a.status === 'New' ? 'badge-status-new' :
                          (a.status === 'Acknowledged' ? 'badge-status-ack' :
                          (a.status === 'In Progress' ? 'badge-status-prog' :
                          (a.status === 'Resolved' ? 'badge-status-res' : 'badge-status-reopen')));

      const sourceBadge = a.detection_source === 'ML Classifier' ? 'badge-normal' :
                          (a.detection_source === 'Dual-Fused Heuristics' ? 'badge-high-risk' : 'badge-suspicious');

      const isCriticalUnresolved = a.severity === 'Critical' && !a.resolved;

      return `
        <tr class="${isCriticalUnresolved ? 'row-high-risk' : ''} ${isSelected ? 'row-selected' : ''}">
          <td style="text-align: center;">
            <input type="checkbox" ${isSelected ? 'checked' : ''} onchange="AlertsView.toggleSelectRow('${a.id}', this.checked)" />
          </td>
          <td style="cursor: pointer;" onclick="AlertsView.openIncidentDetails('${a.id}')" title="Click to open forensic dossier">
            <div class="mono" style="font-weight: 700; color: var(--highlight-mint); text-decoration: underline; text-decoration-color: rgba(34, 197, 94, 0.4);">${a.id}</div>
            <div class="mono" style="font-size: 11px; color: var(--text-muted);">${a.timestamp}</div>
          </td>
          <td>
            <span class="badge ${sevClass}" style="font-weight: 700;">${a.severity}</span>
          </td>
          <td style="cursor: pointer;" onclick="AlertsView.openIncidentDetails('${a.id}')">
            <strong style="color: var(--text-main); font-size: 13px;">${a.device_name}</strong>
            <div class="mono" style="font-size: 11px; color: var(--text-muted);">${a.device_id} &bull; ${a.source_ip || 'N/A'}</div>
          </td>
          <td style="max-width: 280px; cursor: pointer;" onclick="AlertsView.openIncidentDetails('${a.id}')">
            <div style="font-weight: 600; color: var(--text-main); font-size: 13px;">${a.title}</div>
            <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
              ${a.reason || a.details || ''}
            </div>
            <div style="margin-top: 4px;">
              <span class="badge ${sourceBadge}" style="font-size: 9px; padding: 1px 6px;">${a.detection_source || 'Rule Engine'}</span>
            </div>
          </td>
          <td>
            <div style="font-family: var(--font-mono); font-size: 11px; color: var(--highlight-mint); background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 4px; padding: 3px 6px; line-height: 1.2; display: inline-block; max-width: 140px;">
              ${(a.mitre_technique || 'T1499').split(' ')[0]}
              <div style="font-size: 9px; color: var(--text-secondary); font-family: var(--font-sans); margin-top: 1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${a.mitre_technique || ''}">
                ${(a.mitre_technique || '').substring((a.mitre_technique || '').indexOf(' ') + 1)}
              </div>
            </div>
          </td>
          <td>
            <span class="badge ${statusClass}">${a.status || (a.resolved ? 'Resolved' : 'New')}</span>
          </td>
          <td style="text-align: right; white-space: nowrap;">
            <div style="display: flex; gap: 6px; justify-content: flex-end; align-items: center;">
              <button class="btn btn-secondary btn-sm" onclick="AlertsView.openIncidentDetails('${a.id}')" style="padding: 4px 8px; font-weight: 600;">Inspect</button>
              ${a.status === 'New' ? `
                <button class="btn btn-secondary btn-sm" onclick="AlertsView.updateStatus('${a.id}', 'Acknowledged')" title="Acknowledge alert" style="padding: 4px 6px; font-size: 11px;">Ack</button>
              ` : ''}
              ${!a.resolved ? `
                <button class="btn btn-secondary btn-sm" onclick="AlertsView.updateStatus('${a.id}', 'Resolved')" title="Mark resolved" style="padding: 4px 6px; font-size: 11px;">Resolve</button>
              ` : `
                <button class="btn btn-secondary btn-sm" onclick="AlertsView.updateStatus('${a.id}', 'Reopened')" title="Reopen incident" style="padding: 4px 6px; font-size: 11px;">Reopen</button>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join("");
  },

  async updateStatus(alertId, newStatus, comment = "") {
    const alert = (App.state.alerts || []).find(a => a.id === alertId);
    if (!alert) return;

    alert.status = newStatus;
    alert.resolved = (newStatus === "Resolved");
    alert.action_taken = `Status transitioned to ${newStatus}`;
    if (comment) {
      alert.analyst_notes = alert.analyst_notes || [];
      alert.analyst_notes.push({
        author: "SecOps Analyst",
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        note: comment
      });
    }

    App.showToast(`Incident ${alertId} marked as ${newStatus}`, "success");
    this.renderAlerts();
    this.updateKpis();
    App.updateNotificationCount();
    App.renderNotificationsDropdown();
    if (window.OverviewView) OverviewView.updateData();

    try {
      const data = await window.ApiClient.alerts.updateStatus(alertId, newStatus, comment);
      if (data && data.kpis) App.state.kpis = data.kpis;
    } catch (e) {
      console.warn("[AlertsView] Status update error:", e);
    }
  },

  async executeBulkAction(action) {
    const alertIds = Array.from(this.selectedAlertIds);
    if (alertIds.length === 0) return;

    if (action === "isolate") {
      if (!confirm(`Are you sure you want to isolate devices associated with ${alertIds.length} selected incident(s)? This will cut off their network connectivity.`)) {
        return;
      }
      const affectedDevs = new Set();
      (App.state.alerts || []).filter(a => alertIds.includes(a.id)).forEach(a => {
        affectedDevs.add(a.device_id);
        a.action_taken = "Associated Device Quarantined / Network Cut";
      });
      affectedDevs.forEach(devId => App.quarantineDevice(devId, true));
      App.showToast(`Isolated ${affectedDevs.size} device(s) affected by selected alerts`, "danger");
    } else {
      const statusMap = {
        acknowledge: "Acknowledged",
        in_progress: "In Progress",
        resolve: "Resolved",
        reopen: "Reopened"
      };
      const targetStatus = statusMap[action] || "Acknowledged";
      (App.state.alerts || []).forEach(a => {
        if (alertIds.includes(a.id)) {
          a.status = targetStatus;
          a.resolved = (targetStatus === "Resolved");
          a.action_taken = `Bulk ${targetStatus} by SecOps`;
        }
      });
      App.showToast(`Bulk updated ${alertIds.length} incident(s) to ${targetStatus}`, "success");
    }

    this.clearSelection();
    this.renderAlerts();
    this.updateKpis();
    App.updateNotificationCount();
    App.renderNotificationsDropdown();
    if (window.OverviewView) OverviewView.updateData();

    try {
      const data = await window.ApiClient.alerts.bulkAction(alertIds, action);
      if (data) {
        if (data.alerts) App.state.alerts = data.alerts;
        if (data.kpis) App.state.kpis = data.kpis;
        this.renderAlerts();
        this.updateKpis();
      }
    } catch (e) {
      console.warn("[AlertsView] Bulk action error:", e);
    }
  },

  openIncidentDetails(alertId) {
    const alert = (App.state.alerts || []).find(a => a.id === alertId);
    if (!alert) return;

    const modal = document.getElementById("incident-modal");
    const content = document.getElementById("incident-modal-content");
    if (!modal || !content) return;

    const ind = alert.traffic_indicators || {};
    const notes = alert.analyst_notes || [];

    const sev = alert.severity || 'Critical';
    const status = alert.status || (alert.resolved ? 'Resolved' : 'New');
    const detectionSource = alert.detection_source || 'Dual-Fused Heuristics';
    const sourceIp = alert.source_ip || (App.state.devices && (App.state.devices.find(d => d.id === alert.device_id) || {}).ip) || '192.168.1.107';
    const classification = alert.classification || alert.category || 'Botnet Incursion';
    const reasonText = alert.reason || alert.details || 'Anomalous traffic telemetry exceeded baseline security thresholds.';
    const mitreTech = alert.mitre_technique || 'T1499 Denial of Service / T1046 Network Service Scanning';
    const suggestedAct = alert.suggested_action || 'Quarantine affected device and audit port activity.';
    const actionTaken = alert.action_taken || 'Alert Dispatched';

    const sevClass = `badge-sev-${sev.toLowerCase()}`;
    const statusClass = status === 'New' ? 'badge-status-new' :
                        (status === 'Acknowledged' ? 'badge-status-ack' :
                        (status === 'In Progress' ? 'badge-status-prog' :
                        (status === 'Resolved' ? 'badge-status-res' : 'badge-status-reopen')));

    const sourceBadge = detectionSource === 'ML Classifier' ? 'badge-normal' :
                        (detectionSource === 'Dual-Fused Heuristics' ? 'badge-high-risk' : 'badge-suspicious');

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <h2 style="font-size: 18px; display: flex; align-items: center; gap: 8px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Incident Forensic Dossier &amp; Triage File
          </h2>
          <span class="mono" style="color: var(--highlight-mint); font-size: 12px;">
            ${alert.id} &bull; ${alert.timestamp} &bull; Flow: ${alert.flow_id || 'N/A'}
          </span>
        </div>
        <button class="close-btn" onclick="document.getElementById('incident-modal').classList.remove('open')">&times;</button>
      </div>

      <!-- Classification & Severity Header -->
      <div style="background: var(--bg-surface); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Threat Signature</span>
          <div style="display: flex; gap: 6px;">
            <span class="badge ${sevClass}" style="font-weight: 700;">${sev}</span>
            <span class="badge ${statusClass}">${status}</span>
            <span class="badge ${sourceBadge}">${detectionSource}</span>
          </div>
        </div>
        <h3 style="font-size: 16px; color: var(--text-main); margin-bottom: 4px;">${alert.title}</h3>
        <p style="font-size: 13px; color: var(--text-secondary);">${reasonText}</p>
      </div>

      <!-- Affected Asset Card -->
      <div class="grid-2" style="background: var(--bg-card); padding: 12px 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 16px; font-size: 12px;">
        <div><span style="color: var(--text-muted);">Asset Name:</span> <strong>${alert.device_name}</strong></div>
        <div><span style="color: var(--text-muted);">Device Identifier:</span> <span class="mono">${alert.device_id}</span></div>
        <div><span style="color: var(--text-muted);">Source IP Address:</span> <span class="mono">${sourceIp}</span></div>
        <div><span style="color: var(--text-muted);">Threat Category:</span> <span>${classification}</span></div>
      </div>

      <!-- Telemetry Indicators Grid -->
      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Correlated Telemetry Indicators</div>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
          <div style="background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">Packet Rate</div>
            <div class="mono" style="font-size: 13px; font-weight: 700; color: #34d399;">${(ind.packet_rate || 0).toFixed(1)} pps</div>
          </div>
          <div style="background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">Target Port &amp; IP</div>
            <div class="mono" style="font-size: 13px; font-weight: 700; color: #f87171;">Port ${ind.dest_port || 80} &bull; ${ind.dest_ip || 'Ext Host'}</div>
          </div>
          <div style="background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">TCP SYN Ratio</div>
            <div class="mono" style="font-size: 13px; font-weight: 700; color: #fb923c;">${(ind.syn_ratio || 0).toFixed(2)}</div>
          </div>
          <div style="background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">Connection Rate</div>
            <div class="mono" style="font-size: 13px; font-weight: 700; color: #38bdf8;">${(ind.conn_freq || 0).toFixed(1)} /10s</div>
          </div>
          <div style="background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">Payload Entropy</div>
            <div class="mono" style="font-size: 13px; font-weight: 700; color: #a78bfa;">${(ind.payload_entropy || 0).toFixed(2)} bits/B</div>
          </div>
          <div style="background: var(--bg-surface); padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 10px; color: var(--text-muted);">Estimated Throughput</div>
            <div class="mono" style="font-size: 13px; font-weight: 700; color: var(--highlight-mint);">${((ind.byte_rate || 0) / 1024).toFixed(1)} KB/s</div>
          </div>
        </div>
      </div>

      <!-- MITRE ATT&CK Mapping Card -->
      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">MITRE ATT&CK for IoT Mapping</div>
        <div style="background: var(--bg-surface); padding: 10px 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
          <strong style="color: var(--highlight-mint); font-size: 13px;">${mitreTech}</strong>
          <p style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
            Pattern aligns with automated adversarial campaigns involving IoT botnet command sweeps, vulnerability scanning, or volumetric bandwidth exhaustion.
          </p>
        </div>
      </div>

      <!-- Suggested Next Action & Active Remediation -->
      <div style="background: rgba(34, 197, 94, 0.08); border: 1px solid var(--primary-accent); padding: 12px 14px; border-radius: var(--radius-md); margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <div style="font-size: 11px; text-transform: uppercase; color: var(--highlight-mint); font-weight: 700;">Prescribed Mitigation Playbook</div>
          <div style="font-size: 11px; color: var(--text-muted);">Remediation Status: <strong style="color: var(--text-main); font-family: var(--font-mono);">${actionTaken}</strong></div>
        </div>
        <p style="font-size: 13px; color: var(--text-main); margin: 0;">${suggestedAct}</p>
      </div>

      <!-- Analyst Investigation Notes Thread -->
      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Analyst Forensics &amp; Audit Trail</div>
        <div class="notes-timeline" id="incident-notes-list">
          ${notes.length === 0 ? `
            <div style="color: var(--text-muted); font-size: 12px; font-style: italic;">No analyst notes logged yet.</div>
          ` : notes.map(n => `
            <div class="note-bubble">
              <div class="note-header">
                <span class="note-author">${n.author}</span>
                <span class="note-time">${n.timestamp}</span>
              </div>
              <div style="color: var(--text-main);">${n.note}</div>
            </div>
          `).join("")}
        </div>

        <!-- Add Note Input -->
        <div style="display: flex; gap: 8px; margin-top: 8px;">
          <input type="text" id="input-new-note" class="cyber-input" placeholder="Type analyst finding or investigation note..." style="flex: 1; font-size: 12px;" onkeydown="if(event.key === 'Enter') AlertsView.submitAnalystNote('${alert.id}')" />
          <button class="btn btn-secondary btn-sm" onclick="AlertsView.submitAnalystNote('${alert.id}')">Add Note</button>
        </div>
      </div>

      <!-- Modal Action Buttons Footer -->
      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: 12px;">
        <div style="display: flex; gap: 6px;">
          ${alert.status !== 'Acknowledged' && !alert.resolved ? `
            <button class="btn btn-secondary btn-sm" onclick="AlertsView.updateStatus('${alert.id}', 'Acknowledged'); AlertsView.openIncidentDetails('${alert.id}');">Acknowledge</button>
          ` : ''}
          ${alert.status !== 'In Progress' && !alert.resolved ? `
            <button class="btn btn-secondary btn-sm" onclick="AlertsView.updateStatus('${alert.id}', 'In Progress'); AlertsView.openIncidentDetails('${alert.id}');">Start Investigation</button>
          ` : ''}
          ${!alert.resolved ? `
            <button class="btn btn-primary btn-sm" onclick="AlertsView.updateStatus('${alert.id}', 'Resolved'); AlertsView.openIncidentDetails('${alert.id}');">Mark Resolved</button>
            <button class="btn btn-danger btn-sm" onclick="App.quarantineDevice('${alert.device_id}', true); document.getElementById('incident-modal').classList.remove('open');">Isolate Device</button>
          ` : `
            <button class="btn btn-secondary btn-sm" onclick="AlertsView.updateStatus('${alert.id}', 'Reopened'); AlertsView.openIncidentDetails('${alert.id}');">Reopen Incident</button>
          `}
        </div>
        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('incident-modal').classList.remove('open')">Close</button>
      </div>
    `;

    modal.classList.add("open");
  },

  async submitAnalystNote(alertId) {
    const input = document.getElementById("input-new-note");
    if (!input || !input.value.trim()) return;

    const noteText = input.value.trim();
    const alert = (App.state.alerts || []).find(a => a.id === alertId);
    if (alert) {
      alert.analyst_notes = alert.analyst_notes || [];
      alert.analyst_notes.push({
        author: "SecOps Analyst",
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        note: noteText
      });
      input.value = "";
      this.openIncidentDetails(alertId);
      App.showToast("Analyst note appended to incident dossier", "success");

      try {
        await window.ApiClient.alerts.addNote(alertId, noteText, "SecOps Analyst");
      } catch (e) {
        console.warn("[AlertsView] Note add error:", e);
      }
    }
  },

  exportAlerts(format) {
    const alerts = App.state.alerts || (window.IOT_FALLBACK_DATA ? window.IOT_FALLBACK_DATA.alerts : []);
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `iot_botnet_incidents_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      let csv = "Alert ID,Timestamp,Severity,Device ID,Device Name,Source IP,Threat Classification,Title,Detection Source,Reason,Status,MITRE Technique,Suggested Action,Action Taken\n";
      alerts.forEach(a => {
        const title = (a.title || "").replace(/"/g, '""');
        const devName = (a.device_name || "").replace(/"/g, '""');
        const cat = (a.classification || a.category || "").replace(/"/g, '""');
        const reason = (a.reason || a.details || "").replace(/"/g, '""');
        const mitre = (a.mitre_technique || "").replace(/"/g, '""');
        const action = (a.suggested_action || "").replace(/"/g, '""');
        const taken = (a.action_taken || "").replace(/"/g, '""');
        csv += `"${a.id}","${a.timestamp}","${a.severity}","${a.device_id}","${devName}","${a.source_ip || ''}","${cat}","${title}","${a.detection_source || ''}","${reason}","${a.status || ''}","${mitre}","${action}","${taken}"\n`;
      });
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `iot_botnet_incidents_${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    }
    App.showToast(`Exported ${alerts.length} incident dossiers as ${format.toUpperCase()}`, "info");
  }
};
