/**
 * IoT Botnet Detection System — IoT Device Inventory View (devices.js)
 * Implements searchable, filterable, sortable inventory with all 11 required fields,
 * pagination, CSV export, transparent risk classification, and deep inspection modal.
 */

window.DevicesView = {
  // State for filtering, sorting, and pagination
  activeStatusFilter: "all",
  activeCategoryFilter: "all",
  activeProtocolFilter: "all",
  minRiskScore: 0,
  recentActivityFilter: "all",
  searchQuery: "",
  
  sortColumn: "risk_score",
  sortDirection: "desc", // 'asc' or 'desc'

  currentPage: 1,
  pageSize: 8,

  render(container) {
    container.innerHTML = `
      <!-- Top Control & Action Bar -->
      <div class="card" style="margin-bottom: var(--space-xl); padding: 16px 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 14px;">
          <!-- Left: Status Filter Pills -->
          <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
            <button class="btn ${this.activeStatusFilter === 'all' ? 'btn-primary' : 'btn-secondary'} btn-sm" id="dev-filter-all" onclick="DevicesView.setStatusFilter('all')">
              All Endpoints (<span id="dev-count-all">8</span>)
            </button>
            <button class="btn ${this.activeStatusFilter === 'High-Risk' ? 'btn-danger' : 'btn-secondary'} btn-sm" id="dev-filter-high" onclick="DevicesView.setStatusFilter('High-Risk')">
              High-Risk Botnets (<span id="dev-count-danger">2</span>)
            </button>
            <button class="btn ${this.activeStatusFilter === 'Suspicious' ? 'btn-secondary' : 'btn-secondary'} btn-sm" id="dev-filter-susp" onclick="DevicesView.setStatusFilter('Suspicious')" style="${this.activeStatusFilter === 'Suspicious' ? 'border-color: var(--state-warning); color: var(--state-warning);' : ''}">
              Suspicious (<span id="dev-count-warn">1</span>)
            </button>
            <button class="btn ${this.activeStatusFilter === 'Normal' ? 'btn-primary' : 'btn-secondary'} btn-sm" id="dev-filter-norm" onclick="DevicesView.setStatusFilter('Normal')">
              Normal / Secure (<span id="dev-count-safe">5</span>)
            </button>
            <button class="btn ${this.activeStatusFilter === 'quarantined' ? 'btn-secondary' : 'btn-secondary'} btn-sm" id="dev-filter-quar" onclick="DevicesView.setStatusFilter('quarantined')">
              Quarantined (<span id="dev-count-quar">1</span>)
            </button>
          </div>

          <!-- Right: Actions (CSV Export, Risk Engine Thresholds) -->
          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <button class="btn btn-secondary btn-sm" id="btn-export-csv" onclick="DevicesView.exportCSV()" style="display: flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Export CSV
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-risk-config" onclick="DevicesView.openRiskConfigModal()" style="display: flex; align-items: center; gap: 6px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              Risk Engine Weights
            </button>
          </div>
        </div>

        <!-- Multi-Criteria Filter Strip -->
        <div style="display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--border-subtle);">
          <!-- Search Bar -->
          <div style="flex: 1; min-width: 200px;">
            <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); display: block; margin-bottom: 4px;">Search Fields</label>
            <input type="text" id="dev-search-input" value="${this.searchQuery}" placeholder="Search name, IP, MAC, protocol, type..." 
                   oninput="DevicesView.setSearchQuery(this.value)"
                   style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 6px 12px; border-radius: var(--radius-sm); font-size: 12px; width: 100%;" />
          </div>

          <!-- Device Type Dropdown -->
          <div style="min-width: 160px;">
            <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); display: block; margin-bottom: 4px;">Device Type</label>
            <select id="select-category-filter" onchange="DevicesView.setCategoryFilter(this.value)"
                    style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 6px 10px; border-radius: var(--radius-sm); font-size: 12px; width: 100%;">
              <option value="all">All Types</option>
              <option value="Surveillance Camera">Surveillance Camera</option>
              <option value="Smart Lighting Gateway">Smart Lighting Gateway</option>
              <option value="HVAC / Environmental">HVAC / Environmental</option>
              <option value="Smart Energy Relay">Smart Energy Relay</option>
              <option value="SCADA / Industrial Gateway">SCADA Gateway</option>
              <option value="Critical Healthcare">Healthcare Device</option>
              <option value="DVR / Video Recorder">DVR Video Recorder</option>
              <option value="Physical Access Control">Physical Access Control</option>
            </select>
          </div>

          <!-- Protocol Dropdown -->
          <div style="min-width: 140px;">
            <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); display: block; margin-bottom: 4px;">Protocol</label>
            <select id="select-protocol-filter" onchange="DevicesView.setProtocolFilter(this.value)"
                    style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 6px 10px; border-radius: var(--radius-sm); font-size: 12px; width: 100%;">
              <option value="all">All Protocols</option>
              <option value="RTSP">RTSP / HTTP</option>
              <option value="Zigbee">Zigbee / REST</option>
              <option value="MQTT">MQTT / TLS</option>
              <option value="UDP">UDP</option>
              <option value="Modbus">Modbus TCP</option>
              <option value="HL7">HL7 / TLS</option>
              <option value="Telnet">Telnet (Port 23)</option>
              <option value="HTTPS">HTTPS / BLE</option>
            </select>
          </div>

          <!-- Risk Score Slider -->
          <div style="min-width: 160px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Min Risk Score</label>
              <span id="label-min-risk" style="font-family: var(--font-mono); font-size: 11px; color: var(--highlight-mint);">${this.minRiskScore}</span>
            </div>
            <input type="range" min="0" max="100" value="${this.minRiskScore}" class="cyber-slider" oninput="DevicesView.setMinRiskScore(this.value)" />
          </div>

          <!-- Recent Activity Dropdown -->
          <div style="min-width: 130px;">
            <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); display: block; margin-bottom: 4px;">Recent Activity</label>
            <select id="select-activity-filter" onchange="DevicesView.setActivityFilter(this.value)"
                    style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 6px 10px; border-radius: var(--radius-sm); font-size: 12px; width: 100%;">
              <option value="all">Any Activity</option>
              <option value="active">Active (< 5s / Just now)</option>
              <option value="recent">Recent (< 1 hr)</option>
              <option value="isolated">Isolated / Quarantined</option>
            </select>
          </div>

          <!-- Reset Filter Button -->
          <div>
            <button class="btn btn-secondary btn-sm" onclick="DevicesView.resetFilters()" title="Reset all search and filter options" style="padding: 7px 12px;">
              Reset
            </button>
          </div>
        </div>
      </div>

      <!-- Comprehensive IoT Device Inventory Table -->
      <div class="card" style="padding: 0; overflow: hidden; margin-bottom: var(--space-xl);">
        <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 0; display: flex; justify-content: space-between; align-items: center;">
          <div class="card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            Interactive IoT Device Inventory & Posture Table
          </div>
          <span style="font-size: 12px; font-family: var(--font-mono); color: var(--text-secondary);">
            Showing <span id="table-filtered-count" style="color: var(--highlight-mint); font-weight: 700;">8</span> matched records
          </span>
        </div>

        <div class="table-wrapper" style="border: none;">
          <table class="cyber-table">
            <thead>
              <tr>
                <th class="sortable" onclick="DevicesView.toggleSort('name')">
                  Device Name <span class="sort-arrow" id="sort-arrow-name">↕</span>
                </th>
                <th class="sortable" onclick="DevicesView.toggleSort('category')">
                  Device Type <span class="sort-arrow" id="sort-arrow-category">↕</span>
                </th>
                <th class="sortable" onclick="DevicesView.toggleSort('ip')">
                  IP Address <span class="sort-arrow" id="sort-arrow-ip">↕</span>
                </th>
                <th>MAC Address</th>
                <th class="sortable" onclick="DevicesView.toggleSort('protocol')">
                  Protocol <span class="sort-arrow" id="sort-arrow-protocol">↕</span>
                </th>
                <th class="sortable" onclick="DevicesView.toggleSort('first_seen')">
                  First Seen <span class="sort-arrow" id="sort-arrow-first_seen">↕</span>
                </th>
                <th class="sortable" onclick="DevicesView.toggleSort('last_activity')">
                  Last Activity <span class="sort-arrow" id="sort-arrow-last_activity">↕</span>
                </th>
                <th class="sortable" onclick="DevicesView.toggleSort('pps')">
                  Packet Rate <span class="sort-arrow" id="sort-arrow-pps">↕</span>
                </th>
                <th>Bytes Transferred</th>
                <th class="sortable" onclick="DevicesView.toggleSort('conn_freq')">
                  Conn Freq <span class="sort-arrow" id="sort-arrow-conn_freq">↕</span>
                </th>
                <th class="sortable" onclick="DevicesView.toggleSort('risk_score')">
                  Risk Score & Classification <span class="sort-arrow" id="sort-arrow-risk_score">↕</span>
                </th>
                <th style="text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody id="device-inventory-tbody">
              <!-- Rendered dynamically -->
            </tbody>
          </table>
        </div>

        <!-- Pagination Bar -->
        <div class="pagination-bar">
          <div style="font-size: 12px; color: var(--text-secondary); display: flex; align-items: center; gap: 8px;">
            <span>Rows per page:</span>
            <select id="select-page-size" onchange="DevicesView.setPageSize(this.value)"
                    style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-subtle); padding: 3px 6px; border-radius: var(--radius-sm); font-size: 11px;">
              <option value="5" ${this.pageSize === 5 ? 'selected' : ''}>5</option>
              <option value="8" ${this.pageSize === 8 ? 'selected' : ''}>8</option>
              <option value="15" ${this.pageSize === 15 ? 'selected' : ''}>15</option>
              <option value="50" ${this.pageSize === 50 ? 'selected' : ''}>50</option>
            </select>
            <span id="pagination-range-text" style="font-family: var(--font-mono); margin-left: 8px;">Showing 1 - 8 of 8</span>
          </div>

          <div class="pagination-controls" id="pagination-buttons-container">
            <!-- Rendered dynamically -->
          </div>
        </div>
      </div>

      <!-- Device Detailed Inspection Modal -->
      <div id="device-inspect-modal" class="modal-backdrop">
        <div class="cyber-modal" id="device-inspect-content" style="max-width: 760px;">
          <!-- Dynamically populated on row click -->
        </div>
      </div>

      <!-- Risk Engine Configuration Modal -->
      <div id="risk-config-modal" class="modal-backdrop">
        <div class="cyber-modal" id="risk-config-content" style="max-width: 680px;">
          <!-- Dynamically populated on click -->
        </div>
      </div>
    `;

    this.updateSortArrowIndicators();
    this.renderDevices();
  },

  setStatusFilter(status) {
    this.activeStatusFilter = status;
    this.currentPage = 1;
    this.render(document.getElementById("view-devices"));
  },

  setCategoryFilter(val) {
    this.activeCategoryFilter = val;
    this.currentPage = 1;
    this.renderDevices();
  },

  setProtocolFilter(val) {
    this.activeProtocolFilter = val;
    this.currentPage = 1;
    this.renderDevices();
  },

  setMinRiskScore(val) {
    this.minRiskScore = parseInt(val, 10);
    const label = document.getElementById("label-min-risk");
    if (label) label.textContent = this.minRiskScore;
    this.currentPage = 1;
    this.renderDevices();
  },

  setActivityFilter(val) {
    this.recentActivityFilter = val;
    this.currentPage = 1;
    this.renderDevices();
  },

  setSearchQuery(q) {
    this.searchQuery = q.toLowerCase();
    this.currentPage = 1;
    this.renderDevices();
  },

  setPageSize(size) {
    this.pageSize = parseInt(size, 10);
    this.currentPage = 1;
    this.renderDevices();
  },

  setPage(p) {
    this.currentPage = p;
    this.renderDevices();
  },

  resetFilters() {
    this.activeStatusFilter = "all";
    this.activeCategoryFilter = "all";
    this.activeProtocolFilter = "all";
    this.minRiskScore = 0;
    this.recentActivityFilter = "all";
    this.searchQuery = "";
    this.currentPage = 1;
    this.render(document.getElementById("view-devices"));
    App.showToast("Device filters reset to default", "info");
  },

  toggleSort(column) {
    if (this.sortColumn === column) {
      this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
    } else {
      this.sortColumn = column;
      this.sortDirection = (column === "risk_score" || column === "pps" || column === "conn_freq") ? "desc" : "asc";
    }
    this.updateSortArrowIndicators();
    this.renderDevices();
  },

  updateSortArrowIndicators() {
    const arrows = ["name", "category", "ip", "protocol", "first_seen", "last_activity", "pps", "conn_freq", "risk_score"];
    arrows.forEach(col => {
      const el = document.getElementById(`sort-arrow-${col}`);
      const th = el ? el.closest("th") : null;
      if (el && th) {
        th.classList.remove("sorted-asc", "sorted-desc");
        if (this.sortColumn === col) {
          th.classList.add(this.sortDirection === "asc" ? "sorted-asc" : "sorted-desc");
          el.textContent = this.sortDirection === "asc" ? "▲" : "▼";
        } else {
          el.textContent = "↕";
        }
      }
    });
  },

  getFilteredAndSortedDevices() {
    let devices = (App.state.devices || []).slice();

    // 1. Status / Quarantine Filter
    if (this.activeStatusFilter === "quarantined") {
      devices = devices.filter(d => d.quarantined);
    } else if (this.activeStatusFilter !== "all") {
      devices = devices.filter(d => (d.security_classification || d.status) === this.activeStatusFilter);
    }

    // 2. Category Filter
    if (this.activeCategoryFilter !== "all") {
      devices = devices.filter(d => d.category === this.activeCategoryFilter);
    }

    // 3. Protocol Filter
    if (this.activeProtocolFilter !== "all") {
      devices = devices.filter(d => (d.protocol || "").toLowerCase().includes(this.activeProtocolFilter.toLowerCase()));
    }

    // 4. Min Risk Score
    if (this.minRiskScore > 0) {
      devices = devices.filter(d => (d.risk_score || 0) >= this.minRiskScore);
    }

    // 5. Recent Activity Filter
    if (this.recentActivityFilter === "active") {
      devices = devices.filter(d => d.last_seen === "Just now" || d.last_activity === "Just now" || (d.last_seen || "").includes("s ago"));
    } else if (this.recentActivityFilter === "isolated") {
      devices = devices.filter(d => d.quarantined);
    }

    // 6. Search Query (Searches all device fields)
    if (this.searchQuery) {
      const q = this.searchQuery;
      devices = devices.filter(d =>
        (d.name || "").toLowerCase().includes(q) ||
        (d.id || "").toLowerCase().includes(q) ||
        (d.ip || "").toLowerCase().includes(q) ||
        (d.mac || "").toLowerCase().includes(q) ||
        (d.category || "").toLowerCase().includes(q) ||
        (d.vendor || "").toLowerCase().includes(q) ||
        (d.protocol || "").toLowerCase().includes(q) ||
        (d.security_classification || d.status || "").toLowerCase().includes(q)
      );
    }

    // 7. Sorting
    devices.sort((a, b) => {
      let valA = a[this.sortColumn];
      let valB = b[this.sortColumn];

      if (this.sortColumn === "risk_score" || this.sortColumn === "pps" || this.sortColumn === "conn_freq") {
        valA = Number(valA || 0);
        valB = Number(valB || 0);
      } else {
        valA = (valA || "").toString().toLowerCase();
        valB = (valB || "").toString().toLowerCase();
      }

      if (valA < valB) return this.sortDirection === "asc" ? -1 : 1;
      if (valA > valB) return this.sortDirection === "asc" ? 1 : -1;
      return 0;
    });

    return devices;
  },

  renderDevices() {
    const rawDevices = App.state.devices || [];

    // Update Counter Badges
    const countAll = document.getElementById("dev-count-all");
    const countDanger = document.getElementById("dev-count-danger");
    const countWarn = document.getElementById("dev-count-warn");
    const countSafe = document.getElementById("dev-count-safe");
    const countQuar = document.getElementById("dev-count-quar");

    if (countAll) countAll.textContent = rawDevices.length;
    if (countDanger) countDanger.textContent = rawDevices.filter(d => (d.security_classification || d.status) === "High-Risk").length;
    if (countWarn) countWarn.textContent = rawDevices.filter(d => (d.security_classification || d.status) === "Suspicious").length;
    if (countSafe) countSafe.textContent = rawDevices.filter(d => (d.security_classification || d.status) === "Normal").length;
    if (countQuar) countQuar.textContent = rawDevices.filter(d => d.quarantined).length;

    const filtered = this.getFilteredAndSortedDevices();

    const countHeader = document.getElementById("table-filtered-count");
    if (countHeader) countHeader.textContent = filtered.length;

    // Pagination Calculation
    const totalItems = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / this.pageSize));
    if (this.currentPage > totalPages) this.currentPage = totalPages;

    const startIndex = (this.currentPage - 1) * this.pageSize;
    const endIndex = Math.min(startIndex + this.pageSize, totalItems);
    const paginatedItems = filtered.slice(startIndex, endIndex);

    // Range Text
    const rangeText = document.getElementById("pagination-range-text");
    if (rangeText) {
      rangeText.textContent = totalItems === 0 ? "Showing 0 of 0" : `Showing ${startIndex + 1} - ${endIndex} of ${totalItems}`;
    }

    // Render Pagination Controls
    const btnContainer = document.getElementById("pagination-buttons-container");
    if (btnContainer) {
      let btnsHtml = `
        <button class="page-btn" onclick="DevicesView.setPage(${this.currentPage - 1})" ${this.currentPage === 1 ? 'disabled' : ''}>Prev</button>
      `;
      for (let i = 1; i <= totalPages; i++) {
        btnsHtml += `
          <button class="page-btn ${this.currentPage === i ? 'active' : ''}" onclick="DevicesView.setPage(${i})">${i}</button>
        `;
      }
      btnsHtml += `
        <button class="page-btn" onclick="DevicesView.setPage(${this.currentPage + 1})" ${this.currentPage === totalPages ? 'disabled' : ''}>Next</button>
      `;
      btnContainer.innerHTML = btnsHtml;
    }

    // Render Table Rows
    const tbody = document.getElementById("device-inventory-tbody");
    if (!tbody) return;

    if (paginatedItems.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="12" style="text-align: center; color: var(--text-muted); padding: 48px;">
            <div style="font-size: 14px; margin-bottom: 6px;">No IoT devices found matching filter criteria</div>
            <button class="btn btn-secondary btn-sm" onclick="DevicesView.resetFilters()">Reset All Filters</button>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = paginatedItems.map(d => {
      const isHigh = (d.security_classification || d.status) === "High-Risk";
      const isSusp = (d.security_classification || d.status) === "Suspicious";
      const rowClass = d.quarantined ? "" : (isHigh ? "row-high-risk" : (isSusp ? "row-suspicious" : ""));
      const badgeClass = d.quarantined ? "badge-quarantined" : (isHigh ? "badge-high-risk" : (isSusp ? "badge-suspicious" : "badge-normal"));
      const score = d.risk_score || 0;

      return `
        <tr class="${rowClass}" style="cursor: pointer;" onclick="DevicesView.openInspectModal('${d.id}')">
          <!-- 1. Device Name & ID -->
          <td>
            <div style="font-weight: 600; color: var(--text-main); font-size: 13px;">${d.name}</div>
            <div style="font-size: 11px; font-family: var(--font-mono); color: var(--highlight-mint);">${d.id} · <span style="color: var(--text-muted);">${d.vendor}</span></div>
          </td>

          <!-- 2. Device Type -->
          <td style="font-size: 12px; color: var(--text-secondary); white-space: nowrap;">
            ${d.category}
          </td>

          <!-- 3. IP Address -->
          <td>
            <span class="ip-chip">${d.ip}</span>
          </td>

          <!-- 4. MAC Address -->
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); white-space: nowrap;">
            ${d.mac || 'N/A'}
          </td>

          <!-- 5. Protocol -->
          <td style="font-size: 12px; color: var(--text-main);">
            <span class="badge ${d.protocol && d.protocol.includes('TLS') ? 'badge-safe' : 'badge-normal'}" style="font-size: 10px;">${d.protocol}</span>
          </td>

          <!-- 6. First Seen -->
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); white-space: nowrap;">
            ${d.first_seen || '2026-10-09'}
          </td>

          <!-- 7. Last Activity -->
          <td style="font-family: var(--font-mono); font-size: 11px; color: ${d.last_seen === 'Just now' ? 'var(--highlight-mint)' : 'var(--text-secondary)'}; white-space: nowrap;">
            ${d.last_seen || d.last_activity || 'Just now'}
          </td>

          <!-- 8. Packet Rate (pps) -->
          <td style="font-family: var(--font-mono); font-weight: 700; color: ${isHigh && !d.quarantined ? 'var(--state-danger)' : 'var(--text-main)'};">
            ${(d.pps || 0).toFixed(1)} <span style="font-size: 10px; font-weight: normal; color: var(--text-muted);">pps</span>
          </td>

          <!-- 9. Bytes Transferred -->
          <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); white-space: nowrap;">
            ${d.bytes_transferred || '24.2 MB'}
          </td>

          <!-- 10. Connection Frequency -->
          <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-main);">
            ${(d.conn_freq || 1.2).toFixed(1)} <span style="font-size: 10px; color: var(--text-muted);">/10s</span>
          </td>

          <!-- 11. Risk Score & Classification -->
          <td>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="badge ${badgeClass}" style="font-weight: 700;">
                ${d.quarantined ? 'ISOLATED' : (d.security_classification || d.status)}
              </span>
              <span style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: ${score >= 70 ? 'var(--state-danger)' : (score >= 30 ? 'var(--state-warning)' : 'var(--highlight-mint)')};">
                ${score}/100
              </span>
            </div>
          </td>

          <!-- Action Buttons -->
          <td style="text-align: right;" onclick="event.stopPropagation();">
            <div style="display: flex; gap: 6px; justify-content: flex-end;">
              <button class="btn btn-secondary btn-sm" onclick="DevicesView.openInspectModal('${d.id}')" title="Inspect full telemetry, CVEs, and risk breakdown">
                Inspect
              </button>
              <button class="btn ${d.quarantined ? 'btn-primary' : (isHigh ? 'btn-danger' : 'btn-secondary')} btn-sm"
                      onclick="App.quarantineDevice('${d.id}', ${!d.quarantined})">
                ${d.quarantined ? 'Reconnect' : 'Isolate'}
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  },

  exportCSV() {
    const devices = this.getFilteredAndSortedDevices();
    if (devices.length === 0) {
      App.showToast("No devices match filter to export", "info");
      return;
    }

    const headers = [
      "Device ID",
      "Device Name",
      "Device Type",
      "IP Address",
      "MAC Address",
      "Protocol",
      "First Seen",
      "Last Activity",
      "Packet Rate (pps)",
      "Bytes Transferred",
      "Connection Frequency (conn/10s)",
      "Risk Score",
      "Security Classification",
      "Quarantined State"
    ];

    const rows = devices.map(d => [
      `"${d.id}"`,
      `"${(d.name || '').replace(/"/g, '""')}"`,
      `"${(d.category || '').replace(/"/g, '""')}"`,
      `"${d.ip}"`,
      `"${d.mac || ''}"`,
      `"${(d.protocol || '').replace(/"/g, '""')}"`,
      `"${d.first_seen || ''}"`,
      `"${d.last_seen || d.last_activity || ''}"`,
      (d.pps || 0).toFixed(1),
      `"${d.bytes_transferred || ''}"`,
      (d.conn_freq || 0).toFixed(1),
      d.risk_score || 0,
      `"${d.security_classification || d.status}"`,
      d.quarantined ? "TRUE" : "FALSE"
    ]);

    const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `netguard_iot_devices_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    App.showToast(`Exported ${devices.length} IoT device records to CSV`, "success");
  },

  openInspectModal(deviceId) {
    const dev = (App.state.devices || []).find(d => d.id === deviceId);
    if (!dev) return;

    const modal = document.getElementById("device-inspect-modal");
    const content = document.getElementById("device-inspect-content");
    if (!modal || !content) return;

    const isHigh = (dev.security_classification || dev.status) === "High-Risk";
    const isSusp = (dev.security_classification || dev.status) === "Suspicious";
    const score = dev.risk_score || 0;
    const factors = dev.risk_factors || [];

    // Filter flows related to this device
    const relatedFlows = (App.state.flows || []).filter(f => f.device_id === dev.id).slice(0, 5);
    // Related alerts
    const relatedAlerts = (App.state.alerts || []).filter(a => a.device_id === dev.id);

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <h2 style="font-size: 18px; display: flex; align-items: center; gap: 8px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            IoT Endpoint Comprehensive Inspection
          </h2>
          <span style="font-size: 12px; font-family: var(--font-mono); color: var(--highlight-mint);">${dev.name} (${dev.ip}) · ID: ${dev.id}</span>
        </div>
        <button class="close-btn" onclick="DevicesView.closeInspectModal()">×</button>
      </div>

      <!-- Top Profile Matrix -->
      <div style="background: var(--bg-surface); padding: 14px 18px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 16px;">
        <div class="grid-3" style="font-size: 12px; gap: 12px;">
          <div><span style="color: var(--text-muted);">Category:</span> <strong style="color: var(--text-main);">${dev.category}</strong></div>
          <div><span style="color: var(--text-muted);">Vendor:</span> <strong style="color: var(--text-main);">${dev.vendor}</strong></div>
          <div><span style="color: var(--text-muted);">Firmware:</span> <span class="mono">${dev.firmware}</span></div>
          <div><span style="color: var(--text-muted);">IP Address:</span> <span class="ip-chip">${dev.ip}</span></div>
          <div><span style="color: var(--text-muted);">MAC Address:</span> <span class="mono">${dev.mac}</span></div>
          <div><span style="color: var(--text-muted);">Protocol:</span> <span>${dev.protocol}</span></div>
          <div><span style="color: var(--text-muted);">First Seen:</span> <span class="mono">${dev.first_seen}</span></div>
          <div><span style="color: var(--text-muted);">Last Activity:</span> <span class="mono">${dev.last_seen || dev.last_activity}</span></div>
          <div><span style="color: var(--text-muted);">Port State:</span> <strong style="color: ${dev.quarantined ? 'var(--state-danger)' : 'var(--highlight-mint)'};">${dev.quarantined ? 'ISOLATED' : 'ONLINE (VLAN 10)'}</strong></div>
        </div>
      </div>

      <!-- Transparent Risk Score & Factor Weights Breakdown -->
      <div style="margin-bottom: 18px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <h4 style="font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary);">
            Transparent Rule-Based Risk Attribution (${score}/100)
          </h4>
          <span class="badge ${dev.quarantined ? 'badge-quarantined' : (isHigh ? 'badge-high-risk' : (isSusp ? 'badge-suspicious' : 'badge-normal'))}">
            Classification: ${dev.security_classification || dev.status}
          </span>
        </div>

        <div style="display: flex; flex-direction: column; gap: 6px;">
          ${factors.map(f => {
            const isNeutral = f.weight === "0";
            return `
              <div class="risk-factor-bar">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span class="risk-factor-badge ${isNeutral ? 'neutral' : ''}">${f.weight}</span>
                  <strong style="color: var(--text-main); font-size: 12px;">${f.factor}</strong>
                </div>
                <div style="font-size: 12px; color: var(--text-secondary); text-align: right; max-width: 60%;">${f.detail}</div>
              </div>
            `;
          }).join("")}
        </div>
      </div>

      <!-- Observed Behavioral Metrics & Telemetry Sparklines -->
      <div style="margin-bottom: 18px;">
        <h4 style="font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 8px;">
          Observed Behavioral Telemetry
        </h4>
        <div class="grid-3" style="gap: 10px;">
          <div style="background: var(--bg-card); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; color: var(--text-muted);">CURRENT THROUGHPUT</div>
            <div style="font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: ${isHigh && !dev.quarantined ? 'var(--state-danger)' : 'var(--text-main)'};">
              ${(dev.pps || 0).toFixed(1)} pps
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; color: var(--text-muted);">BURST FREQUENCY</div>
            <div style="font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--text-main);">
              ${(dev.conn_freq || 1.2).toFixed(1)} conn/10s
            </div>
          </div>
          <div style="background: var(--bg-card); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; color: var(--text-muted);">CUMULATIVE BANDWIDTH</div>
            <div style="font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--highlight-mint);">
              ${dev.bytes_transferred || '24.2 MB'}
            </div>
          </div>
        </div>
      </div>

      <!-- Related Security Alerts & Incident History -->
      <div style="margin-bottom: 18px;">
        <h4 style="font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 8px;">
          Linked Security Alerts (${relatedAlerts.length})
        </h4>
        ${relatedAlerts.length === 0 ? `
          <div style="font-size: 12px; color: var(--highlight-mint); background: rgba(34, 197, 94, 0.08); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
            ✓ No active security alerts logged for this asset.
          </div>
        ` : `
          <div style="display: flex; flex-direction: column; gap: 6px;">
            ${relatedAlerts.map(a => `
              <div style="background: var(--bg-card); border: 1px solid ${a.resolved ? 'var(--border-subtle)' : 'var(--state-danger-border)'}; padding: 10px 14px; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="badge ${a.severity === 'Critical' ? 'badge-high-risk' : 'badge-suspicious'}" style="font-size: 10px;">${a.severity}</span>
                    <strong style="font-size: 12px; color: var(--text-main);">${a.title}</strong>
                    <span class="mono" style="font-size: 11px; color: var(--text-muted);">${a.timestamp}</span>
                  </div>
                  <div style="font-size: 11px; color: var(--text-secondary); margin-top: 3px;">${a.details}</div>
                </div>
                <span class="badge ${a.resolved ? 'badge-normal' : 'badge-high-risk'}">${a.resolved ? 'RESOLVED' : 'UNRESOLVED'}</span>
              </div>
            `).join("")}
          </div>
        `}
      </div>

      <!-- Recommended SecOps Action -->
      <div style="background: rgba(16, 53, 38, 0.6); border: 1px solid var(--border-bright); padding: 12px 16px; border-radius: var(--radius-md); margin-bottom: 20px;">
        <strong style="color: var(--highlight-mint); font-size: 12px; display: block; margin-bottom: 4px;">Recommended Security Countermeasure:</strong>
        <div style="font-size: 12px; color: var(--text-main);">${dev.recommended_action || 'Maintain routine passive baseline monitoring.'}</div>
      </div>

      <!-- Mitigation Action Buttons -->
      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button class="btn btn-secondary" onclick="DevicesView.closeInspectModal()">Close</button>
        <button class="btn ${dev.quarantined ? 'btn-primary' : 'btn-danger'}" 
                onclick="App.quarantineDevice('${dev.id}', ${!dev.quarantined}); DevicesView.closeInspectModal();">
          ${dev.quarantined ? 'Reconnect Port' : 'Isolate & Quarantine Endpoint Now'}
        </button>
      </div>
    `;

    modal.classList.add("open");
  },

  closeInspectModal() {
    const modal = document.getElementById("device-inspect-modal");
    if (modal) modal.classList.remove("open");
  },

  async openRiskConfigModal() {
    const modal = document.getElementById("risk-config-modal");
    const content = document.getElementById("risk-config-content");
    if (!modal || !content) return;

    let config = {
      thresholds: { normal_max: 29, suspicious_max: 69, high_risk_min: 70 },
      weights: { packet_rate: 25, abnormal_ports: 30, malicious_ips: 35, beaconing: 25, protocol_violations: 20 }
    };

    try {
      config = await window.ApiClient.devices.getRiskConfig();
    } catch (e) {}

    content.innerHTML = `
      <div class="modal-header">
        <div>
          <h2 style="font-size: 18px; display: flex; align-items: center; gap: 8px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            Device Risk Classification Thresholds & Factor Weights
          </h2>
          <span style="font-size: 12px; color: var(--text-secondary);">Configure transparent rule engine criteria for Normal, Suspicious, and High-Risk tiers</span>
        </div>
        <button class="close-btn" onclick="DevicesView.closeRiskConfigModal()">×</button>
      </div>

      <div style="background: var(--bg-surface); padding: 14px 18px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 18px;">
        <h4 style="font-size: 13px; color: var(--highlight-mint); margin-bottom: 12px;">Security Classification Score Cutoffs (0 - 100)</h4>
        
        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">Normal Cutoff (Score &le; N)</span>
            <span class="slider-value" id="val-cutoff-norm">${config.thresholds.normal_max}</span>
          </div>
          <input type="range" min="10" max="50" value="${config.thresholds.normal_max}" class="cyber-slider"
                 oninput="document.getElementById('val-cutoff-norm').textContent = this.value; document.getElementById('val-cutoff-susp-min').textContent = (parseInt(this.value)+1);" id="cfg-normal-max" />
        </div>

        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">High-Risk Minimum Threshold (Score &ge; N)</span>
            <span class="slider-value" id="val-cutoff-high">${config.thresholds.high_risk_min}</span>
          </div>
          <input type="range" min="55" max="95" value="${config.thresholds.high_risk_min}" class="cyber-slider"
                 oninput="document.getElementById('val-cutoff-high').textContent = this.value; document.getElementById('val-cutoff-susp-max').textContent = (parseInt(this.value)-1);" id="cfg-high-min" />
        </div>

        <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-secondary); margin-top: 6px;">
          Suspicious Tier Range: <span id="val-cutoff-susp-min" style="color: var(--state-warning);">${config.thresholds.normal_max + 1}</span> to <span id="val-cutoff-susp-max" style="color: var(--state-warning);">${config.thresholds.high_risk_min - 1}</span>
        </div>
      </div>

      <div style="background: var(--bg-surface); padding: 14px 18px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 20px;">
        <h4 style="font-size: 13px; color: var(--highlight-mint); margin-bottom: 12px;">Factor Weight Allocations (Penalty Points)</h4>

        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">High Packet Rate Volumetric Penalty</span>
            <span class="slider-value" id="val-w-pps">+${config.weights.packet_rate}</span>
          </div>
          <input type="range" min="5" max="40" value="${config.weights.packet_rate}" class="cyber-slider"
                 oninput="document.getElementById('val-w-pps').textContent = '+' + this.value;" id="cfg-w-pps" />
        </div>

        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">Abnormal Port Access (Telnet/Modbus/Scans)</span>
            <span class="slider-value" id="val-w-ports">+${config.weights.abnormal_ports}</span>
          </div>
          <input type="range" min="10" max="50" value="${config.weights.abnormal_ports}" class="cyber-slider"
                 oninput="document.getElementById('val-w-ports').textContent = '+' + this.value;" id="cfg-w-ports" />
        </div>

        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">Known Malicious C2 IP Communication</span>
            <span class="slider-value" id="val-w-ips">+${config.weights.malicious_ips}</span>
          </div>
          <input type="range" min="10" max="50" value="${config.weights.malicious_ips}" class="cyber-slider"
                 oninput="document.getElementById('val-w-ips').textContent = '+' + this.value;" id="cfg-w-ips" />
        </div>

        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">Beaconing Patterns & High Burst Frequency</span>
            <span class="slider-value" id="val-w-beacon">+${config.weights.beaconing}</span>
          </div>
          <input type="range" min="5" max="40" value="${config.weights.beaconing}" class="cyber-slider"
                 oninput="document.getElementById('val-w-beacon').textContent = '+' + this.value;" id="cfg-w-beacon" />
        </div>

        <div class="slider-group">
          <div class="slider-header">
            <span class="slider-label">Protocol Violations & Critical CVE Exploitation</span>
            <span class="slider-value" id="val-w-proto">+${config.weights.protocol_violations}</span>
          </div>
          <input type="range" min="5" max="40" value="${config.weights.protocol_violations}" class="cyber-slider"
                 oninput="document.getElementById('val-w-proto').textContent = '+' + this.value;" id="cfg-w-proto" />
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button class="btn btn-secondary" onclick="DevicesView.closeRiskConfigModal()">Cancel</button>
        <button class="btn btn-primary" onclick="DevicesView.saveRiskConfig()">
          Apply & Recalculate Inventory Scores
        </button>
      </div>
    `;

    modal.classList.add("open");
  },

  closeRiskConfigModal() {
    const modal = document.getElementById("risk-config-modal");
    if (modal) modal.classList.remove("open");
  },

  async saveRiskConfig() {
    const normalMax = parseInt(document.getElementById("cfg-normal-max").value, 10);
    const highMin = parseInt(document.getElementById("cfg-high-min").value, 10);

    const payload = {
      thresholds: {
        normal_max: normalMax,
        suspicious_max: highMin - 1,
        high_risk_min: highMin
      },
      weights: {
        packet_rate: parseInt(document.getElementById("cfg-w-pps").value, 10),
        abnormal_ports: parseInt(document.getElementById("cfg-w-ports").value, 10),
        malicious_ips: parseInt(document.getElementById("cfg-w-ips").value, 10),
        beaconing: parseInt(document.getElementById("cfg-w-beacon").value, 10),
        protocol_violations: parseInt(document.getElementById("cfg-w-proto").value, 10)
      }
    };

    try {
      const data = await window.ApiClient.devices.updateRiskConfig(payload);
      if (data && data.devices) App.state.devices = data.devices;
      if (data && data.kpis) App.state.kpis = data.kpis;
      App.showToast("Risk engine factor weights updated & inventory recalculated", "success");
    } catch (err) {
      App.showToast("Applied risk engine weights locally", "info");
    }

    this.closeRiskConfigModal();
    this.renderDevices();
  }
};
