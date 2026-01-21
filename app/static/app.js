const stateStatus = document.getElementById("stateStatus");
const hostList = document.getElementById("hostList");
const hostTableBody = document.getElementById("hostTableBody");
const projectList = document.getElementById("projectList");
const hostRowTemplate = document.getElementById("hostRowTemplate");
const hostTableRowTemplate = document.getElementById("hostTableRowTemplate");
const projectRowTemplate = document.getElementById("projectRowTemplate");
const projectSelectToggle = document.getElementById("projectSelectToggle");
const projectCount = document.getElementById("projectCount");
const headerFilterHosts = document.getElementById("headerFilterHosts");
const headerFilterStatus = document.getElementById("headerFilterStatus");
const headerFilterUpdates = document.getElementById("headerFilterUpdates");
const filterToggleButtons = document.querySelectorAll(".filter-toggle");
const filterMenus = document.querySelectorAll(".filter-menu");
const projectSortHeaders = document.querySelectorAll(".project-table .sort-header");
const projectFilterName = document.getElementById("projectFilterName");
const clearProjectFiltersBtn = document.getElementById("clearProjectFilters");
const projectFilterCount = document.getElementById("projectFilterCount");
const bulkActions = document.getElementById("bulkActions");
const bulkActionsWrap = document.getElementById("bulkActionsWrap");
const bulkProgress = document.getElementById("bulkProgress");
const bulkProgressText = document.getElementById("bulkProgressText");
const bulkProgressBar = document.getElementById("bulkProgressBar");
const composeModal = document.getElementById("composeModal");
const composeTarget = document.getElementById("composeTarget");
const composePath = document.getElementById("composePath");
const composeEditor = document.getElementById("composeEditor");
const composeStatus = document.getElementById("composeStatus");
const composeLint = document.getElementById("composeLint");
const composeSearchBar = document.getElementById("composeSearchBar");
const composeSearchInput = document.getElementById("composeSearchInput");
const composeReplaceInput = document.getElementById("composeReplaceInput");
const composeFindNextBtn = document.getElementById("composeFindNext");
const composeReplaceBtn = document.getElementById("composeReplace");
const composeReplaceAllBtn = document.getElementById("composeReplaceAll");
const composeSearchCloseBtn = document.getElementById("composeSearchClose");
const commandModal = document.getElementById("commandModal");
const closeCommandModalBtn = document.getElementById("closeCommandModal");
const commandTarget = document.getElementById("commandTarget");
const commandInput = document.getElementById("commandInput");
const commandStatus = document.getElementById("commandStatus");
const commandOutput = document.getElementById("commandOutput");
const runCommandBtn = document.getElementById("runCommand");
const previewComposeBtn = document.getElementById("previewCompose");
const confirmComposeBtn = document.getElementById("confirmCompose");
const closeComposeModalBtn = document.getElementById("closeComposeModal");
const diffPanel = document.getElementById("diffPanel");
const diffView = document.getElementById("diffView");
const logsModal = document.getElementById("logsModal");
const logsTarget = document.getElementById("logsTarget");
const logsContent = document.getElementById("logsContent");
const closeLogsModalBtn = document.getElementById("closeLogsModal");
const logsServiceInput = document.getElementById("logsService");
const logsTailInput = document.getElementById("logsTail");
const refreshLogsBtn = document.getElementById("refreshLogs");
const toggleFollowBtn = document.getElementById("toggleFollow");
const logsShowStdout = document.getElementById("logsShowStdout");
const logsShowStderr = document.getElementById("logsShowStderr");
const projectDetailsModal = document.getElementById("projectDetailsModal");
const closeProjectDetailsModalBtn = document.getElementById("closeProjectDetailsModal");
const projectDetailsTitle = document.getElementById("projectDetailsTitle");
const projectDetailsHost = document.getElementById("projectDetailsHost");
const projectDetailsPath = document.getElementById("projectDetailsPath");
const projectDetailsBackup = document.getElementById("projectDetailsBackup");
const projectDetailsBackupSuccess = document.getElementById("projectDetailsBackupSuccess");
const projectDetailsStatus = document.getElementById("projectDetailsStatus");
const projectDetailsStatsBody = document.getElementById("projectDetailsStatsBody");
const projectDetailsPortsBody = document.getElementById("projectDetailsPortsBody");
const shellModal = document.getElementById("shellModal");
const closeShellModalBtn = document.getElementById("closeShellModal");
const shellTarget = document.getElementById("shellTarget");
const shellStatus = document.getElementById("shellStatus");
const shellTerminal = document.getElementById("shellTerminal");
const openBackupScheduleBtn = document.getElementById("openBackupSchedule");
const backupScheduleModal = document.getElementById("backupScheduleModal");
const closeBackupScheduleModalBtn = document.getElementById("closeBackupScheduleModal");
const openRestoreModalBtn = document.getElementById("openRestoreModal");
const restoreModal = document.getElementById("restoreModal");
const closeRestoreModalBtn = document.getElementById("closeRestoreModal");
const restoreBackupTarget = document.getElementById("restoreBackupTarget");
const restoreHostSelect = document.getElementById("restoreHost");
const restoreProjectSelect = document.getElementById("restoreProject");
const restoreStatus = document.getElementById("restoreStatus");
const runRestoreBtn = document.getElementById("runRestore");
const openCreateProjectBtn = document.getElementById("openCreateProject");
const createProjectModal = document.getElementById("createProjectModal");
const closeCreateProjectModalBtn = document.getElementById("closeCreateProjectModal");
const createProjectHost = document.getElementById("createProjectHost");
const createProjectName = document.getElementById("createProjectName");
const createProjectBackup = document.getElementById("createProjectBackup");
const createProjectRun = document.getElementById("createProjectRun");
const createProjectCompose = document.getElementById("createProjectCompose");
const createSearchBar = document.getElementById("createSearchBar");
const createSearchInput = document.getElementById("createSearchInput");
const createReplaceInput = document.getElementById("createReplaceInput");
const createFindNextBtn = document.getElementById("createFindNext");
const createReplaceBtn = document.getElementById("createReplace");
const createReplaceAllBtn = document.getElementById("createReplaceAll");
const createSearchCloseBtn = document.getElementById("createSearchClose");
const createProjectStatus = document.getElementById("createProjectStatus");
const createProjectProgressText = document.getElementById("createProjectProgressText");
const createProjectProgressBar = document.getElementById("createProjectProgressBar");
const createProjectSubmit = document.getElementById("createProjectSubmit");
const convertRunToComposeBtn = document.getElementById("convertRunToCompose");
const deleteProjectModal = document.getElementById("deleteProjectModal");
const closeDeleteProjectModalBtn = document.getElementById("closeDeleteProjectModal");
const deleteProjectTarget = document.getElementById("deleteProjectTarget");
const deleteProjectStatus = document.getElementById("deleteProjectStatus");
const deleteProjectBackup = document.getElementById("deleteProjectBackup");
const deleteProjectBackupToggle = document.getElementById("deleteProjectBackupToggle");
const confirmDeleteProjectBtn = document.getElementById("confirmDeleteProject");
const authModal = document.getElementById("authModal");
const authUsername = document.getElementById("authUsername");
const authPassword = document.getElementById("authPassword");
const authSubmit = document.getElementById("authSubmit");
const authStatus = document.getElementById("authStatus");
const currentUserBadge = document.getElementById("currentUserBadge");
const currentUserLabel = document.getElementById("currentUserName");
const userMenu = document.getElementById("userMenu");
const userCurrentPassword = document.getElementById("userCurrentPassword");
const userNewPassword = document.getElementById("userNewPassword");
const userChangePasswordBtn = document.getElementById("userChangePassword");
const userMenuStatus = document.getElementById("userMenuStatus");
const logoutBtn = document.getElementById("userLogout");
const openConfigBtn = document.getElementById("openConfig");
const openEventStatusBtn = document.getElementById("openEventStatus");
const eventStatusModal = document.getElementById("eventStatusModal");
const closeEventStatusModalBtn = document.getElementById("closeEventStatusModal");
const refreshEventStatusBtn = document.getElementById("refreshEventStatus");
const toggleEventAutoBtn = document.getElementById("toggleEventAuto");
const eventStatusList = document.getElementById("eventStatusList");
const eventStatusUpdated = document.getElementById("eventStatusUpdated");
const configModal = document.getElementById("configModal");
const closeConfigModalBtn = document.getElementById("closeConfigModal");
const hostConfigTemplate = document.getElementById("hostConfigTemplate");
const backupConfigTemplate = document.getElementById("backupConfigTemplate");
const userConfigTemplate = document.getElementById("userConfigTemplate");
const hostConfigList = document.getElementById("hostConfigList");
const backupConfigList = document.getElementById("backupConfigList");
const userConfigList = document.getElementById("userConfigList");
const configTabs = document.querySelectorAll(".config-tab");
const configTabPanels = document.querySelectorAll(".config-tab-panel");
const addHostConfigBtn = document.getElementById("addHostConfig");
const addBackupConfigBtn = document.getElementById("addBackupConfig");
const addUserConfigBtn = document.getElementById("addUserConfig");
const tokenExpiryInput = document.getElementById("tokenExpirySeconds");
const saveTokenExpiryBtn = document.getElementById("saveTokenExpiry");
const configStatus = document.getElementById("configStatus");
const toastContainer = document.getElementById("toastContainer");
const scheduleScope = document.getElementById("scheduleScope");
const scheduleScopeHint = document.getElementById("scheduleScopeHint");
const scheduleTime = document.getElementById("scheduleTime");
const daysOfWeekContainer = document.getElementById("scheduleDaysOfWeek");
const daysOfMonthSelect = document.getElementById("scheduleDaysOfMonth");
const monthsSelect = document.getElementById("scheduleMonths");
const cronExpression = document.getElementById("cronExpression");
const customCron = document.getElementById("customCron");
const saveScheduleBtn = document.getElementById("saveSchedule");
const scheduleStatus = document.getElementById("scheduleStatus");
const scheduleLast = document.getElementById("scheduleLast");
const scheduleNext = document.getElementById("scheduleNext");
const scheduleSummaryBody = document.getElementById("scheduleSummaryBody");
const scheduleConfig = document.getElementById("scheduleConfig");

function applyCompactMode() {
  const params = new URLSearchParams(window.location.search);
  const compactParam = params.get("compact") || params.get("view") || params.get("mode");
  const compactValue = (compactParam || "").toLowerCase();
  const isCompact = ["1", "true", "yes", "compact"].includes(compactValue);
  if (document.body) {
    document.body.classList.toggle("compact-mode", isCompact);
  }
}

applyCompactMode();

function handleFindShortcut(event) {
  if (event.defaultPrevented) {
    return;
  }
  if (!projectFilterName) {
    return;
  }
  if (event.key.toLowerCase() !== "f") {
    return;
  }
  if (!(event.ctrlKey || event.metaKey) || event.altKey) {
    return;
  }
  if (document.activeElement === projectFilterName) {
    return;
  }
  if (
    (composeModal && !composeModal.classList.contains("hidden")) ||
    (createProjectModal && !createProjectModal.classList.contains("hidden"))
  ) {
    return;
  }
  event.preventDefault();
  projectFilterName.focus();
  projectFilterName.select();
}

function handleComposeSearchShortcut(event) {
  if (event.defaultPrevented) {
    return;
  }
  if (!(event.ctrlKey || event.metaKey) || event.altKey) {
    return;
  }
  const key = event.key.toLowerCase();
  if (key !== "f" && key !== "h") {
    return;
  }
  const composeOpen = composeModal && !composeModal.classList.contains("hidden");
  const createOpen = createProjectModal && !createProjectModal.classList.contains("hidden");
  if (!composeOpen && !createOpen) {
    return;
  }
  const context = composeOpen ? getComposeSearchContext() : getCreateSearchContext();
  if (!context || !context.bar) {
    return;
  }
  if (document.activeElement === context.searchInput || document.activeElement === context.replaceInput) {
    return;
  }
  event.preventDefault();
  openSearchBar(context, key === "h" ? "replace" : "find");
}

function setHardRestartActive(active) {
  if (!document.body) {
    return;
  }
  document.body.classList.toggle("hard-restart-active", active);
  if (!active) {
    state.shiftStartLocks.clear();
  }
  updateBulkRestartLabel(active);
  updateShiftStartButtons();
}

function handleHardRestartModifier(event) {
  if (event.key !== "Shift") {
    return;
  }
  setHardRestartActive(event.type === "keydown");
}

function updateBulkRestartLabel(active) {
  const button = document.querySelector('.bulk-action[data-bulk-action="restart"]');
  if (!button) {
    return;
  }
  const baseLabel = button.dataset.baseLabel || "Restart";
  if (!button.dataset.baseLabel) {
    button.dataset.baseLabel = baseLabel;
  }
  const label = active ? "Hard Restart" : baseLabel;
  button.title = label;
  button.setAttribute("aria-label", label);
}

function updateActionTooltip(button, value) {
  if (!button) {
    return;
  }
  if (!button.dataset.baseTooltip) {
    button.dataset.baseTooltip =
      button.getAttribute("title") || button.getAttribute("aria-label") || "";
  }
  const tooltip = value || button.dataset.baseTooltip;
  if (!tooltip) {
    return;
  }
  button.setAttribute("title", tooltip);
  button.setAttribute("aria-label", tooltip);
}

function updateShiftStartButtons() {
  if (!projectList) {
    return;
  }
  const shiftActive = document.body?.classList.contains("hard-restart-active");
  const updateShiftActive = shiftActive && state.updatesEnabled;
  projectList.querySelectorAll(".project-row").forEach((row) => {
    if (row.dataset.allowProjectActions !== "true") {
      return;
    }
    const projectRunning = row.dataset.projectRunning === "true";
    const projectKey = row.dataset.projectKey || "";
    const shiftOverride = Boolean(
      shiftActive && projectRunning && !state.shiftStartLocks.has(projectKey)
    );
    const startBtn = row.querySelector('.project-action[data-action="start"]');
    const stopBtn = row.querySelector('.project-action[data-action="stop"]');
    if (!startBtn || !stopBtn) {
      return;
    }
    const startRunning = startBtn.dataset.actionRunning === "true";
    const stopRunning = stopBtn.dataset.actionRunning === "true";
    let showStart = startRunning || !projectRunning;
    let showStop = stopRunning || projectRunning;
    if (shiftOverride && !stopRunning) {
      showStart = true;
      showStop = false;
    }
    if (!startBtn.classList.contains("role-hidden")) {
      startBtn.classList.toggle("hidden", !showStart);
    }
    if (!stopBtn.classList.contains("role-hidden")) {
      stopBtn.classList.toggle("hidden", !showStop);
    }
    startBtn.classList.toggle("shift-start", shiftOverride);
    updateActionTooltip(
      startBtn,
      shiftOverride ? "Start project again" : null
    );
    const restartBtn = row.querySelector('.project-action[data-action="restart"]');
    const updateBtn = row.querySelector('.project-action[data-action="update"]');
    if (updateBtn) {
      updateBtn.classList.toggle("shift-update", updateShiftActive);
    }
    updateActionTooltip(
      restartBtn,
      shiftActive ? "Hard restart project" : null
    );
    updateActionTooltip(
      updateBtn,
      updateShiftActive ? "Check updates (no image updates applied)" : null
    );
    row
      .querySelectorAll('.service-action[data-action="restart"]')
      .forEach((button) => {
        updateActionTooltip(
          button,
          shiftActive ? "Hard restart service" : null
        );
      });
  });
}

const ROLE_ADMIN = "admin";
const ROLE_POWER = "power";
const ROLE_NORMAL = "normal";

const state = {
  hosts: [],
  stateSnapshot: null,
  stateIntervalSeconds: null,
  backupScheduleAvailable: true,
  updatesEnabled: true,
  backupTargetsAvailable: true,
  authToken: null,
  authUser: "",
  userRole: "normal",
  initialized: false,
  configTabsInit: false,
  selectedProjects: new Set(),
  shiftStartLocks: new Set(),
  backupCancelled: new Set(),
  actionProgress: new Map(),
  hostActionProgress: new Map(),
  serviceActionProgress: new Map(),
  authExpiredNotified: false,
  actionMenuListenerBound: false,
  restoreInProgress: false,
  restoreCancelRequested: false,
  restoreLockedProjects: new Set(),
  projectFilters: {
    hosts: [],
    sortBy: "name",
    sortDir: "asc",
    status: "all",
    updates: "all",
    query: "",
  },
  filterMenuListenerBound: false,
};

const composeState = {
  hostId: null,
  projectName: null,
};

const composeSearchState = {
  query: "",
  lastMatch: null,
};

const createSearchState = {
  query: "",
  lastMatch: null,
};

let composeEditorCm = null;

let composeDiffView = null;
let createComposeEditor = null;

const commandState = {
  hostId: null,
  projectName: null,
};

const logsState = {
  hostId: null,
  projectName: null,
  stream: null,
};

const shellState = {
  hostId: null,
  projectName: null,
  serviceName: null,
  socket: null,
  term: null,
  fitAddon: null,
};

const projectDetailsState = {
  key: null,
};

const scheduleState = {
  initialized: false,
  lastLoadFailed: false,
  summary: [],
  selectedKey: "global",
};

const eventStatusState = {
  items: [],
  updatedAt: null,
  timerId: null,
  autoRefreshId: null,
  autoRefreshEnabled: true,
  loading: false,
};

const EVENT_INTERVAL_CONFIG = {
  status_refresh: { label: "Interval (s)", endpoint: "/state/interval" },
  update_refresh: { label: "Interval (s)", endpoint: "/update/interval" },
  token_cleanup: { label: "Interval (s)", endpoint: "/config/token-cleanup-interval" },
  fd_track: { label: "Interval (s)", endpoint: "/config/fd-track-interval" },
};

const EVENT_STATUS_REFRESH_MS = 30000;

const deleteProjectState = {
  hostId: null,
  projectName: null,
};

const DEFAULT_CREATE_COMPOSE = `services:\n  app:\n    image: nginx:latest\n    ports:\n      - \"8080:80\"\n`;
const AUTH_COOKIE_NAME = "rpm_token";


function normalizeErrorDetail(detail) {
  if (detail === null || detail === undefined) {
    return "";
  }
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((entry) => {
        if (entry && typeof entry === "object") {
          return entry.msg || entry.message || "";
        }
        return String(entry);
      })
      .filter(Boolean);
    return messages.join(" ");
  }
  if (typeof detail === "object") {
    if (detail.message) {
      return String(detail.message);
    }
    if (detail.detail) {
      return normalizeErrorDetail(detail.detail);
    }
    return "";
  }
  return String(detail);
}

function parseErrorMessage(text, fallback) {
  if (!text) {
    return fallback || "Request failed.";
  }
  try {
    const payload = JSON.parse(text);
    if (typeof payload === "string") {
      return payload;
    }
    if (payload && typeof payload === "object") {
      const detail = normalizeErrorDetail(payload.detail);
      if (detail) {
        return detail;
      }
      const message = normalizeErrorDetail(payload.message || payload.error);
      if (message) {
        return message;
      }
      return fallback || "Request failed.";
    }
  } catch (err) {
    return text;
  }
  return text || fallback || "Request failed.";
}

async function handleUnauthorized(response) {
  const text = await response.text();
  const message = parseErrorMessage(text, "Unauthorized.");
  clearAuthToken();
  showAuthModal(message);
  throw new Error(message);
}

async function apiRequest(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const authHeader = getAuthHeader();
  if (authHeader) {
    headers.Authorization = authHeader;
  }
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    await handleUnauthorized(response);
  }
  if (!response.ok) {
    const text = await response.text();
    const message = parseErrorMessage(text, response.statusText);
    throw new Error(message);
  }
  return response;
}

const api = {
  async get(path) {
    const res = await apiRequest(path);
    return res.json();
  },
  async post(path, body) {
    const options = { method: "POST" };
    if (body !== undefined) {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(body);
    }
    const res = await apiRequest(path, options);
    return res.json();
  },
  async put(path, body) {
    const res = await apiRequest(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return res.json();
  },
  async delete(path) {
    const res = await apiRequest(path, { method: "DELETE" });
    return res.json();
  },
};

function parseEventChunk(chunk) {
  const lines = chunk.split("\n");
  let eventName = "message";
  const dataLines = [];
  lines.forEach((line) => {
    if (line.startsWith("event:")) {
      eventName = line.slice(6).trim() || "message";
    } else if (line.startsWith("data:")) {
      const value = line.startsWith("data: ") ? line.slice(6) : line.slice(5);
      dataLines.push(value);
    }
  });
  return { event: eventName, data: dataLines.join("\n") };
}

function createEventStream(url, handlers) {
  const controller = new AbortController();
  const headers = {};
  const authHeader = getAuthHeader();
  if (authHeader) {
    headers.Authorization = authHeader;
  }
  const done = fetch(url, { headers, signal: controller.signal })
    .then(async (response) => {
      if (response.status === 401) {
        await handleUnauthorized(response);
      }
      if (!response.ok) {
        const text = await response.text();
        throw new Error(parseErrorMessage(text, response.statusText));
      }
      if (!response.body) {
        throw new Error("Stream unavailable.");
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done: streamDone } = await reader.read();
        if (streamDone) {
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        buffer = buffer.replace(/\r/g, "");
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";
        parts.forEach((part) => {
          if (!part.trim()) {
            return;
          }
          const parsed = parseEventChunk(part);
          if (handlers && handlers.onEvent) {
            handlers.onEvent(parsed.event, parsed.data);
          }
        });
      }
      if (buffer.trim()) {
        const parsed = parseEventChunk(buffer);
        if (handlers && handlers.onEvent) {
          handlers.onEvent(parsed.event, parsed.data);
        }
      }
    })
    .catch((err) => {
      if (controller.signal.aborted) {
        return;
      }
      if (handlers && handlers.onError) {
        handlers.onError(err);
      }
    });
  return {
    close() {
      controller.abort();
    },
    done,
  };
}

function formatTimestamp(value) {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  return date.toLocaleString();
}

function formatInterval(value) {
  if (value === null || value === undefined) return "unknown";
  if (value <= 0) return "disabled";
  return `${value}s`;
}

function updateStateStatus() {
  const interval = formatInterval(state.stateIntervalSeconds);
  if (!stateStatus) {
    return;
  }
  stateStatus.textContent = `State interval: ${interval}`;
}

function updateIntervalVisibility() {
  return;
}

async function saveEventInterval(eventId, input, button) {
  const config = EVENT_INTERVAL_CONFIG[eventId];
  if (!config) {
    return;
  }
  const rawValue = input ? input.value : "";
  const seconds = Number.parseInt(rawValue, 10);
  if (Number.isNaN(seconds) || seconds < 0) {
    setConfigStatus("Interval must be 0 or greater.", "error");
    return;
  }
  if (button) {
    button.disabled = true;
  }
  setConfigStatus("Saving settings...");
  try {
    await api.put(config.endpoint, { seconds });
    if (eventId === "status_refresh") {
      state.stateIntervalSeconds = seconds;
      updateStateStatus();
    }
    setConfigStatus("Settings saved.", "success");
    await loadEventStatus();
  } catch (err) {
    setConfigStatus(`Failed to save settings: ${err.message}`, "error");
  } finally {
    if (button) {
      button.disabled = false;
    }
  }
}

function updateProjectFilterState() {
  if (headerFilterHosts) {
    state.projectFilters.hosts = Array.from(headerFilterHosts.selectedOptions).map(
      (option) => option.value
    );
  }
  if (headerFilterStatus) {
    state.projectFilters.status = headerFilterStatus.value;
  }
  if (headerFilterUpdates) {
    state.projectFilters.updates = headerFilterUpdates.value;
  }
  if (projectFilterName) {
    state.projectFilters.query = projectFilterName.value || "";
  }
}

function updateProjectFilterIndicators() {
  const hostActive = headerFilterHosts && headerFilterHosts.selectedOptions.length > 0;
  const statusActive = headerFilterStatus && headerFilterStatus.value !== "all";
  const updatesActive = headerFilterUpdates && headerFilterUpdates.value !== "all";
  const queryActive = Boolean(projectFilterName && projectFilterName.value.trim());

  if (headerFilterHosts) {
    const toggle = document.querySelector('.filter-toggle[data-filter="hosts"]');
    if (toggle) {
      toggle.classList.toggle('active', hostActive);
    }
  }
  if (headerFilterStatus) {
    const toggle = document.querySelector('.filter-toggle[data-filter="status"]');
    if (toggle) {
      toggle.classList.toggle('active', statusActive);
    }
  }
  if (headerFilterUpdates) {
    const toggle = document.querySelector('.filter-toggle[data-filter="updates"]');
    if (toggle) {
      toggle.classList.toggle('active', updatesActive);
    }
  }
  const activeCount = [hostActive, statusActive, updatesActive, queryActive].filter(Boolean).length;
  if (projectFilterCount) {
    projectFilterCount.textContent = String(activeCount);
    projectFilterCount.classList.toggle('hidden', activeCount === 0);
  }
}


function renderHostFilterOptions() {
  if (!headerFilterHosts) {
    return;
  }
  const available = new Set(state.hosts.map((host) => host.host_id));
  state.projectFilters.hosts = state.projectFilters.hosts.filter((hostId) =>
    available.has(hostId)
  );
  const selected = new Set(state.projectFilters.hosts);
  headerFilterHosts.innerHTML = "";
  state.hosts.forEach((host) => {
    const option = document.createElement("option");
    option.value = host.host_id;
    option.textContent = host.host_id;
    option.selected = selected.has(host.host_id);
    headerFilterHosts.appendChild(option);
  });
}


function updateProjectSortIndicators() {
  projectSortHeaders.forEach((header) => {
    const indicator = header.querySelector(".sort-indicator");
    if (!indicator) {
      return;
    }
    const sortKey = header.dataset.sort;
    if (sortKey === state.projectFilters.sortBy) {
      header.classList.add("active");
      indicator.textContent =
        state.projectFilters.sortDir === "desc" ? "arrow_downward" : "arrow_upward";
    } else {
      header.classList.remove("active");
      indicator.textContent = "";
    }
  });
}

function createBadge(label, className) {
  const badge = document.createElement("span");
  badge.className = `badge ${className}`;
  badge.textContent = label;
  return badge;
}

function projectStatusLabel(status) {
  if (!status) return { label: "unknown", className: "" };
  return { label: status, className: status };
}

function updateBadgeLabel(updatesAvailable) {
  if (updatesAvailable === null || updatesAvailable === undefined) {
    return { label: "updates: n/a", className: "" };
  }
  if (updatesAvailable) {
    return { label: "updates: yes", className: "updates-yes" };
  }
  return { label: "updates: no", className: "updates-no" };
}

function backupBadgeInfo(entry) {
  if (!entry.lastBackupAt) {
    return { label: "Last Backup: never", className: "" };
  }
  const timestamp = formatTimestamp(entry.lastBackupAt);
  if (entry.lastBackupSuccess === false) {
    return { label: `Last Backup failed: ${timestamp}`, className: "backup-fail" };
  }
  return { label: `Last Backup: ${timestamp}`, className: "backup-ok" };
}

function pad(value) {
  return value.toString().padStart(2, "0");
}

function showToast(message, variant = "success") {
  if (!toastContainer) {
    return;
  }
  const toast = document.createElement("div");
  toast.className = `toast ${variant}`;
  toast.textContent = message;
  toastContainer.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.add("visible");
  });
  window.setTimeout(() => {
    toast.classList.add("closing");
    window.setTimeout(() => {
      toast.remove();
    }, 250);
  }, 3000);
}

function getCookieValue(name) {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

function setCookieValue(name, value, expiresAt) {
  let cookie = `${name}=${encodeURIComponent(value)}; path=/`;
  if (expiresAt instanceof Date && !Number.isNaN(expiresAt.getTime())) {
    cookie += `; expires=${expiresAt.toUTCString()}`;
  }
  document.cookie = cookie;
}

function clearCookieValue(name) {
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
}

function updateAuthDisplay() {
  if (!currentUserLabel) {
    return;
  }
  const name = state.authUser || "--";
  currentUserLabel.textContent = name;
}

function setUserMenuStatus(message, isError = false) {
  if (!userMenuStatus) {
    return;
  }
  userMenuStatus.textContent = message || "";
  userMenuStatus.classList.toggle("error", Boolean(isError));
}

function openUserMenu() {
  if (!userMenu) {
    return;
  }
  userMenu.classList.remove("hidden");
  if (currentUserBadge) {
    currentUserBadge.setAttribute("aria-expanded", "true");
  }
}

function closeUserMenu() {
  if (!userMenu) {
    return;
  }
  userMenu.classList.add("hidden");
  if (currentUserBadge) {
    currentUserBadge.setAttribute("aria-expanded", "false");
  }
  setUserMenuStatus("");
}

function toggleUserMenu() {
  if (!userMenu) {
    return;
  }
  const willOpen = userMenu.classList.contains("hidden");
  if (willOpen) {
    openUserMenu();
  } else {
    closeUserMenu();
  }
}

async function submitPasswordChange() {
  if (!userCurrentPassword || !userNewPassword) {
    return;
  }
  const currentPassword = userCurrentPassword.value;
  const newPassword = userNewPassword.value;
  if (!currentPassword || !newPassword) {
    setUserMenuStatus("Enter current and new password.", true);
    return;
  }
  setUserMenuStatus("Updating password...");
  try {
    await api.post("/auth/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
    userCurrentPassword.value = "";
    userNewPassword.value = "";
    setUserMenuStatus("Password updated.");
  } catch (err) {
    setUserMenuStatus(`Password update failed: ${err.message}`, true);
  }
}

function resolveRoleFromPayload(payload) {
  const role = String(payload?.role || "").toLowerCase();
  if (role === ROLE_ADMIN || role === ROLE_POWER || role === ROLE_NORMAL) {
    return role;
  }
  const username = String(payload?.username || "").toLowerCase();
  if (username === "admin") {
    return ROLE_ADMIN;
  }
  return ROLE_NORMAL;
}

function isAdminRole() {
  return state.userRole === ROLE_ADMIN;
}

function isPowerRole() {
  return state.userRole === ROLE_ADMIN || state.userRole === ROLE_POWER;
}

function canManageProjects() {
  return isPowerRole();
}

function canEditCompose() {
  return isAdminRole();
}

function canDeleteProject() {
  return isAdminRole();
}

function canAccessConfig() {
  return isAdminRole();
}

function canAccessEvents() {
  return isAdminRole();
}

function canAccessBackupSchedule() {
  return isAdminRole();
}

function canRestoreProjects() {
  return isAdminRole();
}

function setButtonAccess(button, allowed, message, options = {}) {
  if (!button) {
    return;
  }
  const hideOnDeny = options.hideOnDeny === true;
  if (!button.dataset.defaultTitle) {
    button.dataset.defaultTitle = button.title || "";
  }
  if (!hideOnDeny && button.dataset.roleHidden === "true") {
    button.classList.remove("role-hidden");
    button.dataset.roleHidden = "";
  }
  if (hideOnDeny) {
    if (!allowed) {
      button.classList.add("role-hidden");
      button.dataset.roleHidden = "true";
    } else if (button.dataset.roleHidden === "true") {
      button.classList.remove("role-hidden");
      button.dataset.roleHidden = "";
    }
  }
  if (allowed) {
    button.disabled = false;
    button.dataset.forceDisabled = "";
    button.title = button.dataset.defaultTitle || button.title;
  } else {
    button.disabled = true;
    button.dataset.forceDisabled = "true";
    if (message) {
      button.title = message;
    }
  }
}

function updateBulkActionPermissions() {
  if (!bulkActions || !bulkActionsWrap) {
    return;
  }
  const allowed = canManageProjects();
  const buttons = bulkActions.querySelectorAll(".bulk-action");
  buttons.forEach((button) => {
    const action = button.dataset.bulkAction;
    if (!allowed) {
      setButtonAccess(button, false, "Requires admin or power user.", {
        hideOnDeny: true,
      });
      return;
    }
    if (action === "backup" && !isAdminRole()) {
      setButtonAccess(button, false, "Admin access required.", {
        hideOnDeny: true,
      });
      return;
    }
    if (action === "backup" && !state.backupTargetsAvailable) {
      setButtonAccess(button, false, "No enabled backup targets.");
      return;
    }
    setButtonAccess(button, true);
  });
}

function updateRolePermissions() {
  const adminAllowed = canAccessConfig();
  setButtonAccess(openConfigBtn, adminAllowed, "Admin access required.", {
    hideOnDeny: true,
  });
  setButtonAccess(openEventStatusBtn, canAccessEvents(), "Admin access required.", {
    hideOnDeny: true,
  });
  setButtonAccess(
    openBackupScheduleBtn,
    canAccessBackupSchedule(),
    "Admin access required.",
    { hideOnDeny: true }
  );
  setButtonAccess(openCreateProjectBtn, adminAllowed, "Admin access required.", {
    hideOnDeny: true,
  });
  setButtonAccess(openRestoreModalBtn, canRestoreProjects(), "Admin access required.", {
    hideOnDeny: true,
  });
  updateBulkActionPermissions();
  if (state.initialized) {
    renderLists();
  }
}

function decodeToken(token) {
  if (!token) {
    return null;
  }
  const padding = "=".repeat((4 - (token.length % 4)) % 4);
  try {
    const raw = atob(`${token}${padding}`);
    return JSON.parse(raw);
  } catch (err) {
    return null;
  }
}

function tokenExpired(payload) {
  if (!payload || !payload.expiration) {
    return true;
  }
  const expiration = new Date(payload.expiration);
  if (Number.isNaN(expiration.getTime())) {
    return true;
  }
  return expiration.getTime() <= Date.now();
}

let authExpiryTimeout = null;

function clearAuthExpiryTimeout() {
  if (authExpiryTimeout) {
    window.clearTimeout(authExpiryTimeout);
    authExpiryTimeout = null;
  }
}

function scheduleAuthExpiry(payload) {
  clearAuthExpiryTimeout();
  if (!payload || !payload.expiration) {
    return;
  }
  const expiresAt = new Date(payload.expiration).getTime();
  if (Number.isNaN(expiresAt)) {
    return;
  }
  const delay = Math.max(0, expiresAt - Date.now());
  if (delay === 0) {
    handleAuthExpired();
    return;
  }
  authExpiryTimeout = window.setTimeout(() => {
    handleAuthExpired();
  }, delay);
}

function handleAuthExpired() {
  if (state.authExpiredNotified) {
    clearAuthToken();
    return;
  }
  state.authExpiredNotified = true;
  clearAuthToken();
  showAuthModal("Session expired. Please sign in.");
}

function setAuthToken(token) {
  const payload = decodeToken(token);
  if (!payload || tokenExpired(payload)) {
    clearAuthToken();
    return;
  }
  state.authToken = token;
  state.authUser = payload.username || "";
  state.userRole = resolveRoleFromPayload(payload);
  state.authExpiredNotified = false;
  const expiresAt = new Date(payload.expiration);
  setCookieValue(AUTH_COOKIE_NAME, token, expiresAt);
  scheduleAuthExpiry(payload);
  updateAuthDisplay();
  updateRolePermissions();
}

function clearAuthToken() {
  closeUserMenu();
  state.authToken = null;
  state.authUser = "";
  state.userRole = ROLE_NORMAL;
  clearAuthExpiryTimeout();
  clearCookieValue(AUTH_COOKIE_NAME);
  updateAuthDisplay();
  updateRolePermissions();
}

function loadAuthFromCookie() {
  const token = getCookieValue(AUTH_COOKIE_NAME);
  if (!token) {
    return false;
  }
  const payload = decodeToken(token);
  if (!payload || tokenExpired(payload)) {
    clearAuthToken();
    return false;
  }
  state.authToken = token;
  state.authUser = payload.username || "";
  state.userRole = resolveRoleFromPayload(payload);
  state.authExpiredNotified = false;
  scheduleAuthExpiry(payload);
  updateAuthDisplay();
  updateRolePermissions();
  return true;
}

function showAuthModal(message) {
  if (!authModal) {
    return;
  }
  authModal.classList.remove("hidden");
  if (authStatus) {
    authStatus.textContent = message || "";
    authStatus.classList.remove("error", "success");
  }
  if (authPassword) {
    authPassword.value = "";
  }
  if (authUsername) {
    authUsername.focus();
  }
}

function hideAuthModal() {
  if (!authModal) {
    return;
  }
  authModal.classList.add("hidden");
  if (authStatus) {
    authStatus.textContent = "";
    authStatus.classList.remove("error", "success");
  }
}

function getAuthHeader() {
  const payload = decodeToken(state.authToken || "");
  if (!payload || tokenExpired(payload)) {
    handleAuthExpired();
    return "";
  }
  if (!state.authUser) {
    state.authUser = payload.username || "";
    updateAuthDisplay();
  }
  return `Bearer ${state.authToken}`;
}

function getTimezoneOffsetMinutes() {
  return new Date().getTimezoneOffset();
}

function normalizeTime(hour, minute, offsetMinutes) {
  let total = hour * 60 + minute + offsetMinutes;
  let dayDelta = 0;
  if (total >= 1440 || total < 0) {
    dayDelta = Math.floor(total / 1440);
  }
  total = ((total % 1440) + 1440) % 1440;
  return {
    hour: Math.floor(total / 60),
    minute: total % 60,
    dayDelta,
  };
}

function shiftDayValues(values, delta, modulo) {
  return values.map((value) => {
    const numeric = parseInt(value, 10);
    const shifted = ((numeric + delta) % modulo + modulo) % modulo;
    return shifted.toString();
  });
}

function uniqueSorted(values) {
  return Array.from(new Set(values.map((value) => parseInt(value, 10))))
    .sort((a, b) => a - b)
    .map((value) => value.toString());
}

function convertDomMonth(domValues, monthValues, hour, minute, direction) {
  if (!domValues.length) {
    return { dom: domValues, month: monthValues };
  }
  const months = monthValues.length
    ? monthValues.map((value) => parseInt(value, 10))
    : Array.from({ length: 12 }, (_, index) => index + 1);
  const domNumbers = domValues.map((value) => parseInt(value, 10));
  const domSet = new Set();
  const monthSet = new Set();
  const year = new Date().getFullYear();
  months.forEach((month) => {
    domNumbers.forEach((day) => {
      let date = null;
      if (direction === "utc_to_local") {
        date = new Date(Date.UTC(year, month - 1, day, hour, minute));
        if (date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
          return;
        }
        monthSet.add(date.getMonth() + 1);
        domSet.add(date.getDate());
      } else {
        date = new Date(year, month - 1, day, hour, minute);
        if (date.getMonth() !== month - 1 || date.getDate() !== day) {
          return;
        }
        monthSet.add(date.getUTCMonth() + 1);
        domSet.add(date.getUTCDate());
      }
    });
  });
  let dom = uniqueSorted(Array.from(domSet));
  let month = uniqueSorted(Array.from(monthSet));
  if (dom.length === 31) {
    dom = [];
  }
  if (month.length === 12) {
    month = [];
  }
  return { dom, month };
}

function convertCronParts(parts, direction) {
  const offset = getTimezoneOffsetMinutes();
  const offsetMinutes = direction === "local_to_utc" ? offset : -offset;
  const baseHour = parseInt(parts.hour, 10);
  const baseMinute = parseInt(parts.minute, 10);
  const { hour, minute, dayDelta } = normalizeTime(baseHour, baseMinute, offsetMinutes);
  let dom = parts.dom || [];
  let month = parts.month || [];
  let dow = parts.dow || [];

  if (dow.length) {
    dow = shiftDayValues(dow, dayDelta, 7);
  }
  if (dom.length) {
    const converted = convertDomMonth(dom, month, baseHour, baseMinute, direction);
    dom = converted.dom;
    month = converted.month;
  }

  return { hour, minute, dom, month, dow };
}

function populateSelect(select, start, end) {
  select.innerHTML = "";
  for (let i = start; i <= end; i += 1) {
    const option = document.createElement("option");
    option.value = i.toString();
    option.textContent = i.toString();
    select.appendChild(option);
  }
}

function getSelectedValues(select) {
  return Array.from(select.selectedOptions).map((option) => option.value);
}

function setSelectedValues(select, values) {
  const valueSet = new Set(values.map((value) => value.toString()));
  Array.from(select.options).forEach((option) => {
    option.selected = valueSet.has(option.value);
  });
}

function getSelectedDow() {
  return Array.from(daysOfWeekContainer.querySelectorAll("input"))
    .filter((input) => input.checked)
    .map((input) => input.value);
}

function setSelectedDow(values) {
  const valueSet = new Set(values.map((value) => value.toString()));
  Array.from(daysOfWeekContainer.querySelectorAll("input")).forEach((input) => {
    input.checked = valueSet.has(input.value);
  });
}

function collectCronInputs() {
  const timeValue = scheduleTime.value || "00:00";
  const [hourRaw, minuteRaw] = timeValue.split(":");
  return {
    minute: parseInt(minuteRaw, 10),
    hour: parseInt(hourRaw, 10),
    dom: getSelectedValues(daysOfMonthSelect),
    month: getSelectedValues(monthsSelect),
    dow: getSelectedDow(),
  };
}

function buildCronString(parts) {
  const dom = parts.dom.length ? parts.dom.join(",") : "*";
  const month = parts.month.length ? parts.month.join(",") : "*";
  const dow = parts.dow.length ? parts.dow.join(",") : "*";
  return `${parts.minute} ${parts.hour} ${dom} ${month} ${dow}`;
}

function buildCronFromInputs() {
  const parts = collectCronInputs();
  return buildCronString({
    minute: parts.minute.toString(),
    hour: parts.hour.toString(),
    dom: parts.dom,
    month: parts.month,
    dow: parts.dow,
  });
}

function buildCronFromInputsUtc() {
  const parts = collectCronInputs();
  const converted = convertCronParts(
    {
      minute: parts.minute.toString(),
      hour: parts.hour.toString(),
      dom: parts.dom,
      month: parts.month,
      dow: parts.dow,
    },
    "local_to_utc"
  );
  return buildCronString({
    minute: converted.minute.toString(),
    hour: converted.hour.toString(),
    dom: converted.dom,
    month: converted.month,
    dow: converted.dow,
  });
}

function convertCustomCronToUtc(expr) {
  const parsed = parseCron(expr);
  if (!parsed || !parsed.ok) {
    return expr;
  }
  const converted = convertCronParts(parsed, "local_to_utc");
  return buildCronString({
    minute: converted.minute.toString(),
    hour: converted.hour.toString(),
    dom: converted.dom,
    month: converted.month,
    dow: converted.dow,
  });
}

function parseCron(expr) {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) {
    return { ok: false };
  }
  const [minute, hour, dom, month, dow] = parts;
  const simpleField = (value) => /^(\*|\d+(,\d+)*)$/.test(value);
  if (![minute, hour, dom, month, dow].every(simpleField)) {
    return { ok: false };
  }
  if (minute === "*" || hour === "*" || minute.includes(",") || hour.includes(",")) {
    return { ok: false };
  }
  return {
    ok: true,
    minute,
    hour,
    dom: dom === "*" ? [] : dom.split(","),
    month: month === "*" ? [] : month.split(","),
    dow: dow === "*" ? [] : dow.split(","),
  };
}

function setBuilderEnabled(enabled) {
  scheduleTime.disabled = !enabled;
  Array.from(daysOfWeekContainer.querySelectorAll("input")).forEach((input) => {
    input.disabled = !enabled;
  });
  daysOfMonthSelect.disabled = !enabled;
  monthsSelect.disabled = !enabled;
}

function setCronEditable(editable) {
  cronExpression.readOnly = !editable;
}

function syncCronFromBuilder() {
  if (customCron.checked) {
    return;
  }
  cronExpression.value = buildCronFromInputs();
}

function updateScheduleInfo(data) {
  scheduleLast.textContent = formatTimestamp(data.last_run);
  scheduleNext.textContent = data.next_run ? formatTimestamp(data.next_run) : "never";
}

function getGlobalBackupLastRun() {
  let latest = null;
  state.hosts.forEach((host) => {
    const overrides = host.backup_cron_override || {};
    const enabledMap = host.backup_enabled || {};
    const lastAtMap = host.backup_last_at || {};
    const projects = host.projects || Object.keys(lastAtMap);
    projects.forEach((projectName) => {
      if (overrides[projectName]) {
        return;
      }
      if (!enabledMap[projectName]) {
        return;
      }
      const value = lastAtMap[projectName];
      if (!value) {
        return;
      }
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return;
      }
      if (!latest || date > latest) {
        latest = date;
      }
    });
  });
  return latest ? latest.toISOString() : null;
}

function parseScheduleScope(value) {
  if (value === "global") {
    return { type: "global" };
  }
  const [hostId, ...rest] = value.split("::");
  return { type: "project", hostId, projectName: rest.join("::") };
}

function populateScheduleScope() {
  if (!scheduleScope) {
    return;
  }
  const current = scheduleScope.value;
  scheduleScope.innerHTML = "";
  const globalOption = document.createElement("option");
  globalOption.value = "global";
  globalOption.textContent = "Global schedule";
  scheduleScope.appendChild(globalOption);

  const entries = (scheduleState.summary && scheduleState.summary.length)
    ? scheduleState.summary.filter((entry) => entry.scope === "project")
    : buildProjectEntries();
  const hosts = new Map();
  entries.forEach((entry) => {
    const hostId = entry.host_id || entry.hostId;
    const projectName = entry.project || entry.projectName;
    if (!hostId || !projectName) {
      return;
    }
    const list = hosts.get(hostId) || [];
    list.push(projectName);
    hosts.set(hostId, list);
  });
  Array.from(hosts.keys())
    .sort()
    .forEach((hostId) => {
      const group = document.createElement("optgroup");
      group.label = hostId;
      hosts
        .get(hostId)
        .sort()
        .forEach((projectName) => {
          const option = document.createElement("option");
          option.value = `${hostId}::${projectName}`;
          option.textContent = projectName;
          group.appendChild(option);
        });
      scheduleScope.appendChild(group);
    });
  if (current) {
    scheduleScope.value = current;
  }
}


function getScheduleSummaryEntry(key) {
  return scheduleState.summary.find((entry) => entry.key === key);
}

function formatScheduleTimestamp(value) {
  return formatTimestamp(value);
}

function getFilteredScheduleSummaryItems() {
  const items = scheduleState.summary || [];
  if (!items.length) {
    return items;
  }
  const visibleKeys = new Set(
    applyProjectFilters(buildProjectEntries()).map((entry) => entry.key)
  );
  return items.filter((entry) => entry.scope !== "project" || visibleKeys.has(entry.key));
}

function renderScheduleSummary() {
  if (!scheduleSummaryBody) {
    return;
  }
  scheduleSummaryBody.innerHTML = "";
  const items = getFilteredScheduleSummaryItems();
  if (!items.length) {
    const row = document.createElement("tr");
    row.className = "empty";
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.textContent = "No schedule data available.";
    row.appendChild(cell);
    scheduleSummaryBody.appendChild(row);
    return;
  }
  if (!scheduleState.selectedKey || !items.some((entry) => entry.key === scheduleState.selectedKey)) {
    const fallback = items.find((entry) => entry.scope === "global");
    scheduleState.selectedKey = (fallback ? fallback.key : items[0].key);
  }
  items.forEach((entry) => {
    const row = document.createElement("tr");
    row.className = "schedule-summary-row";
    if (entry.scope === "global") {
      row.classList.add("global");
    }
    row.dataset.key = entry.key;
    if (entry.key === scheduleState.selectedKey) {
      row.classList.add("selected");
    }
    row.addEventListener("click", (event) => {
      if (event.target.closest("input")) {
        return;
      }
      selectScheduleRow(entry.key);
    });

    const nameCell = document.createElement("td");
    if (entry.name === "global") {
      nameCell.textContent = "global";
    } else {
      nameCell.textContent = getProjectDisplayName(entry.host_id || "", entry.name);
    }
    if (entry.host_id) {
      nameCell.title = entry.host_id;
    }

    const lastCell = document.createElement("td");
    lastCell.textContent = formatScheduleTimestamp(entry.last_run);

    const statusCell = document.createElement("td");
    if (!entry.last_run) {
      statusCell.textContent = "never";
    } else if (entry.last_success === true) {
      statusCell.textContent = "success";
    } else if (entry.last_success === false) {
      const reason = entry.last_failure || "";
      statusCell.textContent = reason ? `failed: ${reason}` : "failed";
      if (reason) {
        statusCell.title = reason;
      }
    } else {
      statusCell.textContent = "unknown";
    }

    const nextCell = document.createElement("td");
    nextCell.textContent = entry.enabled && entry.next_run ? formatScheduleTimestamp(entry.next_run) : "never";

    const enabledCell = document.createElement("td");
    enabledCell.className = "center";
    const enabledInput = document.createElement("input");
    enabledInput.type = "checkbox";
    enabledInput.checked = Boolean(entry.enabled);
    enabledInput.addEventListener("click", (event) => {
      event.stopPropagation();
    });
    enabledInput.addEventListener("change", () => {
      entry.enabled = enabledInput.checked;
      renderScheduleSummary();
      toggleScheduleEnabled(entry, enabledInput.checked);
    });
    enabledCell.appendChild(enabledInput);

    const overrideCell = document.createElement("td");
    overrideCell.className = "center";
    const overrideInput = document.createElement("input");
    overrideInput.type = "checkbox";
    overrideInput.checked = Boolean(entry.override);
    overrideInput.disabled = entry.scope === "global";
    overrideInput.addEventListener("click", (event) => {
      event.stopPropagation();
    });
    overrideInput.addEventListener("change", () => {
      entry.override = overrideInput.checked;
      renderScheduleSummary();
      if (entry.key === scheduleState.selectedKey) {
        setScheduleConfigDisabled(entry.scope === "project" && !entry.override);
        updateScheduleHint(entry, entry.key);
      }
      toggleScheduleOverride(entry, overrideInput.checked);
    });
    overrideCell.appendChild(overrideInput);

    row.appendChild(nameCell);
    row.appendChild(lastCell);
    row.appendChild(statusCell);
    row.appendChild(nextCell);
    row.appendChild(enabledCell);
    row.appendChild(overrideCell);

    scheduleSummaryBody.appendChild(row);
  });
}

function setScheduleConfigDisabled(disabled) {
  if (!scheduleConfig) {
    return;
  }
  scheduleConfig.classList.toggle("disabled", disabled);
}

function updateScheduleHint(entry, configScope) {
  if (!scheduleScopeHint) {
    return;
  }
  if (entry.scope === "global") {
    scheduleScopeHint.textContent = "";
    return;
  }
  if (!entry.override) {
    scheduleScopeHint.textContent = "Override disabled; showing global schedule.";
    return;
  }
  if (configScope === "global") {
    scheduleScopeHint.textContent = "Override disabled; showing global schedule.";
    return;
  }
  scheduleScopeHint.textContent = "Override schedule for this project.";
}

async function updateScheduleSelection() {
  const entry = getScheduleSummaryEntry(scheduleState.selectedKey) || {
    key: "global",
    scope: "global",
    name: "global",
    enabled: false,
    override: false,
  };
  const configScope = entry.scope === "global" || entry.override ? entry.key : "global";
  if (scheduleScope) {
    scheduleScope.value = configScope;
  }
  await loadSchedule();
  updateScheduleInfo({
    last_run: entry.last_run,
    next_run: entry.enabled ? entry.next_run : null,
  });
  setScheduleConfigDisabled(entry.scope === "project" && !entry.override);
  updateScheduleHint(entry, configScope);
}

function selectScheduleRow(key) {
  scheduleState.selectedKey = key;
  renderScheduleSummary();
  updateScheduleSelection();
}

function getCurrentScheduleCronUtc() {
  const raw = cronExpression.value.trim();
  let cron = customCron.checked ? convertCustomCronToUtc(raw) : buildCronFromInputsUtc();
  cron = cron ? cron.trim() : "";
  return cron;
}

async function toggleScheduleEnabled(entry, enabled) {
  if (entry.scope === "global") {
    try {
      const current = await api.get("/backup/schedule");
      const cron = current.cron || "";
      if (enabled && !cron) {
        alert("Global schedule needs a cron expression before enabling.");
        await loadScheduleSummary(entry.key);
        return;
      }
      await api.put("/backup/schedule", {
        cron: cron || null,
        enabled,
      });
      await loadScheduleSummary(entry.key);
    } catch (err) {
      alert(`Failed to update global schedule: ${err.message}`);
      await loadScheduleSummary(entry.key);
    }
    return;
  }

  if (!entry.host_id || !entry.project) {
    return;
  }
  try {
    await api.put(
      `/hosts/${entry.host_id}/projects/${entry.project}/backup/settings`,
      { enabled }
    );
    await loadScheduleSummary(entry.key);
  } catch (err) {
    alert(`Failed to update backup enabled: ${err.message}`);
    await loadScheduleSummary(entry.key);
  }
}

async function toggleScheduleOverride(entry, enabled) {
  if (entry.scope !== "project" || !entry.host_id || !entry.project) {
    return;
  }
  try {
    if (enabled) {
      let cron = getCurrentScheduleCronUtc();
      if (!cron) {
        const globalInfo = await api.get("/backup/schedule");
        cron = globalInfo.cron || "";
      }
      if (!cron) {
        alert("No cron expression available to apply as an override.");
        await loadScheduleSummary(entry.key);
        return;
      }
      await api.put(
        `/hosts/${entry.host_id}/projects/${entry.project}/backup/settings`,
        { cron_override: cron }
      );
    } else {
      await api.put(
        `/hosts/${entry.host_id}/projects/${entry.project}/backup/settings`,
        { cron_override: null }
      );
    }
    await loadScheduleSummary(entry.key);
  } catch (err) {
    alert(`Failed to update override: ${err.message}`);
    await loadScheduleSummary(entry.key);
  }
}

async function loadScheduleSummary(preferredKey) {
  if (!scheduleSummaryBody) {
    return { ok: false, error: "Schedule UI unavailable." };
  }
  scheduleSummaryBody.innerHTML = '<tr class="empty"><td colspan="6">Loading...</td></tr>';
  try {
    const data = await api.get("/backup/schedule/summary");
    scheduleState.summary = data.items || [];
    populateScheduleScope();
    const keys = new Set(scheduleState.summary.map((entry) => entry.key));
    if (preferredKey && keys.has(preferredKey)) {
      scheduleState.selectedKey = preferredKey;
    }
    if (!scheduleState.selectedKey || !keys.has(scheduleState.selectedKey)) {
      scheduleState.selectedKey = keys.has("global") ? "global" : scheduleState.summary[0]?.key;
    }
    renderScheduleSummary();
    await updateScheduleSelection();
    return { ok: true };
  } catch (err) {
    scheduleSummaryBody.innerHTML = `<tr class="empty"><td colspan="6">${err.message}</td></tr>`;
    return { ok: false, error: err.message };
  }
}
async function loadSchedule() {
  if (!scheduleStatus) {
    return { ok: false, error: "Schedule UI unavailable." };
  }
  scheduleStatus.textContent = "Loading schedule...";
  const scope = parseScheduleScope(scheduleScope?.value || "global");
  try {
    let cron = "";
    let info = null;
    if (scope.type === "global") {
      info = await api.get("/backup/schedule");
      cron = info.cron || "";
      updateScheduleInfo({
        last_run: getGlobalBackupLastRun(),
        next_run: info.next_run,
      });
    } else {
      info = await api.get(
        `/hosts/${scope.hostId}/projects/${scope.projectName}/backup/settings`
      );
      cron = info.cron_override || "";
      const lastRun = info.last_backup_at || info.lastBackupAt;
      updateScheduleInfo({
        last_run: lastRun,
        next_run: info.next_run,
      });
      if (!cron && info.effective_cron) {
        cron = info.effective_cron;
      }
    }

    cronExpression.value = cron;
    const parsed = cron ? parseCron(cron) : null;
    if (parsed && parsed.ok) {
      const converted = convertCronParts(parsed, "utc_to_local");
      customCron.checked = false;
      setBuilderEnabled(true);
      setCronEditable(false);
      scheduleTime.value = `${pad(converted.hour)}:${pad(converted.minute)}`;
      setSelectedValues(daysOfMonthSelect, converted.dom);
      setSelectedValues(monthsSelect, converted.month);
      setSelectedDow(converted.dow);
      cronExpression.value = buildCronString({
        minute: converted.minute.toString(),
        hour: converted.hour.toString(),
        dom: converted.dom,
        month: converted.month,
        dow: converted.dow,
      });
    } else if (cron) {
      customCron.checked = true;
      setBuilderEnabled(false);
      setCronEditable(true);
    } else {
      customCron.checked = false;
      setBuilderEnabled(true);
      setCronEditable(false);
      scheduleTime.value = "00:00";
      setSelectedValues(daysOfMonthSelect, []);
      setSelectedValues(monthsSelect, []);
      setSelectedDow([]);
      syncCronFromBuilder();
    }
    scheduleStatus.textContent = "";
    scheduleState.lastLoadFailed = false;
    return { ok: true };
  } catch (err) {
    const message = `Failed to load schedule: ${err.message}`;
    scheduleStatus.textContent = message;
    scheduleState.lastLoadFailed = true;
    return { ok: false, error: message };
  }
}

async function saveSchedule() {
  if (!scheduleStatus) {
    return;
  }
  scheduleStatus.textContent = "Saving schedule...";
  const raw = cronExpression.value.trim();
  let cron = customCron.checked ? convertCustomCronToUtc(raw) : buildCronFromInputsUtc();
  if (!cron) {
    cron = "";
  }
  try {
    const scope = parseScheduleScope(scheduleScope.value || "global");
    if (scope.type === "global") {
      const entry = getScheduleSummaryEntry("global");
      const enabled = entry ? Boolean(entry.enabled) : false;
      await api.put("/backup/schedule", {
        cron: cron || null,
        enabled,
      });
    } else {
      await api.put(
        `/hosts/${scope.hostId}/projects/${scope.projectName}/backup/settings`,
        { cron_override: cron || null }
      );
    }
    await loadScheduleSummary(scheduleState.selectedKey);
    scheduleStatus.textContent = "Saved.";
  } catch (err) {
    scheduleStatus.textContent = `Save failed: ${err.message}`;
  }
}

function initScheduleControls() {
  populateSelect(daysOfMonthSelect, 1, 31);
  populateSelect(monthsSelect, 1, 12);
  populateScheduleScope();

  customCron.addEventListener("change", () => {
    setBuilderEnabled(!customCron.checked);
    setCronEditable(customCron.checked);
    syncCronFromBuilder();
  });

  scheduleTime.addEventListener("change", syncCronFromBuilder);
  daysOfMonthSelect.addEventListener("change", syncCronFromBuilder);
  monthsSelect.addEventListener("change", syncCronFromBuilder);
  Array.from(daysOfWeekContainer.querySelectorAll("input")).forEach((input) => {
    input.addEventListener("change", syncCronFromBuilder);
  });

  saveScheduleBtn.addEventListener("click", saveSchedule);
}

function getActionLabel(button) {
  const label = button.querySelector(".action-label");
  if (label) {
    return label.textContent;
  }
  return button.textContent;
}

function setActionLabel(button, text) {
  const label = button.querySelector(".action-label");
  if (label) {
    label.textContent = text;
  } else {
    button.textContent = text;
  }
}

function formatActionLabel(action) {
  if (action === "hard_restart") {
    return "Hard restart";
  }
  return action.charAt(0).toUpperCase() + action.slice(1);
}

function setActionRunning(button, running) {
  if (running) {
    button.classList.add("in-progress");
    button.dataset.actionRunning = "true";
    button.disabled = true;
  } else {
    button.classList.remove("in-progress");
    button.dataset.actionRunning = "";
    if (button.dataset.forceDisabled !== "true") {
      button.disabled = false;
    }
  }
}

function serviceStatusInfo(service) {
  const status = (service.status || "").toLowerCase();
  if (status === "up" || status === "down" || status === "degraded") {
    return { label: status, className: status };
  }
  return { label: "unknown", className: "unknown" };
}

function statusIconName(className) {
  if (className === "up") {
    return "arrow_circle_up";
  }
  if (className === "down") {
    return "arrow_circle_down";
  }
  if (className === "degraded") {
    return "warning";
  }
  return "help";
}

function healthIconName(status) {
  if (status === "healthy") {
    return "heart_check";
  }
  if (status === "unhealthy") {
    return "heart_broken";
  }
  if (status === "starting") {
    return "hourglass_top";
  }
  return "pulse_alert";
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
const ANSI_COLORS = {
  30: "#0b0f14",
  31: "#f87171",
  32: "#4ade80",
  33: "#facc15",
  34: "#60a5fa",
  35: "#c084fc",
  36: "#22d3ee",
  37: "#e5e7eb",
  90: "#64748b",
  91: "#fca5a5",
  92: "#86efac",
  93: "#fde047",
  94: "#93c5fd",
  95: "#e9d5ff",
  96: "#67e8f9",
  97: "#f8fafc",
};

const ANSI_BG_COLORS = {
  40: "#0b0f14",
  41: "#b91c1c",
  42: "#166534",
  43: "#854d0e",
  44: "#1e3a8a",
  45: "#6b21a8",
  46: "#155e75",
  47: "#e5e7eb",
  100: "#1f2937",
  101: "#ef4444",
  102: "#22c55e",
  103: "#eab308",
  104: "#3b82f6",
  105: "#a855f7",
  106: "#06b6d4",
  107: "#f8fafc",
};

function ansiToHtml(input) {
  if (!input) {
    return "";
  }
  let normalized = input.replace(/\r/g, "");
  normalized = normalized.replace(/\\033/g, "\x1b");
  normalized = normalized.replace(/\\e/gi, "\x1b");
  normalized = normalized.replace(/\\x1b/gi, "\x1b");
  normalized = normalized.replace(/\\u001b/gi, "\x1b");
  let output = "";
  let index = 0;
  const state = { fg: null, bg: null, bold: false, italic: false, underline: false };
  let open = false;

  const buildStyle = () => {
    const styles = [];
    if (state.fg) {
      styles.push(`color:${state.fg}`);
    }
    if (state.bg) {
      styles.push(`background-color:${state.bg}`);
    }
    if (state.bold) {
      styles.push("font-weight:700");
    }
    if (state.italic) {
      styles.push("font-style:italic");
    }
    if (state.underline) {
      styles.push("text-decoration:underline");
    }
    return styles.join(";");
  };

  const closeSpan = () => {
    if (open) {
      output += "</span>";
      open = false;
    }
  };

  const openSpan = () => {
    const style = buildStyle();
    if (style) {
      output += `<span style="${style}">`;
      open = true;
    }
  };

  const applyCodes = (codes) => {
    for (let i = 0; i < codes.length; i += 1) {
      const code = codes[i];
      if (code === 0) {
        state.fg = null;
        state.bg = null;
        state.bold = false;
        state.italic = false;
        state.underline = false;
        continue;
      }
      if (code === 1) {
        state.bold = true;
        continue;
      }
      if (code === 3) {
        state.italic = true;
        continue;
      }
      if (code === 4) {
        state.underline = true;
        continue;
      }
      if (code === 22) {
        state.bold = false;
        continue;
      }
      if (code === 23) {
        state.italic = false;
        continue;
      }
      if (code === 24) {
        state.underline = false;
        continue;
      }
      if (code === 39) {
        state.fg = null;
        continue;
      }
      if (code === 49) {
        state.bg = null;
        continue;
      }
      if (code === 38 || code === 48) {
        const isFg = code === 38;
        const mode = codes[i + 1];
        if (mode === 2 && codes.length >= i + 4) {
          const r = codes[i + 2];
          const g = codes[i + 3];
          const b = codes[i + 4];
          const color = `rgb(${r}, ${g}, ${b})`;
          if (isFg) {
            state.fg = color;
          } else {
            state.bg = color;
          }
          i += 4;
          continue;
        }
        if (mode === 5 && codes.length >= i + 2) {
          i += 2;
          continue;
        }
        continue;
      }
      if (ANSI_COLORS[code]) {
        state.fg = ANSI_COLORS[code];
        continue;
      }
      if (ANSI_BG_COLORS[code]) {
        state.bg = ANSI_BG_COLORS[code];
        continue;
      }
    }
  };

  while (index < normalized.length) {
    const escIndex = normalized.indexOf("\u001b", index);
    if (escIndex === -1) {
      output += escapeHtml(normalized.slice(index));
      break;
    }
    output += escapeHtml(normalized.slice(index, escIndex));
    const nextChar = normalized[escIndex + 1];
    if (nextChar === "[") {
      const rest = normalized.slice(escIndex);
      const match = rest.match(/^\u001b\[[0-9;?]*[A-Za-z]/);
      if (match) {
        const seq = match[0];
        const finalChar = seq[seq.length - 1];
        if (finalChar.toLowerCase() === "m") {
          const body = seq.slice(2, -1);
          const parts = body.split(";").filter((part) => part.length);
          const codes = parts.length ? parts.map((part) => parseInt(part, 10)) : [0];
          closeSpan();
          applyCodes(codes);
          openSpan();
        }
        index = escIndex + seq.length;
        continue;
      }
    }
    if (nextChar === "]") {
      const rest = normalized.slice(escIndex + 2);
      let end = rest.indexOf("\u0007");
      let advance = 1;
      if (end === -1) {
        const escEnd = rest.indexOf("\u001b\\");
        if (escEnd !== -1) {
          end = escEnd;
          advance = 2;
        }
      }
      if (end !== -1) {
        index = escIndex + 2 + end + advance;
        continue;
      }
    }
    index = escIndex + (nextChar ? 2 : 1);
  }

  closeSpan();
  return output;
}

function initComposeEditor() {
  if (!composeEditor || composeEditorCm || !window.CodeMirror) {
    return;
  }
  composeEditorCm = window.CodeMirror.fromTextArea(composeEditor, {
    mode: "yaml",
    theme: "material-darker",
    lineNumbers: true,
    lineWrapping: true,
    gutters: ["CodeMirror-lint-markers", "CodeMirror-linenumbers"],
    lint: true,
    indentUnit: 2,
    tabSize: 2,
  });
  composeEditorCm.on("change", handleComposeInput);
}

function refreshComposeEditor() {
  if (composeEditorCm) {
    composeEditorCm.refresh();
  }
}

function getComposeValue() {
  if (!composeEditor) {
    return "";
  }
  return composeEditorCm ? composeEditorCm.getValue() : composeEditor.value || "";
}

function setComposeValue(value) {
  if (!composeEditor) {
    return;
  }
  if (composeEditorCm) {
    composeEditorCm.setValue(value);
  }
  composeEditor.value = value;
}

function setComposeOriginal(value) {
  if (!composeEditor) {
    return;
  }
  composeEditor.dataset.original = value;
}

function handleComposeInput() {
  diffPanel.classList.add("hidden");
  confirmComposeBtn.classList.add("hidden");
  if (previewComposeBtn) {
    previewComposeBtn.classList.remove("hidden");
  }
  if (composeModal) {
    composeModal.classList.remove("reviewing");
  }
  composeStatus.textContent = "";
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
  if (diffView) {
    diffView.innerHTML = "";
  }
  composeDiffView = null;
  resetSearchState(composeSearchState);
}

function handleCreateComposeInput() {
  resetSearchState(createSearchState);
}

function resetSearchState(state) {
  if (!state) {
    return;
  }
  state.query = "";
  state.lastMatch = null;
}

function getEditorText(editor, textarea) {
  if (editor) {
    return editor.getValue();
  }
  if (textarea) {
    return textarea.value || "";
  }
  return "";
}

function setEditorText(editor, textarea, value, onChange) {
  if (editor) {
    editor.setValue(value);
    return;
  }
  if (textarea) {
    textarea.value = value;
  }
  if (onChange) {
    onChange();
  }
}

function getEditorSelectionRange(editor, textarea) {
  if (editor) {
    const selection = editor.listSelections()[0];
    const from = selection ? selection.from() : editor.getCursor("from");
    const to = selection ? selection.to() : editor.getCursor("to");
    return {
      start: editor.indexFromPos(from),
      end: editor.indexFromPos(to),
    };
  }
  if (textarea) {
    return {
      start: textarea.selectionStart || 0,
      end: textarea.selectionEnd || 0,
    };
  }
  return { start: 0, end: 0 };
}

function setEditorSelectionRange(editor, textarea, start, end) {
  if (editor) {
    const from = editor.posFromIndex(start);
    const to = editor.posFromIndex(end);
    editor.focus();
    editor.setSelection(from, to);
    editor.scrollIntoView({ from, to }, 40);
    return;
  }
  if (textarea) {
    textarea.focus();
    textarea.setSelectionRange(start, end);
  }
}

function findNextMatch(state, editor, textarea, query) {
  const text = getEditorText(editor, textarea);
  if (!query) {
    return false;
  }
  const selection = getEditorSelectionRange(editor, textarea);
  let startIndex = selection.end;
  if (state.query === query && state.lastMatch) {
    if (selection.start === state.lastMatch.start && selection.end === state.lastMatch.end) {
      startIndex = state.lastMatch.end;
    }
  }
  let index = text.indexOf(query, startIndex);
  if (index === -1 && startIndex > 0) {
    index = text.indexOf(query, 0);
  }
  if (index === -1) {
    return false;
  }
  const end = index + query.length;
  state.query = query;
  state.lastMatch = { start: index, end };
  setEditorSelectionRange(editor, textarea, index, end);
  return true;
}

function replaceCurrentMatch(state, editor, textarea, query, replacement, onChange) {
  if (!query) {
    return false;
  }
  const text = getEditorText(editor, textarea);
  let selection = getEditorSelectionRange(editor, textarea);
  let matchStart = selection.start;
  let matchEnd = selection.end;
  let matched = matchEnd > matchStart && text.slice(matchStart, matchEnd) === query;
  if (!matched && state.query === query && state.lastMatch) {
    matchStart = state.lastMatch.start;
    matchEnd = state.lastMatch.end;
    matched = text.slice(matchStart, matchEnd) === query;
  }
  if (!matched) {
    if (!findNextMatch(state, editor, textarea, query)) {
      return false;
    }
    selection = getEditorSelectionRange(editor, textarea);
    matchStart = selection.start;
    matchEnd = selection.end;
  }
  const newText = text.slice(0, matchStart) + replacement + text.slice(matchEnd);
  setEditorText(editor, textarea, newText, onChange);
  const newEnd = matchStart + replacement.length;
  state.query = query;
  state.lastMatch = { start: matchStart, end: newEnd };
  setEditorSelectionRange(editor, textarea, matchStart, newEnd);
  return true;
}

function replaceAllMatches(state, editor, textarea, query, replacement, onChange) {
  if (!query) {
    return 0;
  }
  const text = getEditorText(editor, textarea);
  let result = "";
  let index = 0;
  let count = 0;
  while (true) {
    const found = text.indexOf(query, index);
    if (found === -1) {
      result += text.slice(index);
      break;
    }
    result += text.slice(index, found) + replacement;
    index = found + query.length;
    count += 1;
  }
  if (count > 0) {
    setEditorText(editor, textarea, result, onChange);
  }
  state.query = query;
  state.lastMatch = null;
  return count;
}

function getComposeSearchContext() {
  return {
    bar: composeSearchBar,
    searchInput: composeSearchInput,
    replaceInput: composeReplaceInput,
    findNextBtn: composeFindNextBtn,
    replaceBtn: composeReplaceBtn,
    replaceAllBtn: composeReplaceAllBtn,
    closeBtn: composeSearchCloseBtn,
    editor: composeEditorCm,
    textarea: composeEditor,
    state: composeSearchState,
    onChange: handleComposeInput,
  };
}

function getCreateSearchContext() {
  return {
    bar: createSearchBar,
    searchInput: createSearchInput,
    replaceInput: createReplaceInput,
    findNextBtn: createFindNextBtn,
    replaceBtn: createReplaceBtn,
    replaceAllBtn: createReplaceAllBtn,
    closeBtn: createSearchCloseBtn,
    editor: createComposeEditor,
    textarea: createProjectCompose,
    state: createSearchState,
    onChange: handleCreateComposeInput,
  };
}

function openSearchBar(context, mode) {
  if (!context || !context.bar) {
    return;
  }
  context.bar.classList.remove("hidden");
  const focusInput = mode === "replace" ? context.replaceInput || context.searchInput : context.searchInput;
  if (focusInput) {
    focusInput.focus();
    focusInput.select();
  }
}

function closeSearchBar(context) {
  if (!context || !context.bar) {
    return;
  }
  context.bar.classList.add("hidden");
  resetSearchState(context.state);
}

function bindSearchControls(getContext) {
  const context = getContext();
  if (!context || !context.bar) {
    return;
  }
  if (context.bar.dataset.bound === "true") {
    return;
  }
  context.bar.dataset.bound = "true";
  const runFind = () => {
    const ctx = getContext();
    const query = ctx.searchInput ? ctx.searchInput.value : "";
    findNextMatch(ctx.state, ctx.editor, ctx.textarea, query);
  };
  const runReplace = () => {
    const ctx = getContext();
    const query = ctx.searchInput ? ctx.searchInput.value : "";
    const replacement = ctx.replaceInput ? ctx.replaceInput.value : "";
    replaceCurrentMatch(ctx.state, ctx.editor, ctx.textarea, query, replacement, ctx.onChange);
  };
  const runReplaceAll = () => {
    const ctx = getContext();
    const query = ctx.searchInput ? ctx.searchInput.value : "";
    const replacement = ctx.replaceInput ? ctx.replaceInput.value : "";
    replaceAllMatches(ctx.state, ctx.editor, ctx.textarea, query, replacement, ctx.onChange);
  };
  const handleEscape = (event) => {
    if (event.key !== "Escape") {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    closeSearchBar(getContext());
  };
  if (context.findNextBtn) {
    context.findNextBtn.addEventListener("click", runFind);
  }
  if (context.replaceBtn) {
    context.replaceBtn.addEventListener("click", runReplace);
  }
  if (context.replaceAllBtn) {
    context.replaceAllBtn.addEventListener("click", runReplaceAll);
  }
  if (context.closeBtn) {
    context.closeBtn.addEventListener("click", () => closeSearchBar(getContext()));
  }
  if (context.searchInput) {
    context.searchInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        runFind();
      }
      handleEscape(event);
    });
    context.searchInput.addEventListener("input", () => {
      const ctx = getContext();
      ctx.state.lastMatch = null;
      ctx.state.query = ctx.searchInput ? ctx.searchInput.value : "";
    });
  }
  if (context.replaceInput) {
    context.replaceInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        runReplace();
      }
      handleEscape(event);
    });
    context.replaceInput.addEventListener("input", () => {
      const ctx = getContext();
      ctx.state.lastMatch = null;
    });
  }
}

function initCreateComposeEditor() {
  if (!createProjectCompose || createComposeEditor || !window.CodeMirror) {
    return;
  }
  createComposeEditor = window.CodeMirror.fromTextArea(createProjectCompose, {
    mode: "yaml",
    theme: "material-darker",
    lineNumbers: true,
    lineWrapping: true,
    gutters: ["CodeMirror-lint-markers", "CodeMirror-linenumbers"],
    lint: true,
    indentUnit: 2,
    tabSize: 2,
  });
  createComposeEditor.on("change", handleCreateComposeInput);
}

function refreshCreateComposeEditor() {
  if (createComposeEditor) {
    createComposeEditor.refresh();
  }
}

function getCreateComposeValue() {
  if (!createProjectCompose) {
    return "";
  }
  return createComposeEditor ? createComposeEditor.getValue() : createProjectCompose.value || "";
}

function setCreateComposeValue(value) {
  if (!createProjectCompose) {
    return;
  }
  if (createComposeEditor) {
    createComposeEditor.setValue(value);
  }
  createProjectCompose.value = value;
}

function applyCommandChunk(chunk, outputParts) {
  if (!chunk) {
    return;
  }
  const reset = /\u001b\[(?:\d+;?)*[Hf]/.test(chunk) || /\u001b\[2J/.test(chunk) || /\u001b\[J/.test(chunk);
  if (reset) {
    outputParts.length = 0;
  }
  const cleaned = chunk.replace(/\u001b\[[0-9;?]*[A-Za-z]/g, (seq) => (seq.endsWith("m") ? seq : ""));
  const parts = cleaned.split("\r");
  if (parts.length > 1) {
    const last = parts[parts.length - 1];
    if (outputParts.length) {
      outputParts[outputParts.length - 1] = last;
    } else {
      outputParts.push(last);
    }
    return;
  }
  outputParts.push(cleaned);
}

function openComposeModal(hostId, projectName) {
  composeState.hostId = hostId;
  composeState.projectName = projectName;
  composeModal.classList.remove("hidden");
  closeSearchBar(getComposeSearchContext());
  initComposeEditor();
  refreshComposeEditor();
  composeTarget.textContent = `${hostId} / ${projectName}`;
  composePath.textContent = "";
  setComposeValue("");
  setComposeOriginal("");
  composeStatus.textContent = "Loading compose file...";
  diffPanel.classList.add("hidden");
  confirmComposeBtn.classList.add("hidden");
  if (previewComposeBtn) {
    previewComposeBtn.classList.remove("hidden");
  }
  if (composeModal) {
    composeModal.classList.remove("reviewing");
  }
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
  if (diffView) {
    diffView.innerHTML = "";
  }
  composeDiffView = null;

  api
    .get(`/hosts/${hostId}/projects/${projectName}/compose`)
    .then((data) => {
      composePath.textContent = data.path || "";
      setComposeValue(data.content || "");
      setComposeOriginal(data.content || "");
      composeStatus.textContent = "";
      refreshComposeEditor();
    })
    .catch((err) => {
      composeStatus.textContent = `Error: ${err.message}`;
    });
}

function closeComposeModal() {
  composeModal.classList.add("hidden");
  closeSearchBar(getComposeSearchContext());
  composeState.hostId = null;
  composeState.projectName = null;
  diffPanel.classList.add("hidden");
  confirmComposeBtn.classList.add("hidden");
  if (previewComposeBtn) {
    previewComposeBtn.classList.remove("hidden");
  }
  if (composeModal) {
    composeModal.classList.remove("reviewing");
  }
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
  if (diffView) {
    diffView.innerHTML = "";
  }
  composeDiffView = null;
}
function openCommandModal(hostId, projectName) {
  if (!commandModal) {
    return;
  }
  commandState.hostId = hostId;
  commandState.projectName = projectName;
  commandModal.classList.remove("hidden");
  if (commandTarget) {
    commandTarget.textContent = `${hostId} / ${projectName}`;
  }
  if (commandInput) {
    commandInput.value = "";
    commandInput.focus();
  }
  if (commandStatus) {
    commandStatus.textContent = "Enter docker compose arguments (e.g. ps -a).";
    commandStatus.classList.remove("error", "success");
  }
  if (commandOutput) {
    commandOutput.textContent = "";
  }
  setCommandRunning(false);
}

function setCommandRunning(running) {
  if (!runCommandBtn) {
    return;
  }
  runCommandBtn.dataset.running = running ? "true" : "";
  runCommandBtn.textContent = running ? "Stop" : "Run";
  runCommandBtn.classList.toggle("subtle", !running);
  runCommandBtn.classList.toggle("ghost", running);
}

function closeCommandModal() {
  if (!commandModal) {
    return;
  }
  commandModal.classList.add("hidden");
  if (commandState.stream) {
    commandState.stream.close();
    commandState.stream = null;
  }
  setCommandRunning(false);
  if (runCommandBtn) {
    runCommandBtn.disabled = false;
  }
  commandState.hostId = null;
  commandState.projectName = null;
  if (commandStatus) {
    commandStatus.textContent = "";
    commandStatus.classList.remove("error", "success");
  }
  if (commandOutput) {
    commandOutput.textContent = "";
  }
}


function openLogsModal(hostId, projectName, serviceName = "") {
  logsState.hostId = hostId;
  logsState.projectName = projectName;
  logsModal.classList.remove("hidden");
  logsTarget.textContent = `${hostId} / ${projectName}${serviceName ? ` / ${serviceName}` : ""}`;
  logsContent.textContent = "Loading logs...";
  logsServiceInput.value = serviceName || "";
  logsTailInput.value = "200";
  logsShowStdout.checked = true;
  logsShowStderr.checked = true;
  updateLogsFilter();
  stopLogFollow();
  fetchLogs();
}

function closeLogsModal() {
  logsModal.classList.add("hidden");
  logsState.hostId = null;
  logsState.projectName = null;
  logsContent.textContent = "";
  stopLogFollow();
}

function setShellStatus(message, isError = false) {
  if (!shellStatus) {
    return;
  }
  shellStatus.textContent = message || "";
  shellStatus.classList.toggle("error", isError);
}

function ensureShellTerminal() {
  if (!shellTerminal) {
    return false;
  }
  if (!window.Terminal || !window.FitAddon) {
    setShellStatus("Terminal emulator unavailable.", true);
    return false;
  }
  if (!shellState.term) {
    shellState.term = new window.Terminal({
      cursorBlink: true,
      fontFamily: '"Courier New", monospace',
      fontSize: 12,
      theme: {
        background: "#0a0f16",
        foreground: "#e2e8f0",
      },
    });
    shellState.fitAddon = new window.FitAddon.FitAddon();
    shellState.term.loadAddon(shellState.fitAddon);
    shellState.term.open(shellTerminal);
    shellState.term.onData((data) => {
      if (shellState.socket && shellState.socket.readyState === WebSocket.OPEN) {
        shellState.socket.send(JSON.stringify({ type: "input", data }));
      }
    });
  }
  return true;
}

function sendShellResize() {
  if (!shellState.socket || shellState.socket.readyState !== WebSocket.OPEN || !shellState.term) {
    return;
  }
  if (shellState.fitAddon) {
    shellState.fitAddon.fit();
  }
  shellState.socket.send(
    JSON.stringify({ type: "resize", cols: shellState.term.cols, rows: shellState.term.rows })
  );
}

function connectShell(hostId, projectName, serviceName) {
  const authHeader = getAuthHeader();
  if (!authHeader) {
    setShellStatus("Sign in required.", true);
    return;
  }
  const token = authHeader.split(" ")[1] || "";
  if (!token) {
    setShellStatus("Session token missing.", true);
    return;
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  let cols = 80;
  let rows = 24;
  if (shellState.term) {
    if (shellState.fitAddon) {
      shellState.fitAddon.fit();
    }
    cols = shellState.term.cols;
    rows = shellState.term.rows;
  }
  const url = `${protocol}://${window.location.host}/ws/hosts/${encodeURIComponent(
    hostId
  )}/projects/${encodeURIComponent(projectName)}/services/${encodeURIComponent(
    serviceName
  )}/shell?token=${encodeURIComponent(token)}&cols=${cols}&rows=${rows}`;
  if (shellState.socket) {
    shellState.socket.close();
  }
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  shellState.socket = socket;
  setShellStatus("Connecting...");

  socket.onopen = () => {
    setShellStatus("Connected");
    if (shellState.term) {
      shellState.term.focus();
    }
    sendShellResize();
  };
  socket.onmessage = (event) => {
    if (!shellState.term) {
      return;
    }
    if (event.data instanceof ArrayBuffer) {
      const view = new Uint8Array(event.data);
      shellState.term.write(new TextDecoder().decode(view));
    } else {
      shellState.term.write(event.data);
    }
  };
  socket.onerror = () => {
    setShellStatus("Shell connection error.", true);
  };
  socket.onclose = () => {
    setShellStatus("Disconnected.");
  };
}

function openShellModal(hostId, projectName, serviceName) {
  if (!shellModal) {
    return;
  }
  shellModal.classList.remove("hidden");
  if (shellTarget) {
    shellTarget.textContent = `${hostId} / ${projectName} / ${serviceName}`;
  }
  shellState.hostId = hostId;
  shellState.projectName = projectName;
  shellState.serviceName = serviceName;
  if (!ensureShellTerminal()) {
    return;
  }
  if (shellState.term) {
    shellState.term.reset();
  }
  connectShell(hostId, projectName, serviceName);
  sendShellResize();
}

function closeShellModal() {
  if (shellModal) {
    shellModal.classList.add("hidden");
  }
  if (shellState.socket) {
    shellState.socket.close();
    shellState.socket = null;
  }
  shellState.hostId = null;
  shellState.projectName = null;
  shellState.serviceName = null;
  setShellStatus("");
  if (shellState.term) {
    shellState.term.reset();
  }
}
function handleShellResize() {
  if (!shellModal || shellModal.classList.contains("hidden")) {
    return;
  }
  sendShellResize();
}


function openProjectDetailsModal(entry) {
  if (!projectDetailsModal) {
    return;
  }
  projectDetailsModal.classList.remove("hidden");
  if (projectDetailsTitle) {
    projectDetailsTitle.textContent = getProjectDisplayName(entry.hostId, entry.projectName);
  }
  if (projectDetailsHost) {
    projectDetailsHost.textContent = entry.hostId || "unknown";
  }
  if (projectDetailsPath) {
    projectDetailsPath.textContent = entry.path || "unknown";
  }
  if (projectDetailsBackup) {
    projectDetailsBackup.textContent = formatTimestamp(entry.lastBackupAt);
  }
  if (projectDetailsBackupSuccess) {
    let successText = "unknown";
    if (entry.lastBackupSuccess === true) {
      successText = "success";
    } else if (entry.lastBackupSuccess === false) {
      const failureReason = entry.lastBackupFailure || "";
      successText = failureReason ? `failed: ${failureReason}` : "failed";
    }
    projectDetailsBackupSuccess.textContent = successText;
  }
  if (projectDetailsStatus) {
    projectDetailsStatus.textContent = formatTimestamp(entry.refreshedAt);
  }
  projectDetailsState.key = `${entry.hostId}::${entry.projectName}`;
  setProjectDetailsPortsMessage("Loading...");
  setProjectDetailsStatsMessage("Loading...");
  loadProjectDetailsPorts(entry.hostId, entry.projectName);
  loadProjectDetailsStats(entry.hostId, entry.projectName);
}


function setProjectDetailsPortsMessage(message) {
  if (!projectDetailsPortsBody) {
    return;
  }
  projectDetailsPortsBody.innerHTML = "";
  const row = document.createElement("tr");
  row.className = "empty";
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.textContent = message;
  row.appendChild(cell);
  projectDetailsPortsBody.appendChild(row);
}

function renderProjectPorts(entries) {
  if (!projectDetailsPortsBody) {
    return;
  }
  projectDetailsPortsBody.innerHTML = "";
  if (!entries || !entries.length) {
    setProjectDetailsPortsMessage("No port mappings.");
    return;
  }
  const sorted = [...entries].sort((a, b) => {
    const nameA = (a.service || a.name || "").toLowerCase();
    const nameB = (b.service || b.name || "").toLowerCase();
    if (nameA === nameB) {
      const portA = `${a.container_port || ""}/${a.protocol || ""}`;
      const portB = `${b.container_port || ""}/${b.protocol || ""}`;
      return portA.localeCompare(portB);
    }
    return nameA.localeCompare(nameB);
  });
  sorted.forEach((entry) => {
    const row = document.createElement("tr");
    const serviceCell = document.createElement("td");
    serviceCell.textContent = entry.service || entry.name || "unknown";

    const containerCell = document.createElement("td");
    containerCell.className = "mono";
    const containerPort = entry.container_port || "n/a";
    const protocol = entry.protocol ? `/${entry.protocol}` : "";
    containerCell.textContent = `${containerPort}${protocol}`;

    const hostIpCell = document.createElement("td");
    hostIpCell.className = "mono";
    hostIpCell.textContent = entry.host_ip || "n/a";

    const hostPortCell = document.createElement("td");
    hostPortCell.className = "mono";
    hostPortCell.textContent = entry.host_port || "n/a";

    row.appendChild(serviceCell);
    row.appendChild(containerCell);
    row.appendChild(hostIpCell);
    row.appendChild(hostPortCell);
    projectDetailsPortsBody.appendChild(row);
  });
}

async function loadProjectDetailsPorts(hostId, projectName) {
  if (!projectDetailsPortsBody) {
    return;
  }
  const requestKey = `${hostId}::${projectName}`;
  projectDetailsState.key = requestKey;
  try {
    const data = await api.get(`/hosts/${hostId}/projects/${projectName}/ports`);
    if (projectDetailsState.key !== requestKey) {
      return;
    }
    renderProjectPorts(data.ports || []);
  } catch (err) {
    if (projectDetailsState.key !== requestKey) {
      return;
    }
    setProjectDetailsPortsMessage(`Error: ${err.message}`);
  }
}

function setProjectDetailsStatsMessage(message) {
  if (!projectDetailsStatsBody) {
    return;
  }
  projectDetailsStatsBody.innerHTML = "";
  const row = document.createElement("tr");
  row.className = "empty";
  const cell = document.createElement("td");
  cell.colSpan = 8;
  cell.textContent = message;
  row.appendChild(cell);
  projectDetailsStatsBody.appendChild(row);
}

function formatProjectStatsMem(entry) {
  if (!entry.mem_usage) {
    return "n/a";
  }
  if (entry.mem_percent) {
    return `${entry.mem_usage} (${entry.mem_percent})`;
  }
  return entry.mem_usage;
}

function formatProjectStatsUptime(entry) {
  if (entry.uptime_seconds === null || entry.uptime_seconds === undefined) {
    return "n/a";
  }
  return formatDuration(entry.uptime_seconds);
}

function renderProjectStats(entries) {
  if (!projectDetailsStatsBody) {
    return;
  }
  projectDetailsStatsBody.innerHTML = "";
  if (!entries || !entries.length) {
    setProjectDetailsStatsMessage("No stats available.");
    return;
  }
  const sorted = [...entries].sort((a, b) => {
    const nameA = (a.service || a.name || "").toLowerCase();
    const nameB = (b.service || b.name || "").toLowerCase();
    return nameA.localeCompare(nameB);
  });
  sorted.forEach((entry) => {
    const row = document.createElement("tr");
    const serviceCell = document.createElement("td");
    serviceCell.textContent = entry.service || entry.name || "unknown";

    const cpuCell = document.createElement("td");
    cpuCell.className = "mono";
    cpuCell.textContent = entry.cpu_percent || "n/a";

    const memCell = document.createElement("td");
    memCell.className = "mono";
    memCell.textContent = formatProjectStatsMem(entry);

    const netCell = document.createElement("td");
    netCell.className = "mono";
    netCell.textContent = entry.net_io || "n/a";

    const blockCell = document.createElement("td");
    blockCell.className = "mono";
    blockCell.textContent = entry.block_io || "n/a";

    const pidsCell = document.createElement("td");
    pidsCell.textContent = entry.pids === null || entry.pids === undefined ? "n/a" : entry.pids;

    const uptimeCell = document.createElement("td");
    uptimeCell.textContent = formatProjectStatsUptime(entry);

    const restartsCell = document.createElement("td");
    restartsCell.textContent = entry.restarts === null || entry.restarts === undefined ? "n/a" : entry.restarts;

    row.appendChild(serviceCell);
    row.appendChild(cpuCell);
    row.appendChild(memCell);
    row.appendChild(netCell);
    row.appendChild(blockCell);
    row.appendChild(pidsCell);
    row.appendChild(uptimeCell);
    row.appendChild(restartsCell);
    projectDetailsStatsBody.appendChild(row);
  });
}

async function loadProjectDetailsStats(hostId, projectName) {
  if (!projectDetailsStatsBody) {
    return;
  }
  const requestKey = `${hostId}::${projectName}`;
  projectDetailsState.key = requestKey;
  try {
    const data = await api.get(`/hosts/${hostId}/projects/${projectName}/stats`);
    if (projectDetailsState.key !== requestKey) {
      return;
    }
    renderProjectStats(data.stats || []);
  } catch (err) {
    if (projectDetailsState.key !== requestKey) {
      return;
    }
    setProjectDetailsStatsMessage(`Error: ${err.message}`);
  }
}

function closeProjectDetailsModal() {
  if (projectDetailsModal) {
    projectDetailsModal.classList.add("hidden");
  }
  projectDetailsState.key = null;
  setProjectDetailsPortsMessage("Loading...");
  setProjectDetailsStatsMessage("Loading...");
}

function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(seconds));
  const units = [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
    ["s", 1],
  ];
  const parts = [];
  let remaining = total;
  for (const [label, size] of units) {
    if (remaining >= size || (label === "s" && parts.length === 0)) {
      const value = Math.floor(remaining / size);
      remaining -= value * size;
      parts.push(`${value}${label}`);
      if (parts.length >= 2) {
        break;
      }
    }
  }
  return parts.join(" ");
}

function formatCountdown(value) {
  if (!value) return "disabled";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  const diff = date.getTime() - Date.now();
  if (diff <= 0) return "due";
  return `in ${formatDuration(Math.ceil(diff / 1000))}`;
}

function updateEventCountdowns() {
  const nodes = document.querySelectorAll(".event-countdown");
  nodes.forEach((node) => {
    const timestamp = node.dataset.timestamp;
    if (!timestamp) {
      node.textContent = "";
      return;
    }
    node.textContent = `(${formatCountdown(timestamp)})`;
  });
}

function renderEventStatusList() {
  if (!eventStatusList) {
    return;
  }
  eventStatusList.innerHTML = "";
  const items = eventStatusState.items || [];
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No event data available.";
    eventStatusList.appendChild(empty);
    return;
  }
  items.forEach((entry) => {
    const card = document.createElement("div");
    card.className = `event-status-card${entry.enabled ? "" : " disabled"}`;

    const head = document.createElement("div");
    head.className = "event-status-head";

    const title = document.createElement("div");
    title.className = "event-status-title";
    title.textContent = entry.label || entry.id;

    const side = document.createElement("div");
    side.className = "event-status-side";

    const badge = document.createElement("span");
    badge.className = "event-status-badge";
    badge.textContent = entry.enabled ? "enabled" : "disabled";

    side.appendChild(badge);

    let intervalConfigNode = null;
    const intervalConfig = EVENT_INTERVAL_CONFIG[entry.id];
    if (intervalConfig) {
      const config = document.createElement("div");
      config.className = "event-interval-config";
      const label = document.createElement("div");
      label.className = "event-interval-label";
      label.textContent = intervalConfig.label;
      const input = document.createElement("input");
      input.className = "event-interval-input";
      input.type = "number";
      input.min = "0";
      input.value = entry.interval_seconds ?? 0;
      const saveBtn = document.createElement("button");
      saveBtn.className = "btn subtle event-interval-save";
      saveBtn.textContent = "Save";
      const updatesDisabled = entry.id === "update_refresh" && !state.updatesEnabled;
      if (updatesDisabled) {
        input.disabled = true;
        saveBtn.disabled = true;
      }
      saveBtn.addEventListener("click", () => saveEventInterval(entry.id, input, saveBtn));
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          saveEventInterval(entry.id, input, saveBtn);
        }
      });
      config.appendChild(label);
      config.appendChild(input);
      config.appendChild(saveBtn);
      intervalConfigNode = config;
    }

    head.appendChild(title);
    head.appendChild(side);

    const desc = document.createElement("div");
    desc.className = "event-status-desc";
    desc.textContent = entry.description || "";

    const descRow = document.createElement("div");
    descRow.className = "event-status-desc-row";
    descRow.appendChild(desc);
    if (intervalConfigNode) {
      descRow.appendChild(intervalConfigNode);
    }

    const meta = document.createElement("div");
    meta.className = "event-status-meta";

    const nextItem = document.createElement("div");
    nextItem.className = "event-status-item";
    const nextLabel = document.createElement("span");
    nextLabel.textContent = "Next run: ";
    const nextValue = document.createElement("strong");
    let nextText = entry.enabled ? formatTimestamp(entry.next_run) : "disabled";
    if (!entry.enabled && entry.interval_seconds === 0) {
      nextText = "never";
    }
    nextValue.textContent = nextText;
    const nextCountdown = document.createElement("span");
    nextCountdown.className = "event-countdown";
    if (entry.enabled && entry.next_run) {
      nextCountdown.dataset.timestamp = entry.next_run;
      nextCountdown.textContent = `(${formatCountdown(entry.next_run)})`;
    }
    nextItem.appendChild(nextLabel);
    nextItem.appendChild(nextValue);
    nextItem.appendChild(nextCountdown);

    const lastItem = document.createElement("div");
    lastItem.className = "event-status-item";
    const lastLabel = document.createElement("span");
    lastLabel.textContent = "Last run: ";
    const lastValue = document.createElement("strong");
    lastValue.textContent = formatTimestamp(entry.last_run);
    lastItem.appendChild(lastLabel);
    lastItem.appendChild(lastValue);

    const resultItem = document.createElement("div");
    resultItem.className = "event-status-item";
    const resultLabel = document.createElement("span");
    resultLabel.textContent = "Last result: ";
    const resultValue = document.createElement("strong");
    resultValue.textContent = entry.last_result || "No runs yet";
    if (entry.last_success === true) {
      resultValue.classList.add("event-status-result", "ok");
    } else if (entry.last_success === false) {
      resultValue.classList.add("event-status-result", "fail");
    }
    resultItem.appendChild(resultLabel);
    resultItem.appendChild(resultValue);

    meta.appendChild(nextItem);
    meta.appendChild(lastItem);
    meta.appendChild(resultItem);

    card.appendChild(head);
    card.appendChild(descRow);
    card.appendChild(meta);

    eventStatusList.appendChild(card);
  });

  updateEventCountdowns();
}

async function loadEventStatus() {
  if (!eventStatusList) {
    return { ok: false };
  }
  if (eventStatusState.loading) {
    return { ok: false, busy: true };
  }
  eventStatusState.loading = true;
  eventStatusList.innerHTML = '<div class="empty">Loading...</div>';
  try {
    const data = await api.get("/events/status");
    eventStatusState.items = data.events || [];
    eventStatusState.updatedAt = data.generated_at || null;
    if (eventStatusUpdated) {
      eventStatusUpdated.textContent = `Updated: ${formatTimestamp(eventStatusState.updatedAt)}`;
    }
    renderEventStatusList();
    return { ok: true };
  } catch (err) {
    eventStatusList.innerHTML = `<div class="empty">${err.message}</div>`;
    if (eventStatusUpdated) {
      eventStatusUpdated.textContent = "Updated: --";
    }
    return { ok: false, error: err.message };
  } finally {
    eventStatusState.loading = false;
  }
}

function startEventStatusTimer() {
  if (eventStatusState.timerId) {
    return;
  }
  eventStatusState.timerId = window.setInterval(updateEventCountdowns, 1000);
}

function stopEventStatusTimer() {
  if (!eventStatusState.timerId) {
    return;
  }
  window.clearInterval(eventStatusState.timerId);
  eventStatusState.timerId = null;
}

function updateEventAutoButton() {
  if (!toggleEventAutoBtn) {
    return;
  }
  toggleEventAutoBtn.textContent = `Auto refresh: ${eventStatusState.autoRefreshEnabled ? "On" : "Off"}`;
  toggleEventAutoBtn.classList.toggle("active", eventStatusState.autoRefreshEnabled);
}

function startEventStatusAutoRefresh() {
  if (!eventStatusState.autoRefreshEnabled || eventStatusState.autoRefreshId) {
    return;
  }
  eventStatusState.autoRefreshId = window.setInterval(() => {
    loadEventStatus();
  }, EVENT_STATUS_REFRESH_MS);
}

function stopEventStatusAutoRefresh() {
  if (!eventStatusState.autoRefreshId) {
    return;
  }
  window.clearInterval(eventStatusState.autoRefreshId);
  eventStatusState.autoRefreshId = null;
}

function setEventStatusActive(active) {
  if (active) {
    updateEventAutoButton();
    loadEventStatus();
    startEventStatusTimer();
    if (eventStatusState.autoRefreshEnabled) {
      startEventStatusAutoRefresh();
    }
    return;
  }
  stopEventStatusTimer();
  stopEventStatusAutoRefresh();
}

function openEventStatusModal() {
  if (!canAccessEvents()) {
    showToast("Admin access required.", "error");
    return;
  }
  openConfigModal();
  setActiveConfigTab("events");
}

function closeEventStatusModal() {
  setEventStatusActive(false);
}

async function openBackupScheduleModal() {
  if (!canAccessBackupSchedule()) {
    showToast("Admin access required.", "error");
    return;
  }
  if (!backupScheduleModal) {
    return;
  }
  backupScheduleModal.classList.remove("hidden");
  if (!scheduleState.initialized) {
    initScheduleControls();
    scheduleState.initialized = true;
  }
  let preferredKey = null;
  if (state.selectedProjects.size === 1) {
    const [onlyProject] = state.selectedProjects;
    preferredKey = onlyProject;
  }
  const result = await loadScheduleSummary(preferredKey);
  if (!result.ok && result.error) {
    showToast(result.error, "error");
  }
}

function closeBackupScheduleModal() {
  if (backupScheduleModal) {
    backupScheduleModal.classList.add("hidden");
  }
}

function setRestoreStatus(message, isError = false) {
  if (!restoreStatus) {
    return;
  }
  restoreStatus.textContent = message || "";
  restoreStatus.classList.toggle("error", Boolean(isError));
}

function updateRestoreButtonState() {
  if (!openRestoreModalBtn) {
    return;
  }
  const label = state.restoreInProgress ? "Restoring" : "Restore";
  setActionLabel(openRestoreModalBtn, label);
  openRestoreModalBtn.title = state.restoreInProgress
    ? "Cancel restore after the current project finishes"
    : "Restore";
}

function requestRestoreCancel() {
  if (!state.restoreInProgress || state.restoreCancelRequested) {
    return;
  }
  state.restoreCancelRequested = true;
  updateRestoreButtonState();
  showToast("Restore will stop after the current project finishes.");
}

function handleRestoreButtonClick() {
  if (state.restoreInProgress) {
    requestRestoreCancel();
    return;
  }
  openRestoreModal();
}


function populateRestoreHosts() {
  if (!restoreHostSelect) {
    return;
  }
  restoreHostSelect.innerHTML = "";
  if (!state.hosts.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No hosts available";
    restoreHostSelect.appendChild(option);
    if (runRestoreBtn) {
      runRestoreBtn.disabled = true;
    }
    return;
  }
  state.hosts.forEach((host) => {
    const option = document.createElement("option");
    option.value = host.host_id;
    option.textContent = `${host.host_id} (${host.user}@${host.host})`;
    restoreHostSelect.appendChild(option);
  });
  if (runRestoreBtn) {
    runRestoreBtn.disabled = false;
  }
}

function populateRestoreTargets(targets) {
  if (!restoreBackupTarget) {
    return;
  }
  restoreBackupTarget.innerHTML = "";
  if (!targets.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No backup targets";
    restoreBackupTarget.appendChild(option);
    restoreBackupTarget.disabled = true;
    if (runRestoreBtn) {
      runRestoreBtn.disabled = true;
    }
    return;
  }
  targets.forEach((target) => {
    const option = document.createElement("option");
    option.value = target.id;
    option.textContent = target.enabled ? target.id : `${target.id} (disabled)`;
    restoreBackupTarget.appendChild(option);
  });
  restoreBackupTarget.disabled = false;
}

function populateRestoreProjects(projects) {
  if (!restoreProjectSelect) {
    return;
  }
  restoreProjectSelect.innerHTML = "";
  if (!projects.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No backups found";
    restoreProjectSelect.appendChild(option);
    if (runRestoreBtn) {
      runRestoreBtn.disabled = true;
    }
    return;
  }
  const hostId = restoreHostSelect ? restoreHostSelect.value : "";
  projects.forEach((project) => {
    const option = document.createElement("option");
    option.value = project;
    option.textContent = getProjectDisplayName(hostId, project);
    restoreProjectSelect.appendChild(option);
  });
  if (restoreProjectSelect.options.length) {
    restoreProjectSelect.options[0].selected = true;
  }
  if (runRestoreBtn) {
    runRestoreBtn.disabled = false;
  }
}

async function loadRestoreTargets() {
  if (!restoreBackupTarget) {
    return;
  }
  setRestoreStatus("Loading backup targets...");
  try {
    const targets = await api.get("/backup/targets");
    populateRestoreTargets(targets || []);
    setRestoreStatus("");
  } catch (err) {
    populateRestoreTargets([]);
    setRestoreStatus(`Failed to load backup targets: ${err.message}`, true);
  }
}

async function loadRestoreProjects() {
  if (!restoreBackupTarget || !restoreProjectSelect) {
    return;
  }
  const backupId = restoreBackupTarget.value;
  if (!backupId) {
    populateRestoreProjects([]);
    setRestoreStatus("Select a backup target to load projects.");
    return;
  const stateHost = state.stateSnapshot?.hosts?.find((item) => item.host_id === hostId);
  let existing = [];
  if (stateHost && Array.isArray(stateHost.projects)) {
    existing = projects.filter((project) =>
      stateHost.projects.some((entry) => entry.project === project)
    );
  } else {
    const hostEntry = state.hosts.find((item) => item.host_id === hostId);
    if (hostEntry && Array.isArray(hostEntry.projects)) {
      existing = projects.filter((project) => hostEntry.projects.includes(project));
    }
  }
  if (!overwrite && existing.length) {
    const confirmOverwrite = window.confirm(
      `Project(s) already exist on ${hostId}: ${existing.join(", ")}\. Overwrite with the backup?`
    );
    if (confirmOverwrite) {
      await runRestore(true);
      return;
    }
    setRestoreStatus("Restore cancelled.");
    return;
  }
  }
  setRestoreStatus("Loading backup projects...");
  try {
    const data = await api.get(`/backup/targets/${encodeURIComponent(backupId)}/projects`);
    const projects = data.projects || [];
    populateRestoreProjects(projects);
    if (projects.length) {
      setRestoreStatus(`Loaded ${projects.length} project${projects.length === 1 ? "" : "s"}.`);
    } else {
      setRestoreStatus("No backups found for this target.");
    }
  } catch (err) {
    populateRestoreProjects([]);
    setRestoreStatus(`Failed to load backups: ${err.message}`, true);
  }
}

async function openRestoreModal() {
  if (!canRestoreProjects()) {
    showToast("Admin or power access required.", "error");
    return;
  }
  if (!restoreModal) {
    return;
  }
  restoreModal.classList.remove("hidden");
  setRestoreStatus("");
  populateRestoreHosts();
  await loadRestoreTargets();
  await loadRestoreProjects();
}

function closeRestoreModal() {
  if (restoreModal) {
    restoreModal.classList.add("hidden");
  }
}

async function runRestore(overwrite = false) {
  if (!restoreBackupTarget || !restoreHostSelect || !restoreProjectSelect) {
    return;
  }
  if (state.restoreInProgress) {
    requestRestoreCancel();
    return;
  }
  const backupId = restoreBackupTarget.value;
  const hostId = restoreHostSelect.value;
  const projects = Array.from(restoreProjectSelect.selectedOptions)
    .map((option) => option.value)
    .filter(Boolean);
  if (!backupId || !hostId || !projects.length) {
    setRestoreStatus("Select a backup target, host, and project(s) to restore.", true);
    return;
  }
  const stateHost = state.stateSnapshot?.hosts?.find((item) => item.host_id === hostId);
  let existing = [];
  if (stateHost && Array.isArray(stateHost.projects)) {
    existing = projects.filter((project) =>
      stateHost.projects.some((entry) => entry.project === project)
    );
  } else {
    const hostEntry = state.hosts.find((item) => item.host_id === hostId);
    if (hostEntry && Array.isArray(hostEntry.projects)) {
      existing = projects.filter((project) => hostEntry.projects.includes(project));
    }
  }
  if (!overwrite && existing.length) {
    const confirmOverwrite = window.confirm(
      `Project(s) already exist on ${hostId}: ${existing.join(", ")}. Overwrite with the backup?`
    );
    if (confirmOverwrite) {
      await runRestore(true);
      return;
    }
    setRestoreStatus("Restore cancelled.");
    return;
  }
  state.restoreInProgress = true;
  state.restoreCancelRequested = false;
  state.restoreLockedProjects = new Set(existing.map((project) => `${hostId}::${project}`));
  updateRestoreButtonState();
  if (runRestoreBtn) {
    runRestoreBtn.disabled = true;
  }
  closeRestoreModal();
  closeAllActionMenus();
  renderProjectList();
  setBulkProgress("restore", 0, projects.length, hostId);
  setRestoreStatus(`Restoring ${projects.map((project) => getProjectDisplayName(hostId, project)).join(", ")}...`);
  try {
    const results = [];
    let completed = 0;
    for (const project of projects) {
      const payload = {
        backup_id: backupId,
        host_id: hostId,
        projects: [project],
        overwrite,
      };
      try {
        const result = await api.post("/backup/restore", payload);
        const entries = Array.isArray(result) ? result : [result];
        results.push(...entries);
      } catch (err) {
        results.push({
          project,
          output: `Restore failed: ${err.message || String(err)}`,
        });
      }
      completed += 1;
      setBulkProgress("restore", completed, projects.length, project);
      if (state.restoreCancelRequested) {
        break;
      }
    }
    const failures = results.filter((entry) =>
      String(entry.output || "").toLowerCase().includes("restore failed")
    );
    const successCount = results.length - failures.length;
    const cancelled = state.restoreCancelRequested && completed < projects.length;
    const summary = cancelled
      ? `Restore cancelled after ${completed}/${projects.length}.`
      : `Restore complete: ${successCount} succeeded, ${failures.length} failed.`;
    let detail = "";
    if (failures.length) {
      detail = failures
        .map((entry) => `${getProjectDisplayName(hostId, entry.project || "unknown")}: ${entry.output}`)
        .join(" | ");
    }
    const message = detail ? `${summary} ${detail}` : summary;
    setRestoreStatus(message, failures.length > 0);
    showToast(summary, failures.length > 0 ? "error" : "success");
    setBulkProgress("restore", completed, projects.length, hostId);
  } catch (err) {
    setRestoreStatus(`Restore failed: ${err.message}`, true);
    showToast(`Restore failed: ${err.message}`, "error");
  } finally {
    state.restoreInProgress = false;
    state.restoreCancelRequested = false;
    state.restoreLockedProjects = new Set();
    updateRestoreButtonState();
    renderProjectList();
    if (runRestoreBtn) {
      runRestoreBtn.disabled = false;
    }
    window.setTimeout(() => setBulkProgress("restore", 0, 0), 1500);
  }
}

function resetCreateProgress() {
  if (createProjectProgressText) {
    createProjectProgressText.textContent = "Awaiting input";
  }
  if (createProjectProgressBar) {
    createProjectProgressBar.style.width = "0%";
  }
  const progress = document.querySelector(".create-progress");
  if (progress) {
    progress.classList.add("hidden");
  }
}

function setCreateProgress(message, percent) {
  if (createProjectProgressText && message) {
    createProjectProgressText.textContent = message;
  }
  if (createProjectProgressBar && typeof percent === "number") {
    createProjectProgressBar.style.width = `${percent}%`;
  }
  const progress = document.querySelector(".create-progress");
  if (progress) {
    progress.classList.remove("hidden");
  }
}

async function requestRunConversion(command, serviceName) {
  const payload = { command };
  if (serviceName) {
    payload.service = serviceName;
  }
  const data = await api.post("/compose/convert", payload);
  return data.compose || "";
}

async function convertRunToCompose() {
  if (!createProjectRun || !createProjectCompose || !createProjectStatus) {
    return;
  }
  const command = createProjectRun.value.trim();
  const serviceName = createProjectName ? createProjectName.value.trim() : "";
  if (!command) {
    createProjectStatus.textContent = "Docker run command is required to convert.";
    createProjectStatus.classList.add("error");
    return;
  }
  if (convertRunToComposeBtn) {
    convertRunToComposeBtn.disabled = true;
  }
  createProjectStatus.textContent = "";
  createProjectStatus.classList.remove("error", "success");
  setCreateProgress("Converting docker run...", 20);
  try {
    const composeText = await requestRunConversion(command, serviceName);
    setCreateComposeValue(composeText);
    refreshCreateComposeEditor();
    createProjectStatus.textContent = "Docker run converted to compose.";
    createProjectStatus.classList.add("success");
    setCreateProgress("Conversion complete.", 40);
  } catch (err) {
    setCreateProgress("Conversion failed.", 0);
    createProjectStatus.textContent = `Conversion failed: ${err.message}`;
    createProjectStatus.classList.add("error");
  } finally {
    if (convertRunToComposeBtn) {
      convertRunToComposeBtn.disabled = false;
    }
  }
}

async function submitAuth() {
  if (!authUsername || !authPassword || !authStatus) {
    return;
  }
  const username = authUsername.value.trim();
  const password = authPassword.value;
  if (!username || !password) {
    authStatus.textContent = "Username and password are required.";
    authStatus.classList.remove("success");
    authStatus.classList.add("error");
    return;
  }
  if (authSubmit) {
    authSubmit.disabled = true;
  }
  authStatus.textContent = "Signing in...";
  authStatus.classList.remove("error", "success");
  try {
    const response = await fetch("/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(parseErrorMessage(text, response.statusText));
    }
    const token = (await response.text()).trim();
    if (!token) {
      throw new Error("Token missing from response.");
    }
    setAuthToken(token);
    authStatus.textContent = "Signed in.";
    authStatus.classList.add("success");
    hideAuthModal();
    await initApp(true);
  } catch (err) {
    authStatus.textContent = `Sign in failed: ${err.message}`;
    authStatus.classList.add("error");
  } finally {
    if (authSubmit) {
      authSubmit.disabled = false;
    }
  }
}

function populateCreateProjectHosts() {
  if (!createProjectHost) {
    return;
  }
  createProjectHost.innerHTML = "";
  if (!state.hosts.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No hosts available";
    createProjectHost.appendChild(option);
    if (createProjectSubmit) {
      createProjectSubmit.disabled = true;
    }
    return;
  }
  state.hosts.forEach((host) => {
    const option = document.createElement("option");
    option.value = host.host_id;
    option.textContent = `${host.host_id} (${host.user}@${host.host})`;
    createProjectHost.appendChild(option);
  });
  if (createProjectSubmit) {
    createProjectSubmit.disabled = false;
  }
}

function openCreateProjectModal() {
  if (!canAccessConfig()) {
    showToast("Admin access required.", "error");
    return;
  }
  if (!createProjectModal) {
    return;
  }
  createProjectModal.classList.remove("hidden");
  closeSearchBar(getCreateSearchContext());
  initCreateComposeEditor();
  refreshCreateComposeEditor();
  populateCreateProjectHosts();
  if (createProjectName) {
    createProjectName.value = "";
  }
  if (createProjectRun) {
    createProjectRun.value = "";
  }
  if (createProjectCompose) {
    setCreateComposeValue(DEFAULT_CREATE_COMPOSE);
    refreshCreateComposeEditor();
  }
  if (createProjectBackup) {
    createProjectBackup.checked = false;
  }
  if (createProjectStatus) {
    createProjectStatus.textContent = "";
    createProjectStatus.classList.remove("error", "success");
  }
  resetCreateProgress();
}

function closeCreateProjectModal() {
  if (!createProjectModal) {
    return;
  }
  createProjectModal.classList.add("hidden");
  closeSearchBar(getCreateSearchContext());
}

function openDeleteProjectModal(hostId, projectName) {
  if (!deleteProjectModal) {
    return;
  }
  deleteProjectState.hostId = hostId;
  deleteProjectState.projectName = projectName;
  if (deleteProjectTarget) {
    deleteProjectTarget.textContent = `${hostId} / ${projectName}`;
  }
  if (deleteProjectStatus) {
    deleteProjectStatus.textContent = "";
    deleteProjectStatus.classList.remove("error", "success");
  }
  if (deleteProjectBackup) {
    deleteProjectBackup.checked = false;
  }
  if (deleteProjectBackupToggle) {
    deleteProjectBackupToggle.classList.toggle("hidden", !state.backupTargetsAvailable);
  }
  if (confirmDeleteProjectBtn) {
    confirmDeleteProjectBtn.disabled = false;
  }
  deleteProjectModal.classList.remove("hidden");
}

function closeDeleteProjectModal() {
  if (!deleteProjectModal) {
    return;
  }
  deleteProjectModal.classList.add("hidden");
  if (deleteProjectBackup) {
    deleteProjectBackup.checked = false;
  }
  deleteProjectState.hostId = null;
  deleteProjectState.projectName = null;
}

async function submitDeleteProject() {
  if (!deleteProjectState.hostId || !deleteProjectState.projectName) {
    return;
  }
  if (confirmDeleteProjectBtn) {
    confirmDeleteProjectBtn.disabled = true;
  }
  if (deleteProjectStatus) {
    deleteProjectStatus.textContent = "Deleting project...";
    deleteProjectStatus.classList.remove("error", "success");
  }
  try {
    const deleteBackup = deleteProjectBackup ? deleteProjectBackup.checked : false;
    const deleteQuery = deleteBackup ? "?delete_backup=1" : "";
    await api.delete(
      `/hosts/${encodeURIComponent(deleteProjectState.hostId)}/projects/${encodeURIComponent(
        deleteProjectState.projectName
      )}${deleteQuery}`
    );
    showToast(`${getProjectDisplayName(deleteProjectState.hostId, deleteProjectState.projectName)}: project deleted`);
    await loadHosts();
    updateProjectFilterIndicators();
    await loadState();
    renderLists();
    closeDeleteProjectModal();
  } catch (err) {
    if (deleteProjectStatus) {
      deleteProjectStatus.textContent = `Delete failed: ${err.message}`;
      deleteProjectStatus.classList.add("error");
    }
  } finally {
    if (confirmDeleteProjectBtn) {
      confirmDeleteProjectBtn.disabled = false;
    }
  }
}

async function submitCreateProject() {
  if (
    !createProjectHost ||
    !createProjectName ||
    !createProjectCompose ||
    !createProjectStatus ||
    !createProjectSubmit
  ) {
    return;
  }
  const hostId = createProjectHost.value;
  const projectName = createProjectName.value.trim();
  const runCommand = createProjectRun ? createProjectRun.value.trim() : "";
  let content = getCreateComposeValue();
  const enableBackup = Boolean(createProjectBackup && createProjectBackup.checked);
  if (!hostId) {
    createProjectStatus.textContent = "Select a host for the project.";
    createProjectStatus.classList.add("error");
    return;
  }
  if (!projectName) {
    createProjectStatus.textContent = "Project name is required.";
    createProjectStatus.classList.add("error");
    return;
  }
  const trimmedContent = content.trim();
  const defaultCompose = DEFAULT_CREATE_COMPOSE.trim();
  if (runCommand && (!trimmedContent || trimmedContent === defaultCompose)) {
    setCreateProgress("Converting docker run...", 15);
    try {
      content = await requestRunConversion(runCommand, projectName);
      setCreateComposeValue(content);
      refreshCreateComposeEditor();
    } catch (err) {
      setCreateProgress("Conversion failed.", 0);
      createProjectStatus.textContent = `Conversion failed: ${err.message}`;
      createProjectStatus.classList.add("error");
      return;
    }
  }
  if (!content.trim()) {
    createProjectStatus.textContent = "Compose file content is required.";
    createProjectStatus.classList.add("error");
    return;
  }

  createProjectSubmit.disabled = true;
  createProjectStatus.classList.remove("error", "success");
  createProjectStatus.textContent = "";
  resetCreateProgress();
  setCreateProgress("Validating compose file...", 35);
  try {
    const validation = await api.post(`/hosts/${hostId}/projects/validate`, {
      content,
    });
    if (!validation.ok) {
      setCreateProgress("Validation failed.", 0);
      createProjectStatus.textContent =
        validation.output || "Compose validation failed.";
      createProjectStatus.classList.add("error");
      return;
    }
    setCreateProgress("Creating project...", 70);
    await api.post(`/hosts/${hostId}/projects`, {
      project: projectName,
      content,
      enable_backup: enableBackup,
    });
    setCreateProgress("Updating state...", 90);
    createProjectStatus.textContent = "Project created.";
    createProjectStatus.classList.add("success");
    setCreateProgress("Project created.", 100);
    showToast(`${getProjectDisplayName(hostId, projectName)}: project created`);
    await loadHosts();
    updateProjectFilterIndicators();
    await loadState();
    renderLists();
  } catch (err) {
    setCreateProgress("Create failed.", 0);
    createProjectStatus.textContent = `Create failed: ${err.message}`;
    createProjectStatus.classList.add("error");
  } finally {
    createProjectSubmit.disabled = false;
  }
}

function setConfigStatus(message, variant = "") {
  if (!configStatus) {
    return;
  }
  configStatus.textContent = message || "";
  configStatus.classList.remove("error", "success");
  if (variant) {
    configStatus.classList.add(variant);
  }
}

function openConfigModal() {
  if (!canAccessConfig()) {
    showToast("Admin access required.", "error");
    return;
  }
  if (!configModal) {
    return;
  }
  configModal.classList.remove("hidden");
  initConfigTabs();
  const activeTab = getActiveConfigTab() || "hosts";
  setActiveConfigTab(activeTab);
  loadConfigEntries();
}

function closeConfigModal() {
  if (!configModal) {
    return;
  }
  configModal.classList.add("hidden");
  setEventStatusActive(false);
}

function getActiveConfigTab() {
  const active = document.querySelector(".config-tab.active");
  return active ? active.dataset.tab : null;
}

function setActiveConfigTab(target) {
  if (!target) {
    return;
  }
  configTabs.forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === target);
  });
  configTabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.tabPanel === target);
  });
  setEventStatusActive(target === "events");
}

function initConfigTabs() {
  if (state.configTabsInit) {
    return;
  }
  configTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      setActiveConfigTab(tab.dataset.tab);
    });
  });
  state.configTabsInit = true;
}

function confirmDeleteResource(label, name) {
  const target = name ? ` ${name}` : "";
  return window.confirm(`Are you sure you want to delete ${label}${target}?`);
}

function buildHostConfigEntry(host, isNew) {
  const entry = hostConfigTemplate.content.firstElementChild.cloneNode(true);
  entry.dataset.new = isNew ? "true" : "false";
  const idInput = entry.querySelector(".host-id");
  const rootInput = entry.querySelector(".host-root");
  const addressInput = entry.querySelector(".host-address");
  const userInput = entry.querySelector(".host-user");
  const portInput = entry.querySelector(".host-port");
  const keyInput = entry.querySelector(".host-key");
  const title = entry.querySelector(".host-title");
  const collapseBtn = entry.querySelector(".config-collapse");
  idInput.value = host?.id || "";
  rootInput.value = host?.project_root || "";
  addressInput.value = host?.ssh_address || "";
  userInput.value = host?.ssh_username || "";
  portInput.value = host?.ssh_port ?? 22;
  keyInput.value = host?.ssh_key || "";
  if (!isNew) {
    idInput.disabled = true;
    entry.classList.add("collapsed");
    if (collapseBtn) {
      collapseBtn.classList.add("collapsed");
    }
  }
  const updateTitle = () => {
    if (!title) {
      return;
    }
    const value = idInput.value.trim();
    title.textContent = value || (isNew ? "New host" : "Host");
  };
  updateTitle();
  idInput.addEventListener("input", updateTitle);
  if (collapseBtn) {
    collapseBtn.addEventListener("click", () => {
      entry.classList.toggle("collapsed");
      collapseBtn.classList.toggle("collapsed", entry.classList.contains("collapsed"));
    });
  }
  const saveBtn = entry.querySelector(".config-save");
  const deleteBtn = entry.querySelector(".config-delete");
  saveBtn.addEventListener("click", () => saveHostConfig(entry));
  deleteBtn.addEventListener("click", () => {
    const name = idInput.value.trim();
    if (!confirmDeleteResource("host", name)) {
      return;
    }
    deleteHostConfig(entry);
  });
  return entry;
}

function buildBackupConfigEntry(backup, isNew) {
  const entry = backupConfigTemplate.content.firstElementChild.cloneNode(true);
  entry.dataset.new = isNew ? "true" : "false";
  const idInput = entry.querySelector(".backup-id");
  const addressInput = entry.querySelector(".backup-address");
  const usernameInput = entry.querySelector(".backup-username");
  const passwordInput = entry.querySelector(".backup-password");
  const protocolInput = entry.querySelector(".backup-protocol");
  const portInput = entry.querySelector(".backup-port");
  const basePathInput = entry.querySelector(".backup-base-path");
  const enabledInput = entry.querySelector(".backup-enabled");
  const title = entry.querySelector(".backup-title");
  const collapseBtn = entry.querySelector(".config-collapse");
  idInput.value = backup?.id || "";
  addressInput.value = backup?.address || "";
  usernameInput.value = backup?.username || "";
  passwordInput.value = backup?.password || "";
  protocolInput.value = backup?.protocol || "ssh";
  portInput.value = backup?.port ?? 22;
  basePathInput.value = backup?.base_path || "";
  if (enabledInput) {
    enabledInput.checked = backup?.enabled ?? true;
  }
  if (!isNew) {
    idInput.disabled = true;
    entry.classList.add("collapsed");
    if (collapseBtn) {
      collapseBtn.classList.add("collapsed");
    }
  }
  const updateTitle = () => {
    if (!title) {
      return;
    }
    const value = idInput.value.trim();
    title.textContent = value || (isNew ? "New backup" : "Backup");
  };
  updateTitle();
  idInput.addEventListener("input", updateTitle);
  if (collapseBtn) {
    collapseBtn.addEventListener("click", () => {
      entry.classList.toggle("collapsed");
      collapseBtn.classList.toggle("collapsed", entry.classList.contains("collapsed"));
    });
  }
  const saveBtn = entry.querySelector(".config-save");
  const deleteBtn = entry.querySelector(".config-delete");
  saveBtn.addEventListener("click", () => saveBackupConfig(entry));
  deleteBtn.addEventListener("click", () => {
    const name = idInput.value.trim();
    if (!confirmDeleteResource("backup target", name)) {
      return;
    }
    deleteBackupConfig(entry);
  });
  return entry;
}

function buildUserConfigEntry(user, isNew) {
  const entry = userConfigTemplate.content.firstElementChild.cloneNode(true);
  entry.dataset.new = isNew ? "true" : "false";
  const usernameInput = entry.querySelector(".user-name");
  const roleInput = entry.querySelector(".user-role");
  const passwordInput = entry.querySelector(".user-password");
  const lastLogin = entry.querySelector(".user-last-login");
  usernameInput.value = user?.username || "";
  if (roleInput) {
    roleInput.value = user?.role || "normal";
  }
  passwordInput.value = "";
  if (!isNew) {
    usernameInput.disabled = true;
  }
  if (lastLogin) {
    const timestamp = formatTimestamp(user?.last_login);
    lastLogin.textContent = `Last login: ${timestamp}`;
  }
  const saveBtn = entry.querySelector(".config-save");
  const deleteBtn = entry.querySelector(".config-delete");
  saveBtn.addEventListener("click", () => saveUserConfig(entry));
  const usernameValue = usernameInput.value.trim();
  const isAdmin = usernameValue.toLowerCase() == "admin";
  if (roleInput && isAdmin) {
    roleInput.value = "admin";
    roleInput.disabled = true;
  }
  if (deleteBtn) {
    deleteBtn.disabled = isAdmin;
    deleteBtn.dataset.forceDisabled = isAdmin ? "true" : "";
  }
  if (isAdmin && deleteBtn) {
    deleteBtn.title = "Admin user cannot be deleted.";
  }
  deleteBtn.addEventListener("click", () => {
    const name = usernameInput.value.trim();
    if (name.toLowerCase() === "admin") {
      alert("The admin user cannot be deleted.");
      return;
    }
    if (!confirmDeleteResource("user", name)) {
      return;
    }
    deleteUserConfig(entry);
  });
  return entry;
}

function readHostConfig(entry) {
  return {
    id: entry.querySelector(".host-id").value.trim(),
    project_root: entry.querySelector(".host-root").value.trim(),
    ssh_address: entry.querySelector(".host-address").value.trim(),
    ssh_username: entry.querySelector(".host-user").value.trim(),
    ssh_key: entry.querySelector(".host-key").value.trim(),
    ssh_port: Number.parseInt(entry.querySelector(".host-port").value, 10) || 22,
  };
}

function readBackupConfig(entry) {
  return {
    id: entry.querySelector(".backup-id").value.trim(),
    address: entry.querySelector(".backup-address").value.trim(),
    username: entry.querySelector(".backup-username").value.trim(),
    password: entry.querySelector(".backup-password").value.trim(),
    protocol: entry.querySelector(".backup-protocol").value.trim(),
    port: Number.parseInt(entry.querySelector(".backup-port").value, 10) || 22,
    base_path: entry.querySelector(".backup-base-path").value.trim(),
    enabled: entry.querySelector(".backup-enabled")?.checked ?? true,
  };
}

function readUserConfig(entry) {
  return {
    username: entry.querySelector(".user-name").value.trim(),
    password: entry.querySelector(".user-password").value,
    role: entry.querySelector(".user-role")?.value || "normal",
  };
}

async function saveHostConfig(entry) {
  const payload = readHostConfig(entry);
  const saveBtn = entry.querySelector(".config-save");
  const isNew = entry.dataset.new === "true";
  if (!payload.id) {
    setConfigStatus("Host id is required.", "error");
    return;
  }
  if (!payload.project_root || !payload.ssh_address || !payload.ssh_username || !payload.ssh_key) {
    setConfigStatus("Host requires project root, address, username, and key.", "error");
    return;
  }
  saveBtn.disabled = true;
  setConfigStatus("Saving host...");
  try {
    const url = isNew ? "/config/hosts" : `/config/hosts/${encodeURIComponent(payload.id)}`;
    const data = isNew ? await api.post(url, payload) : await api.put(url, payload);
    entry.dataset.new = "false";
    entry.querySelector(".host-id").disabled = true;
    setConfigStatus(`Host ${data.id} saved.`, "success");
    await loadHosts();
    updateProjectFilterIndicators();
    renderLists();
  } catch (err) {
    setConfigStatus(`Host save failed: ${err.message}`, "error");
  } finally {
    saveBtn.disabled = false;
  }
}

async function deleteHostConfig(entry) {
  const payload = readHostConfig(entry);
  const deleteBtn = entry.querySelector(".config-delete");
  if (entry.dataset.new === "true" || !payload.id) {
    entry.remove();
    return;
  }
  deleteBtn.disabled = true;
  setConfigStatus(`Deleting host ${payload.id}...`);
  try {
    await api.delete(`/config/hosts/${encodeURIComponent(payload.id)}`);
    entry.remove();
    setConfigStatus(`Host ${payload.id} deleted.`, "success");
    await loadHosts();
    updateProjectFilterIndicators();
    renderLists();
  } catch (err) {
    setConfigStatus(`Host delete failed: ${err.message}`, "error");
  } finally {
    deleteBtn.disabled = false;
  }
}

async function saveBackupConfig(entry) {
  const payload = readBackupConfig(entry);
  const saveBtn = entry.querySelector(".config-save");
  const isNew = entry.dataset.new === "true";
  if (!payload.id) {
    setConfigStatus("Backup id is required.", "error");
    return;
  }
  if (!payload.address || !payload.username || !payload.password || !payload.base_path) {
    setConfigStatus("Backup requires address, username, password, and base path.", "error");
    return;
  }
  saveBtn.disabled = true;
  setConfigStatus("Saving backup...");
  try {
    const url = isNew ? "/config/backups" : `/config/backups/${encodeURIComponent(payload.id)}`;
    const data = isNew ? await api.post(url, payload) : await api.put(url, payload);
    entry.dataset.new = "false";
    entry.querySelector(".backup-id").disabled = true;
    setConfigStatus(`Backup ${data.id} saved.`, "success");
    await loadBackupScheduleStatus();
    await loadBackupTargetsAvailability();
    renderProjectList();
  } catch (err) {
    setConfigStatus(`Backup save failed: ${err.message}`, "error");
  } finally {
    saveBtn.disabled = false;
  }
}

async function deleteBackupConfig(entry) {
  const payload = readBackupConfig(entry);
  const deleteBtn = entry.querySelector(".config-delete");
  if (entry.dataset.new === "true" || !payload.id) {
    entry.remove();
    return;
  }
  deleteBtn.disabled = true;
  setConfigStatus(`Deleting backup ${payload.id}...`);
  try {
    await api.delete(`/config/backups/${encodeURIComponent(payload.id)}`);
    entry.remove();
    setConfigStatus(`Backup ${payload.id} deleted.`, "success");
    await loadBackupScheduleStatus();
    await loadBackupTargetsAvailability();
    renderProjectList();
  } catch (err) {
    setConfigStatus(`Backup delete failed: ${err.message}`, "error");
  } finally {
    deleteBtn.disabled = false;
  }
}

async function saveUserConfig(entry) {
  const payload = readUserConfig(entry);
  const saveBtn = entry.querySelector(".config-save");
  const isNew = entry.dataset.new === "true";
  if (!payload.username) {
    setConfigStatus("Username is required.", "error");
    return;
  }
  if (isNew && !payload.password) {
    setConfigStatus("Password is required.", "error");
    return;
  }
  saveBtn.disabled = true;
  setConfigStatus(isNew ? "Creating user..." : "Updating user...");
  try {
    const url = isNew
      ? "/config/users"
      : `/config/users/${encodeURIComponent(payload.username)}`;
    const updatePayload = { role: payload.role };
    if (payload.password) {
      updatePayload.password = payload.password;
    }
    const data = isNew
      ? await api.post(url, payload)
      : await api.put(url, updatePayload);
    entry.dataset.new = "false";
    entry.querySelector(".user-name").disabled = true;
    entry.querySelector(".user-password").value = "";
    if (data.role && entry.querySelector(".user-role")) {
      entry.querySelector(".user-role").value = data.role;
    }
    if (data.last_login && entry.querySelector(".user-last-login")) {
      entry.querySelector(".user-last-login").textContent = `Last login: ${formatTimestamp(
        data.last_login
      )}`;
    }
    setConfigStatus(`User ${data.username} saved.`, "success");
  } catch (err) {
    setConfigStatus(`User save failed: ${err.message}`, "error");
  } finally {
    saveBtn.disabled = false;
  }
}

async function deleteUserConfig(entry) {
  const payload = readUserConfig(entry);
  const deleteBtn = entry.querySelector(".config-delete");
  if (entry.dataset.new === "true" || !payload.username) {
    entry.remove();
    return;
  }
  if (payload.username === "admin") {
    setConfigStatus("Admin user cannot be deleted.", "error");
    return;
  }
  deleteBtn.disabled = true;
  setConfigStatus(`Deleting user ${payload.username}...`);
  try {
    await api.delete(`/config/users/${encodeURIComponent(payload.username)}`);
    entry.remove();
    setConfigStatus(`User ${payload.username} deleted.`, "success");
  } catch (err) {
    setConfigStatus(`User delete failed: ${err.message}`, "error");
  } finally {
    deleteBtn.disabled = false;
  }
}

async function loadConfigEntries() {
  if (!hostConfigList || !backupConfigList || !userConfigList) {
    return;
  }
  setConfigStatus("Loading configuration...");
  if (addHostConfigBtn) {
    addHostConfigBtn.disabled = true;
  }
  if (addBackupConfigBtn) {
    addBackupConfigBtn.disabled = true;
  }
  if (addUserConfigBtn) {
    addUserConfigBtn.disabled = true;
  }
  try {
    const [hosts, backups, users] = await Promise.all([
      api.get("/config/hosts"),
      api.get("/config/backups"),
      api.get("/config/users"),
    ]);
    hostConfigList.innerHTML = "";
    backupConfigList.innerHTML = "";
    userConfigList.innerHTML = "";
    if (!hosts.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No hosts configured.";
      hostConfigList.appendChild(empty);
    } else {
      hosts.forEach((host) => {
        hostConfigList.appendChild(buildHostConfigEntry(host, false));
      });
    }
    if (!backups.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No backups configured.";
      backupConfigList.appendChild(empty);
    } else {
      backups.forEach((backup) => {
        backupConfigList.appendChild(buildBackupConfigEntry(backup, false));
      });
    }
    state.backupTargetsAvailable = backups.some((backup) => backup.enabled);
    updateBulkBackupAvailability();
    if (!users.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No users configured.";
      userConfigList.appendChild(empty);
    } else {
      users.forEach((user) => {
        userConfigList.appendChild(buildUserConfigEntry(user, false));
      });
    }
    setConfigStatus("");
  } catch (err) {
    setConfigStatus(`Failed to load configuration: ${err.message}`, "error");
    hostConfigList.innerHTML = "";
    backupConfigList.innerHTML = "";
    userConfigList.innerHTML = "";
    const hostEmpty = document.createElement("div");
    hostEmpty.className = "empty";
    hostEmpty.textContent = "Configuration unavailable.";
    hostConfigList.appendChild(hostEmpty);
    const backupEmpty = document.createElement("div");
    backupEmpty.className = "empty";
    backupEmpty.textContent = "Configuration unavailable.";
    backupConfigList.appendChild(backupEmpty);
    const userEmpty = document.createElement("div");
    userEmpty.className = "empty";
    userEmpty.textContent = "Configuration unavailable.";
    userConfigList.appendChild(userEmpty);
  } finally {
    await loadIntervals();
    if (addHostConfigBtn) {
      addHostConfigBtn.disabled = false;
    }
    if (addBackupConfigBtn) {
      addBackupConfigBtn.disabled = false;
    }
    if (addUserConfigBtn) {
      addUserConfigBtn.disabled = false;
    }
  }
}

async function loadIntervals() {
  if (!tokenExpiryInput) {
    return;
  }
  try {
    const [stateInterval, tokenExpiry] = await Promise.all([
      api.get("/state/interval"),
      api.get("/config/token-expiry"),
    ]);
    tokenExpiryInput.value = tokenExpiry.seconds;
    state.stateIntervalSeconds = stateInterval.seconds;
    updateStateStatus();
  } catch (err) {
    setConfigStatus(`Failed to load settings: ${err.message}`, "error");
  }
}

async function saveTokenExpiry() {
  if (!tokenExpiryInput || !saveTokenExpiryBtn) {
    return;
  }
  const tokenSeconds = Number.parseInt(tokenExpiryInput.value, 10);
  if (Number.isNaN(tokenSeconds) || tokenSeconds < 30) {
    setConfigStatus("Token expiry must be at least 30 seconds.", "error");
    return;
  }
  saveTokenExpiryBtn.disabled = true;
  setConfigStatus("Saving settings...");
  try {
    await api.put("/config/token-expiry", { seconds: tokenSeconds });
    setConfigStatus("Settings saved.", "success");
  } catch (err) {
    setConfigStatus(`Failed to save settings: ${err.message}`, "error");
  } finally {
    saveTokenExpiryBtn.disabled = false;
  }
}

function updateLogsFilter() {
  if (logsShowStdout.checked) {
    logsContent.classList.remove("hide-stdout");
  } else {
    logsContent.classList.add("hide-stdout");
  }
  if (logsShowStderr.checked) {
    logsContent.classList.remove("hide-stderr");
  } else {
    logsContent.classList.add("hide-stderr");
  }
}

function buildLogsQuery() {
  const params = new URLSearchParams();
  const tailValue = parseInt(logsTailInput.value, 10);
  if (!Number.isNaN(tailValue) && tailValue > 0) {
    params.set("tail", String(tailValue));
  }
  const serviceValue = logsServiceInput.value.trim();
  if (serviceValue) {
    params.set("service", serviceValue);
  }
  return params.toString();
}

function fetchLogs() {
  if (!logsState.hostId || !logsState.projectName) {
    logsContent.textContent = "No project selected.";
    return;
  }
  if (logsState.stream) {
    stopLogFollow();
  }
  const query = buildLogsQuery();
  const url = `/hosts/${logsState.hostId}/projects/${logsState.projectName}/logs${query ? `?${query}` : ""}`;
  logsContent.textContent = "Loading logs...";
  api
    .get(url)
    .then((data) => {
      logsContent.innerHTML = "";
      const span = document.createElement("span");
      span.className = "log-line stdout";
      span.innerHTML = ansiToHtml(data.logs || "No logs returned.");
      logsContent.appendChild(span);
      updateLogsFilter();
      logsContent.scrollTop = logsContent.scrollHeight;
    })
    .catch((err) => {
      logsContent.innerHTML = "";
      const span = document.createElement("span");
      span.className = "log-line stderr";
      span.innerHTML = ansiToHtml(`Error: ${err.message}`);
      logsContent.appendChild(span);
      updateLogsFilter();
    });
}

function stopLogFollow() {
  if (logsState.stream) {
    logsState.stream.close();
    logsState.stream = null;
  }
  toggleFollowBtn.textContent = "Follow";
  logsServiceInput.disabled = false;
  logsTailInput.disabled = false;
}

function toggleLogFollow() {
  if (logsState.stream) {
    stopLogFollow();
    return;
  }
  if (!logsState.hostId || !logsState.projectName) {
    logsContent.textContent = "No project selected.";
    return;
  }
  const query = buildLogsQuery();
  const url = `/hosts/${logsState.hostId}/projects/${logsState.projectName}/logs/stream${query ? `?${query}` : ""}`;
  logsContent.textContent = "";
  const appendLine = (line, streamName) => {
    const span = document.createElement("span");
    span.className = `log-line ${streamName}`;
    span.innerHTML = `${ansiToHtml(line)}\n`;
    logsContent.appendChild(span);
    logsContent.scrollTop = logsContent.scrollHeight;
  };

  logsState.stream = createEventStream(url, {
    onEvent: (eventName, data) => {
      if (eventName === "stdout") {
        appendLine(data, "stdout");
      } else if (eventName === "stderr") {
        appendLine(data, "stderr");
      }
    },
    onError: () => {
      const span = document.createElement("span");
      span.className = "log-line stderr";
      span.innerHTML = ansiToHtml("\n[log stream closed]\n");
      logsContent.appendChild(span);
      stopLogFollow();
    },
  });
  toggleFollowBtn.textContent = "Stop";
  logsServiceInput.disabled = true;
  logsTailInput.disabled = true;

}

function buildDiff(original, current) {
  const originalLines = original.split(/\r?\n/);
  const currentLines = current.split(/\r?\n/);
  const rows = originalLines.length;
  const cols = currentLines.length;
  const dp = Array.from({ length: rows + 1 }, () => new Array(cols + 1).fill(0));

  for (let i = rows - 1; i >= 0; i -= 1) {
    for (let j = cols - 1; j >= 0; j -= 1) {
      if (originalLines[i] === currentLines[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const diff = [];
  let i = 0;
  let j = 0;
  while (i < rows && j < cols) {
    if (originalLines[i] === currentLines[j]) {
      diff.push({ type: "context", text: originalLines[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      diff.push({ type: "remove", text: originalLines[i] });
      i += 1;
    } else {
      diff.push({ type: "add", text: currentLines[j] });
      j += 1;
    }
  }

  while (i < rows) {
    diff.push({ type: "remove", text: originalLines[i] });
    i += 1;
  }
  while (j < cols) {
    diff.push({ type: "add", text: currentLines[j] });
    j += 1;
  }

  return diff;
}

function renderDiff(diff) {
  return diff
    .map((item) => {
      const prefix = item.type === "add" ? "+" : item.type === "remove" ? "-" : " ";
      const className =
        item.type === "add"
          ? "diff-line add"
          : item.type === "remove"
          ? "diff-line remove"
          : "diff-line";
      return `<span class="${className}">${escapeHtml(`${prefix}${item.text}`)}</span>`;
    })
    .join("\n");
}

function getStateByHost() {
  const stateByHost = {};
  if (state.stateSnapshot && state.stateSnapshot.hosts) {
    for (const host of state.stateSnapshot.hosts) {
      stateByHost[host.host_id] = host;
    }
  }
  return stateByHost;
}

function getActiveHostIds() {
  if (state.projectFilters.hosts && state.projectFilters.hosts.length) {
    return state.projectFilters.hosts;
  }
  return state.hosts.map((host) => host.host_id);
}

function buildProjectNameCounts() {
  const counts = new Map();
  state.hosts.forEach((host) => {
    const projectPaths = host.project_paths || {};
    const projectNames = host.projects || Object.keys(projectPaths);
    projectNames.forEach((projectName) => {
      counts.set(projectName, (counts.get(projectName) || 0) + 1);
    });
  });
  return counts;
}

function getProjectDisplayName(hostId, projectName) {
  const counts = buildProjectNameCounts();
  if (hostId && (counts.get(projectName) || 0) > 1) {
    return `${projectName} [${hostId}]`;
  }
  return projectName;
}


function buildProjectEntries() {
  const stateByHost = getStateByHost();
  const activeHostIds = new Set(getActiveHostIds());
  const nameCounts = buildProjectNameCounts();
  const entries = [];

  state.hosts.forEach((host) => {
    if (!activeHostIds.has(host.host_id)) {
      return;
    }
    const stateHost = stateByHost[host.host_id];
    const projectPaths = host.project_paths || {};
    const projectNames = host.projects || Object.keys(projectPaths);
    projectNames.forEach((projectName) => {
      const stateProject = stateHost?.projects?.find((item) => item.project === projectName);
      const projectPath = projectPaths[projectName] || stateProject?.path || "";
      const services = stateProject?.services || [];
      const backupEnabled =
        (host.backup_enabled ? host.backup_enabled[projectName] : undefined) ??
        stateProject?.backup_enabled ??
        false;
      const lastBackupAt =
        (host.backup_last_at ? host.backup_last_at[projectName] : undefined) ??
        stateProject?.last_backup_at ??
        null;
      const lastBackupSuccess =
        (host.backup_last_success ? host.backup_last_success[projectName] : undefined) ??
        stateProject?.last_backup_success ??
        null;
      const lastBackupMessage =
        (host.backup_last_message ? host.backup_last_message[projectName] : undefined) ??
        stateProject?.last_backup_message ??
        null;
      const lastBackupFailure =
        (host.backup_last_failure ? host.backup_last_failure[projectName] : undefined) ??
        stateProject?.last_backup_failure ??
        null;
      const displayName = getProjectDisplayName(host.host_id, projectName);
      entries.push({
        key: `${host.host_id}::${projectName}`,
        hostId: host.host_id,
        projectName,
        displayName,
        path: projectPath,
        status: stateProject?.overall_status,
        updatesAvailable: stateProject?.updates_available,
        sleeping: stateProject?.sleeping,
        refreshedAt: stateProject?.refreshed_at || null,
        backupEnabled: Boolean(backupEnabled),
        lastBackupAt,
        lastBackupSuccess,
        lastBackupMessage,
        lastBackupFailure,
        services,
        serviceCount: services.length,
      });
    });
  });

  return entries;
}

function normalizeProjectStatus(entry) {
  if (entry.sleeping) {
    return "sleeping";
  }
  return entry.status || "unknown";
}

function statusRank(status) {
  switch (status) {
    case "up":
      return 0;
    case "degraded":
      return 1;
    case "down":
      return 2;
    case "sleeping":
      return 3;
    case "unknown":
    default:
      return 4;
  }
}

function updateRank(value) {
  if (value === true) return 0;
  if (value === false) return 1;
  return 2;
}

function applyProjectFilters(entries) {
  const query = state.projectFilters.query.trim().toLowerCase();
  const statusFilter = state.projectFilters.status || "all";
  const updatesFilter = state.projectFilters.updates || "all";
  return entries.filter((entry) => {
    if (query) {
      const nameValue = (entry.displayName || entry.projectName).toLowerCase();
      if (!nameValue.includes(query)) {
        return false;
      }
    }
    if (statusFilter !== "all") {
      if (statusFilter === "sleeping") {
        if (!entry.sleeping) {
          return false;
        }
      } else if (normalizeProjectStatus(entry) !== statusFilter) {
        return false;
      }
    }
    if (updatesFilter !== "all") {
      if (updatesFilter === "yes" && entry.updatesAvailable !== true) {
        return false;
      }
      if (updatesFilter === "no" && entry.updatesAvailable !== false) {
        return false;
      }
    }
    return true;
  });
}


function sortProjectEntries(entries) {
  const sortBy = state.projectFilters.sortBy;
  const sortDir = state.projectFilters.sortDir === "desc" ? -1 : 1;
  const sorted = [...entries];
  sorted.sort((a, b) => {
    let cmp = 0;
    if (sortBy === "status") {
      cmp =
        statusRank(normalizeProjectStatus(a)) -
        statusRank(normalizeProjectStatus(b));
    } else if (sortBy === "updates") {
      cmp = updateRank(a.updatesAvailable) - updateRank(b.updatesAvailable);
    } else {
      cmp = a.projectName.localeCompare(b.projectName);
    }
    if (cmp === 0) {
      cmp = a.projectName.localeCompare(b.projectName);
    }
    return cmp * sortDir;
  });
  return sorted;
}

function getVisibleProjectEntries() {
  return sortProjectEntries(applyProjectFilters(buildProjectEntries()));
}

function countSelectedVisible(entries) {
  return entries.filter((entry) => state.selectedProjects.has(entry.key)).length;
}

function syncProjectSelection(availableKeys) {
  state.selectedProjects.forEach((key) => {
    if (!availableKeys.has(key)) {
      state.selectedProjects.delete(key);
    }
  });
}

function syncBackupCancelled(availableKeys) {
  state.backupCancelled.forEach((key) => {
    if (!availableKeys.has(key)) {
      state.backupCancelled.delete(key);
    }
  });
}

function syncActionProgress(availableKeys) {
  state.actionProgress.forEach((_, key) => {
    if (!availableKeys.has(key)) {
      state.actionProgress.delete(key);
    }
  });
}

function syncServiceActionProgress(availableKeys) {
  state.serviceActionProgress.forEach((_, key) => {
    if (!availableKeys.has(key)) {
      state.serviceActionProgress.delete(key);
    }
  });
}

function getActionProgress(projectKey) {
  return state.actionProgress.get(projectKey) || new Set();
}

function setActionProgress(projectKey, action, running) {
  const actions = new Set(state.actionProgress.get(projectKey) || []);
  if (running) {
    actions.add(action);
  } else {
    actions.delete(action);
  }
  if (actions.size) {
    state.actionProgress.set(projectKey, actions);
  } else {
    state.actionProgress.delete(projectKey);
  }
}

function getHostActionProgress(hostId) {
  return state.hostActionProgress.get(hostId) || new Set();
}

function setHostActionProgress(hostId, action, running) {
  const actions = new Set(state.hostActionProgress.get(hostId) || []);
  if (running) {
    actions.add(action);
  } else {
    actions.delete(action);
  }
  if (actions.size) {
    state.hostActionProgress.set(hostId, actions);
  } else {
    state.hostActionProgress.delete(hostId);
  }
}

function serviceActionKey(hostId, projectName, serviceName) {
  return `${hostId}::${projectName}::${serviceName}`;
}

function getServiceActionProgress(key) {
  return state.serviceActionProgress.get(key) || new Set();
}

function closeAllFilterMenus(exceptMenu = null) {
  filterMenus.forEach((menu) => {
    if (!exceptMenu || menu !== exceptMenu) {
      menu.classList.add("hidden");
    }
  });
}

function closeAllActionMenus(exceptPanel = null) {
  document.querySelectorAll(".action-menu-panel").forEach((panel) => {
    if (!exceptPanel || panel !== exceptPanel) {
      panel.classList.add("hidden");
    }
  });
}

function setServiceActionProgress(key, action, running) {
  const actions = new Set(state.serviceActionProgress.get(key) || []);
  if (running) {
    actions.add(action);
  } else {
    actions.delete(action);
  }
  if (actions.size) {
    state.serviceActionProgress.set(key, actions);
  } else {
    state.serviceActionProgress.delete(key);
  }
}

function hasServiceActionRunning(hostId, projectName) {
  const prefix = `${hostId}::${projectName}::`;
  for (const [key, actions] of state.serviceActionProgress.entries()) {
    if (actions.size && key.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}
function deriveOverallStatus(statuses) {
  const normalized = statuses.filter((status) => status);
  if (!normalized.length) {
    return "unknown";
  }
  if (normalized.every((status) => status === "up")) {
    return "up";
  }
  if (normalized.every((status) => status === "down" || status === "unknown")) {
    return normalized.includes("down") ? "down" : "unknown";
  }
  if (normalized.includes("degraded")) {
    return "degraded";
  }
  return "degraded";
}

function updateLocalServiceStatus(hostId, projectName, serviceName, status) {
  if (!state.stateSnapshot?.hosts) {
    return;
  }
  const host = state.stateSnapshot.hosts.find((item) => item.host_id === hostId);
  if (!host) {
    return;
  }
  const project = host.projects?.find((item) => item.project === projectName);
  if (!project) {
    return;
  }
  const services = Array.isArray(project.services) ? project.services : [];
  let service = services.find((item) => item.id === serviceName);
  if (!service) {
    service = { id: serviceName };
    services.push(service);
    project.services = services;
  }
  const now = new Date().toISOString();
  service.status = status;
  service.refreshed_at = now;
  const statuses = services.map((item) => item.status);
  project.overall_status = deriveOverallStatus(statuses);
  project.refreshed_at = now;
}

function _isContainerRunning(container) {
  const state = (container?.state || "").toLowerCase();
  const status = (container?.status || "").toLowerCase();
  return state === "running" || status.startsWith("up");
}

function _deriveServiceStatus(containers) {
  if (!containers.length) {
    return "unknown";
  }
  let runningCount = 0;
  containers.forEach((container) => {
    if (_isContainerRunning(container)) {
      runningCount += 1;
    }
  });
  if (runningCount === containers.length) {
    return "up";
  }
  if (runningCount === 0) {
    return "down";
  }
  return "degraded";
}

function _deriveServiceStatuses(containers) {
  const grouped = {};
  containers.forEach((container) => {
    const service = container?.service || container?.name || "unknown";
    if (!grouped[service]) {
      grouped[service] = [];
    }
    grouped[service].push(container);
  });
  const statuses = {};
  Object.entries(grouped).forEach(([service, items]) => {
    statuses[service] = _deriveServiceStatus(items);
  });
  return statuses;
}

function updateLocalProjectStatus(hostId, projectName, status, options = {}) {
  if (!state.stateSnapshot?.hosts) {
    return;
  }
  const host = state.stateSnapshot.hosts.find((item) => item.host_id === hostId);
  if (!host) {
    return;
  }
  if (!Array.isArray(host.projects)) {
    host.projects = [];
  }
  let project = host.projects.find((item) => item.project === projectName);
  if (!project) {
    project = { project: projectName, services: [] };
    host.projects.push(project);
  }
  const now = new Date().toISOString();
  const containers = Array.isArray(status?.containers) ? status.containers : [];
  const serviceStatuses = _deriveServiceStatuses(containers);
  const services = Array.isArray(project.services) ? project.services : [];
  Object.entries(serviceStatuses).forEach(([serviceName, serviceStatus]) => {
    let service = services.find((item) => item.id === serviceName);
    if (!service) {
      service = { id: serviceName };
      services.push(service);
    }
    service.status = serviceStatus;
    service.refreshed_at = now;
  });
  if (!Object.keys(serviceStatuses).length && status?.overall_status === "down") {
    services.forEach((service) => {
      service.status = "down";
      service.refreshed_at = now;
    });
  }
  project.services = services;
  const statusValues = Object.values(serviceStatuses);
  project.overall_status = status?.overall_status || deriveOverallStatus(statusValues);
  project.refreshed_at = now;
  if (options.clearUpdates) {
    project.updates_available = false;
  }
}

async function refreshProjectStatusAfterAction(hostId, projectName, options = {}) {
  try {
    await api.post(`/hosts/${hostId}/projects/${projectName}/state/refresh`);
  } catch (err) {
    console.error("Project refresh failed", err);
  }
  try {
    const status = await api.get(`/hosts/${hostId}/projects/${projectName}/status`);
    updateLocalProjectStatus(hostId, projectName, status, options);
    if (options.render !== false) {
      renderProjectList();
    }
  } catch (err) {
    console.error("Project status load failed", err);
  }
}


function renderHostList() {
  if (hostList) {
    hostList.innerHTML = "";
  }
  if (hostTableBody) {
    hostTableBody.innerHTML = "";
  }
  const isCompact = document.body.classList.contains("compact-mode");
  const listTarget = isCompact && hostTableBody ? hostTableBody : hostList;
  const rowTemplate =
    isCompact && hostTableRowTemplate ? hostTableRowTemplate : hostRowTemplate;
  if (!listTarget || !rowTemplate) {
    return;
  }
  if (!state.hosts.length) {
    if (listTarget === hostList) {
      const empty = document.createElement("li");
      empty.className = "list-row empty";
      empty.textContent = "No hosts configured.";
      listTarget.appendChild(empty);
    } else {
      const empty = document.createElement("tr");
      empty.className = "list-row empty";
      const emptyCell = document.createElement("td");
      emptyCell.colSpan = 2;
      emptyCell.textContent = "No hosts configured.";
      empty.appendChild(emptyCell);
      listTarget.appendChild(empty);
    }
    return;
  }

  const hostIds = new Set(state.hosts.map((host) => host.host_id));
  const stateByHost = getStateByHost();
  state.hostActionProgress.forEach((_, hostId) => {
    if (!hostIds.has(hostId)) {
      state.hostActionProgress.delete(hostId);
    }
  });

  state.hosts.forEach((host) => {
    const row = rowTemplate.content.firstElementChild.cloneNode(true);
    row.querySelector(".host-name").textContent = host.host_id;
    const projectCountText = host.projects?.length ?? Object.keys(host.project_paths || {}).length;
    row.querySelector(".host-meta").textContent = `${host.user}@${host.host}:${host.port} • ${projectCountText} projects`;

    const allowHostActions = canManageProjects();

    const refreshBtn = row.querySelector(".refresh-host");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () =>
        runHostQuickAction(refreshBtn, host.host_id, "refresh", () =>
          refreshHost(host.host_id)
        )
      );
      setButtonAccess(
        refreshBtn,
        allowHostActions,
        "Requires admin or power user.",
        { hideOnDeny: true }
      );
    }
    const scanBtn = row.querySelector(".scan-host");
    if (scanBtn) {
      scanBtn.addEventListener("click", () =>
        runHostQuickAction(scanBtn, host.host_id, "scan", () =>
          scanHostProjects(host.host_id)
        )
      );
      setButtonAccess(scanBtn, allowHostActions, "Requires admin or power user.", {
        hideOnDeny: true,
      });
    }
    const sleepBtn = row.querySelector(".sleep-host");
    const wakeBtn = row.querySelector(".wake-host");
    const hostState = stateByHost[host.host_id];
    let hasSleeping = false;
    let hasAwake = false;
    if (hostState && Array.isArray(hostState.projects)) {
      hostState.projects.forEach((project) => {
        if (project.sleeping) {
          hasSleeping = true;
        } else {
          hasAwake = true;
        }
      });
    } else {
      const projectCount =
        host.projects?.length ?? Object.keys(host.project_paths || {}).length;
      if (projectCount > 0) {
        hasAwake = true;
      }
    }
    if (sleepBtn) {
      sleepBtn.classList.toggle("hidden", !hasAwake);
      sleepBtn.addEventListener("click", () =>
        runHostAction(sleepBtn, host.host_id, "sleep")
      );
      setButtonAccess(sleepBtn, allowHostActions, "Requires admin or power user.", {
        hideOnDeny: true,
      });
    }
    if (wakeBtn) {
      wakeBtn.classList.toggle("hidden", !hasSleeping);
      wakeBtn.addEventListener("click", () =>
        runHostAction(wakeBtn, host.host_id, "wake")
      );
      setButtonAccess(wakeBtn, allowHostActions, "Requires admin or power user.", {
        hideOnDeny: true,
      });
    }

    const hostActions = getHostActionProgress(host.host_id);
    if (sleepBtn) {
      setActionRunning(sleepBtn, hostActions.has("sleep"));
    }
    if (wakeBtn) {
      setActionRunning(wakeBtn, hostActions.has("wake"));
    }
    if (refreshBtn) {
      setActionRunning(refreshBtn, hostActions.has("refresh"));
    }
    if (scanBtn) {
      setActionRunning(scanBtn, hostActions.has("scan"));
    }
    listTarget.appendChild(row);
  });
}

function renderProjectList() {
  projectList.innerHTML = "";
  const isCompact = document.body.classList.contains("compact-mode");
  if (!state.actionMenuListenerBound) {
    document.addEventListener("click", () => closeAllActionMenus());
    state.actionMenuListenerBound = true;
  }
  const allEntries = buildProjectEntries();
  const visibleEntries = sortProjectEntries(applyProjectFilters(allEntries));
  const availableKeys = new Set(allEntries.map((entry) => entry.key));
  syncProjectSelection(availableKeys);
  syncBackupCancelled(availableKeys);
  syncActionProgress(availableKeys);
  const availableServiceKeys = new Set();
  allEntries.forEach((entry) => {
    entry.services.forEach((service) => {
      const serviceName = service.id || "unknown";
      availableServiceKeys.add(serviceActionKey(entry.hostId, entry.projectName, serviceName));
    });
  });
  syncServiceActionProgress(availableServiceKeys);

  if (isCompact) {
    projectCount.textContent = `${visibleEntries.length} projects`;
  } else {
    projectCount.textContent = `${visibleEntries.length} projects • ${countSelectedVisible(
      visibleEntries
    )} selected`;
  }
  updateProjectSelectToggle(visibleEntries);
  updateProjectSortIndicators();

  if (!visibleEntries.length) {
    const empty = document.createElement("tr");
    empty.className = "list-row empty";
    const emptyCell = document.createElement("td");
    emptyCell.colSpan = isCompact ? 4 : 6;
    emptyCell.textContent = allEntries.length
      ? "No projects match filters."
      : "No projects available.";
    empty.appendChild(emptyCell);
    projectList.appendChild(empty);
    return;
  }

    visibleEntries.forEach((entry) => {
      const row = projectRowTemplate.content.firstElementChild.cloneNode(true);
      row.dataset.projectKey = entry.key;
      const restoreLocked = state.restoreInProgress && state.restoreLockedProjects.has(entry.key);
      const allowProjectActions = canManageProjects();
      row.dataset.allowProjectActions = allowProjectActions ? "true" : "false";
      const allowBackupAction = isAdminRole();
      const allowComposeEdit = canEditCompose();
      const allowDeleteProject = canDeleteProject();
      const allowComposeCommand = canManageProjects();
      const checkbox = row.querySelector(".project-checkbox");
    checkbox.checked = state.selectedProjects.has(entry.key);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        state.selectedProjects.add(entry.key);
      } else {
        state.selectedProjects.delete(entry.key);
      }
      if (isCompact) {
        projectCount.textContent = `${visibleEntries.length} projects`;
      } else {
        projectCount.textContent = `${visibleEntries.length} projects • ${countSelectedVisible(
          visibleEntries
        )} selected`;
      }
      updateBulkVisibility();
    });

    const nameCell = row.querySelector(".project-name");
    nameCell.textContent = entry.displayName || entry.projectName;
    if (restoreLocked) {
      const badge = document.createElement("span");
      badge.className = "restore-badge";
      badge.textContent = "Restoring";
      badge.title = "Restore in progress";
      nameCell.appendChild(badge);
    }

    const statusInfo = projectStatusLabel(entry.status);
    const updatesInfo = updateBadgeLabel(entry.updatesAvailable);

    const deleteBtn = row.querySelector(".project-delete");
    if (deleteBtn) {
      if (!allowDeleteProject) {
        deleteBtn.classList.add("hidden");
      } else {
        deleteBtn.disabled = restoreLocked;
        deleteBtn.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          closeAllActionMenus();
          openDeleteProjectModal(entry.hostId, entry.projectName);
        });
      }
    }

    const detailsBtn = row.querySelector(".project-details");
    if (detailsBtn) {
      detailsBtn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openProjectDetailsModal(entry);
      });
    }

    const actionMenuToggle = row.querySelector(".action-menu-toggle");
    const actionMenuPanel = row.querySelector(".action-menu-panel");
    if (actionMenuToggle && actionMenuPanel) {
      actionMenuToggle.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const willOpen = actionMenuPanel.classList.contains("hidden");
        closeAllActionMenus(actionMenuPanel);
        actionMenuPanel.classList.toggle("hidden", !willOpen);
      });
      actionMenuPanel.addEventListener("click", (event) => {
        event.stopPropagation();
      });
      if (restoreLocked) {
        actionMenuToggle.disabled = true;
        actionMenuToggle.dataset.forceDisabled = "true";
        actionMenuPanel.classList.add("hidden");
      } else {
        actionMenuToggle.disabled = false;
        actionMenuToggle.dataset.forceDisabled = "";
      }
    }

    const statusIcon = row.querySelector(".status-icon");
    statusIcon.classList.remove("up", "down", "degraded", "unknown");
    if (statusInfo.className) {
      statusIcon.classList.add(statusInfo.className);
    } else {
      statusIcon.classList.add("unknown");
    }
    statusIcon.textContent = statusIconName(statusInfo.className);
    statusIcon.title = `Status: ${statusInfo.label}`;

    const updatesIcon = row.querySelector(".updates-icon");
    const updatesLink = row.querySelector(".updates-link");
    const updatesCell = row.querySelector(".project-cell.project-updates");
    if (updatesLink && updatesCell && updatesLink.parentElement !== updatesCell) {
      updatesCell.appendChild(updatesLink);
    }
    if (updatesLink) {
      updatesLink.classList.remove("compact-updates");
    }
    const showUpdates = state.updatesEnabled && updatesInfo.className === "updates-yes";
    updatesIcon.classList.remove("yes");
    if (!state.updatesEnabled) {
      updatesIcon.textContent = "";
      updatesIcon.title = "Updates disabled";
      updatesIcon.classList.add("hidden");
      if (updatesLink) {
        updatesLink.classList.add("hidden");
        updatesLink.classList.remove("no-link");
      }
    } else if (showUpdates) {
      updatesIcon.classList.add("yes");
      updatesIcon.textContent = "published_with_changes";
      updatesIcon.title = "Updates available";
      updatesIcon.classList.remove("hidden");
      if (updatesLink) {
        updatesLink.classList.remove("hidden");
        updatesLink.classList.remove("no-link");
      }
    } else {
      updatesIcon.textContent = "";
      updatesIcon.title = "Updates: none";
      updatesIcon.classList.add("hidden");
      if (updatesLink) {
        updatesLink.classList.add("hidden");
        updatesLink.classList.remove("no-link");
      }
    }

    const sleepingIcon = row.querySelector(".sleep-icon");
    if (entry.sleeping) {
      sleepingIcon.textContent = "bedtime";
      sleepingIcon.title = "Sleeping";
      sleepingIcon.classList.add("active");
      sleepingIcon.classList.remove("hidden");
    } else {
      sleepingIcon.textContent = "";
      sleepingIcon.title = "Sleeping";
      sleepingIcon.classList.remove("active");
      sleepingIcon.classList.add("hidden");
    }

    const actionStates = getActionProgress(entry.key);
    let serviceActionActive = false;
    const projectRunning = statusInfo.className === "up" || statusInfo.className === "degraded";
    row.dataset.projectRunning = projectRunning ? "true" : "false";
    const startRunning = actionStates.has("start");
    const stopRunning = actionStates.has("stop");
    const restartRunning =
      actionStates.has("restart") || actionStates.has("hard_restart");
    const updateRunning = actionStates.has("update");
    const backupRunning = actionStates.has("backup");
    const refreshRunning = actionStates.has("refresh");

    const shiftActive = document.body?.classList.contains("hard-restart-active");
    const shiftOverride = Boolean(
      shiftActive && projectRunning && !state.shiftStartLocks.has(entry.key)
    );

    const startBtn = row.querySelector(".project-action[data-action=\"start\"]");
    const stopBtn = row.querySelector(".project-action[data-action=\"stop\"]");
    const restartBtn = row.querySelector(".project-action[data-action=\"restart\"]");
    const updateBtn = row.querySelector(".project-action[data-action=\"update\"]");
    const backupBtn = row.querySelector(".project-action[data-action=\"backup\"]");
    const refreshBtn = row.querySelector(".project-action[data-action=\"refresh\"]");

    let showStart = startRunning || !projectRunning;
    let showStop = stopRunning || projectRunning;
    if (shiftOverride && !stopRunning) {
      showStart = true;
      showStop = false;
    }
    const showRestart = restartRunning || projectRunning;

    if (startBtn) {
      startBtn.classList.add("action-ready");
      startBtn.dataset.forceDisabled =
        restoreLocked || !allowProjectActions ? "true" : "";
      if (!allowProjectActions) {
        startBtn.disabled = true;
      }
      setActionRunning(startBtn, startRunning);
      startBtn.classList.toggle("shift-start", shiftOverride);
      startBtn.classList.toggle("hidden", !allowProjectActions || !showStart);
    }
    if (stopBtn) {
      stopBtn.classList.add("action-ready");
      stopBtn.dataset.forceDisabled =
        restoreLocked || !allowProjectActions ? "true" : "";
      if (!allowProjectActions) {
        stopBtn.disabled = true;
      }
      setActionRunning(stopBtn, stopRunning);
      stopBtn.classList.toggle("hidden", !allowProjectActions || !showStop);
    }
    if (restartBtn) {
      restartBtn.classList.add("action-ready");
      restartBtn.dataset.forceDisabled =
        restoreLocked || !allowProjectActions ? "true" : "";
      if (!allowProjectActions) {
        restartBtn.disabled = true;
      }
      setActionRunning(restartBtn, restartRunning);
      restartBtn.classList.toggle("hidden", !allowProjectActions || !showRestart);
    }
    if (updateBtn) {
      updateBtn.classList.add("action-ready");
      updateBtn.dataset.forceDisabled =
        restoreLocked || !allowProjectActions ? "true" : "";
      if (!allowProjectActions) {
        updateBtn.disabled = true;
      }
      setActionRunning(updateBtn, updateRunning);
      updateBtn.classList.toggle("shift-update", shiftActive && state.updatesEnabled);
      updateBtn.classList.toggle("hidden", !allowProjectActions);
    }
    if (backupBtn) {
      backupBtn.classList.add("action-ready");
      const forceDisabled =
        restoreLocked || !state.backupTargetsAvailable || !allowBackupAction;
      backupBtn.dataset.forceDisabled = forceDisabled ? "true" : "";
      if (forceDisabled) {
        backupBtn.disabled = true;
      }
      setActionRunning(backupBtn, backupRunning);
      backupBtn.classList.toggle("hidden", !allowBackupAction);
    }
    if (refreshBtn) {
      refreshBtn.classList.add("action-ready");
      refreshBtn.dataset.forceDisabled =
        restoreLocked || !allowProjectActions ? "true" : "";
      if (!allowProjectActions) {
        refreshBtn.disabled = true;
      }
      setActionRunning(refreshBtn, refreshRunning);
      refreshBtn.classList.toggle("hidden", !allowProjectActions);
    }

    const servicesSummary = row.querySelector(".services-summary");
    const servicesText = row.querySelector(".services-text");
    if (entry.serviceCount) {
      servicesText.textContent = `${entry.serviceCount} service${entry.serviceCount === 1 ? "" : "s"}`;
    } else {
      servicesText.textContent = "No service status available";
    }

    const servicesPanel = row.querySelector(".services-panel");
    const servicesList = row.querySelector(".services-list");
    servicesList.innerHTML = "";

    if (!entry.services.length) {
      const emptyItem = document.createElement("li");
      emptyItem.className = "service-item";
      emptyItem.textContent = "No service status available.";
      servicesList.appendChild(emptyItem);
    } else {
      entry.services.forEach((service) => {
        const info = serviceStatusInfo(service);
        const item = document.createElement("li");
        item.className = "service-item";

        const details = document.createElement("div");
        const title = document.createElement("div");
        title.className = "service-title";
        const name = document.createElement("div");
        name.className = "service-name";
        const serviceName = service.id || "unknown";
        const encodedService = encodeURIComponent(serviceName);
        name.textContent = serviceName;
        const links = document.createElement("div");
        links.className = "service-links";
        const addServiceLink = (url, icon, label) => {
          if (!url) {
            return;
          }
          const link = document.createElement("a");
          link.className = "service-link";
          link.href = url;
          link.target = "_blank";
          link.rel = "noopener";
          link.title = label;
          link.setAttribute("aria-label", label);
          const iconSpan = document.createElement("span");
          iconSpan.className = "material-symbols-outlined service-link-icon";
          iconSpan.textContent = icon;
          link.appendChild(iconSpan);
          links.appendChild(link);
        };
        addServiceLink(service.project_url, "folder_code", "Project URL");
        addServiceLink(service.source_url, "box", "Source");
        addServiceLink(service.documentation_url, "quick_reference", "Documentation");
        links.classList.toggle("hidden", !links.childElementCount);
        title.appendChild(name);
        title.appendChild(links);
        const meta = document.createElement("div");
        meta.className = "service-meta";


        details.appendChild(title);
        details.appendChild(meta);

        const badge = document.createElement("span");
        badge.className = `material-symbols-outlined status-icon service-status-icon ${info.className}`;
        badge.textContent = statusIconName(info.className);
        badge.title = `Status: ${info.label}`;

        const rawHealthStatus = (service.health_status || "").toLowerCase();
        const healthStatus = rawHealthStatus || "unknown";
        const healthLabel = rawHealthStatus ? rawHealthStatus : "not reported";
        const healthIcon = document.createElement("span");
        healthIcon.className = `material-symbols-outlined service-health-icon health-${healthStatus}`;
        healthIcon.textContent = healthIconName(healthStatus);
        healthIcon.title = `Health: ${healthLabel}`;

        const updatesIcon = document.createElement("span");
        updatesIcon.className = "material-symbols-outlined updates-icon service-updates-icon";
        const updatesLink = document.createElement("span");
        updatesLink.className = "updates-link service-updates-link";
        updatesLink.appendChild(updatesIcon);
        if (state.updatesEnabled && service.update_available) {
          updatesIcon.classList.add("yes");
          updatesIcon.textContent = "published_with_changes";
          updatesIcon.title = "Updates available";
          updatesLink.classList.remove("hidden");
          updatesLink.classList.remove("no-link");
        } else {
          updatesIcon.classList.add("hidden");
          updatesIcon.textContent = "";
          updatesIcon.title = state.updatesEnabled ? "Updates: none" : "Updates disabled";
          updatesLink.classList.add("hidden");
          updatesLink.classList.remove("no-link");
        }

        const iconsWrap = document.createElement("div");
        iconsWrap.className = "service-icons";
        iconsWrap.appendChild(badge);
        if (healthIcon) {
          iconsWrap.appendChild(healthIcon);
        }
        iconsWrap.appendChild(updatesLink);
        meta.appendChild(iconsWrap);

        const actions = document.createElement("div");
        actions.className = "service-actions";

        const actionStateKey = serviceActionKey(entry.hostId, entry.projectName, serviceName);
        const serviceActions = getServiceActionProgress(actionStateKey);
        if (serviceActions.size) {
          serviceActionActive = true;
          item.classList.add("action-running");
        } else {
          item.classList.remove("action-running");
        }
        const serviceRunning = info.className === "up" || info.className === "degraded";
        const allowServiceActions = allowProjectActions;
        const startRunning = serviceActions.has("start");
        const stopRunning = serviceActions.has("stop");
        const restartRunning =
          serviceActions.has("restart") || serviceActions.has("hard_restart");

        const createServiceActionButton = (icon, label, action) => {
          const button = document.createElement("button");
          button.className = "btn ghost action-ready service-action";
          button.dataset.action = action;
          button.setAttribute("aria-label", label);
          button.title = label;
          const iconSpan = document.createElement("span");
          iconSpan.className = "material-symbols-outlined action-icon";
          iconSpan.textContent = icon;
          button.appendChild(iconSpan);
          if (restoreLocked) {
            button.disabled = true;
            button.dataset.forceDisabled = "true";
          }
          button.addEventListener("click", (event) =>
            runServiceAction(
              button,
              entry.hostId,
              entry.projectName,
              serviceName,
              action,
              event
            )
          );
          return button;
        };

        const startBtn = createServiceActionButton(
          "play_arrow",
          "Start service",
          "start"
        );
        const stopBtn = createServiceActionButton(
          "stop",
          "Stop service",
          "stop"
        );
        const restartBtn = createServiceActionButton(
          "restart_alt",
          "Restart service",
          "restart"
        );

        const showStart = startRunning || !serviceRunning;
        const showStop = stopRunning || serviceRunning;
        const showRestart = restartRunning || serviceRunning;

        setActionRunning(startBtn, startRunning);
        setActionRunning(stopBtn, stopRunning);
        setActionRunning(restartBtn, restartRunning);

        startBtn.classList.toggle("hidden", !allowServiceActions || !showStart);
        stopBtn.classList.toggle("hidden", !allowServiceActions || !showStop);
        restartBtn.classList.toggle("hidden", !allowServiceActions || !showRestart);

        const shellBtn = document.createElement("button");
        shellBtn.className = "btn ghost service-action";
        shellBtn.setAttribute("aria-label", "Service shell");
        shellBtn.title = "Open shell";
        const shellIcon = document.createElement("span");
        shellIcon.className = "material-symbols-outlined action-icon";
        shellIcon.textContent = "terminal";
        shellBtn.appendChild(shellIcon);
        if (!allowServiceActions) {
          shellBtn.classList.add("hidden");
        } else if (restoreLocked) {
          shellBtn.disabled = true;
        }
        shellBtn.addEventListener("click", () =>
          openShellModal(entry.hostId, entry.projectName, serviceName)
        );

        const logsBtn = document.createElement("button");
        logsBtn.className = "btn ghost service-action";
        logsBtn.setAttribute("aria-label", "Service logs");
        logsBtn.title = "Service logs";
        const logsIcon = document.createElement("span");
        logsIcon.className = "material-symbols-outlined action-icon";
        logsIcon.textContent = "article";
        logsBtn.appendChild(logsIcon);
        if (restoreLocked) {
          logsBtn.disabled = true;
        }
        logsBtn.addEventListener("click", () =>
          openLogsModal(entry.hostId, entry.projectName, serviceName)
        );

        actions.appendChild(startBtn);
        actions.appendChild(stopBtn);
        actions.appendChild(restartBtn);
        if (serviceRunning) {
          actions.appendChild(shellBtn);
        }
        actions.appendChild(logsBtn);

        item.appendChild(details);
        item.appendChild(actions);
        servicesList.appendChild(item);
      });
    }

    row.classList.toggle(
      "action-running",
      actionStates.size > 0 || serviceActionActive
    );
    row.classList.toggle("restore-running", restoreLocked);

    servicesSummary.addEventListener("click", () => {
      const isHidden = servicesPanel.classList.toggle("hidden");
      servicesSummary.classList.toggle("open", !isHidden);
    });

    row.querySelectorAll(".project-action").forEach((actionBtn) => {
      const action = actionBtn.dataset.action;
      if (!action) {
        return;
      }
      actionBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        const resolvedAction =
          action === "restart" && event.shiftKey ? "hard_restart" : action;
        runProjectAction(actionBtn, entry.hostId, entry.projectName, resolvedAction);
      });
    });

    const logsBtn = row.querySelector(".logs");
    logsBtn.disabled = restoreLocked;
    logsBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      closeAllActionMenus();
      openLogsModal(entry.hostId, entry.projectName);
    });

    const composeBtn = row.querySelector(".compose");
    if (composeBtn) {
      if (!allowComposeEdit) {
        composeBtn.classList.add("hidden");
      } else {
        composeBtn.disabled = restoreLocked;
        composeBtn.addEventListener("click", (event) => {
          event.stopPropagation();
          closeAllActionMenus();
          openComposeModal(entry.hostId, entry.projectName);
        });
      }
    }

    const commandBtn = row.querySelector(".compose-command");
    if (commandBtn) {
      if (!allowComposeCommand) {
        commandBtn.classList.add("hidden");
      } else {
        commandBtn.disabled = restoreLocked;
        commandBtn.addEventListener("click", (event) => {
          event.stopPropagation();
          closeAllActionMenus();
          openCommandModal(entry.hostId, entry.projectName);
        });
      }
    }

    projectList.appendChild(row);
  });
  updateBulkVisibility();
  updateBulkBackupAvailability();
  updateShiftStartButtons();
}

function renderLists() {
  renderHostList();
  renderProjectList();
}

function formatBackupStep(step, message) {
  if (message) {
    return message;
  }
  const labels = {
    checking: "Checking status",
    stopping: "Stopping project",
    backup: "Running backup",
    starting: "Starting project",
    start_failed: "Start failed",
    stopped: "Backup stopped",
  };
  return labels[step] || "Working...";
}

function backupStepIndex(step) {
  const order = {
    checking: 0,
    stopping: 1,
    backup: 2,
    starting: 3,
    start_failed: 3,
    stopped: 3,
  };
  return order[step] === undefined ? 0 : order[step];
}

function runBackupStream(hostId, projectName, onStep) {
  return new Promise((resolve, reject) => {
    let finished = false;
    const finish = (err) => {
      if (finished) return;
      finished = true;
      stream.close();
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    };

    const stream = createEventStream(
      `/hosts/${hostId}/projects/${projectName}/backup/stream`,
      {
        onEvent: (eventName, data) => {
          if (eventName === "step") {
            let payload = { step: "working", message: data };
            try {
              payload = JSON.parse(data);
            } catch (err) {
              payload = { step: "working", message: data };
            }
            if (onStep) {
              onStep(payload);
            }
            return;
          }
          if (eventName === "complete") {
            let payload = { step: "complete", message: "Backup complete" };
            try {
              payload = JSON.parse(data);
            } catch (err) {
              payload = { step: "complete", message: "Backup complete" };
            }
            if (onStep) {
              onStep({
                step: "complete",
                message: payload.message,
                stopped: payload.stopped,
              });
            }
            finish();
            return;
          }
          if (eventName === "backup_error") {
            let message = data || "Backup failed.";
            try {
              const payload = JSON.parse(data);
              message = payload.message || message;
            } catch (err) {
              message = data || message;
            }
            finish(new Error(message));
          }
        },
        onError: (err) => {
          finish(err || new Error("Backup stream closed."));
        },
      }
    );
  });
}

function runActionStream(hostId, projectName, action, onStep) {
  return new Promise((resolve, reject) => {
    let finished = false;
    const finish = (err, payload) => {
      if (finished) return;
      finished = true;
      stream.close();
      if (err) {
        reject(err);
      } else {
        resolve(payload);
      }
    };

    const stream = createEventStream(
      `/hosts/${hostId}/projects/${projectName}/actions/${action}/stream`,
      {
        onEvent: (eventName, data) => {
          if (eventName === "step") {
            let payload = { step: "working", message: data };
            try {
              payload = JSON.parse(data);
            } catch (err) {
              payload = { step: "working", message: data };
            }
            if (onStep) {
              onStep(payload);
            }
            return;
          }
          if (eventName === "complete") {
            let payload = { step: "complete", message: "Action complete" };
            try {
              payload = JSON.parse(data);
            } catch (err) {
              payload = { step: "complete", message: "Action complete" };
            }
            if (onStep) {
              onStep({
                step: "complete",
                message: payload.message,
                stopped: payload.stopped,
              });
            }
            finish(null, payload);
            return;
          }
          if (eventName === "action_error") {
            let message = data || "Action failed.";
            try {
              const payload = JSON.parse(data);
              message = payload.message || message;
            } catch (err) {
              message = data || message;
            }
            finish(new Error(message));
          }
        },
        onError: (err) => {
          finish(err || new Error("Action stream closed."));
        },
      }
    );
  });
}

function runServiceActionStream(hostId, projectName, serviceName, action, onStep) {
  return new Promise((resolve, reject) => {
    const encodedService = encodeURIComponent(serviceName);
    let finished = false;
    const finish = (err, payload) => {
      if (finished) return;
      finished = true;
      stream.close();
      if (err) {
        reject(err);
      } else {
        resolve(payload);
      }
    };

    const stream = createEventStream(
      `/hosts/${hostId}/projects/${projectName}/services/${encodedService}/actions/${action}/stream`,
      {
        onEvent: (eventName, data) => {
          if (eventName === "step") {
            let payload = { step: "working", message: data };
            try {
              payload = JSON.parse(data);
            } catch (err) {
              payload = { step: "working", message: data };
            }
            if (onStep) {
              onStep(payload);
            }
            return;
          }
          if (eventName === "complete") {
            let payload = { step: "complete", message: "Action complete" };
            try {
              payload = JSON.parse(data);
            } catch (err) {
              payload = { step: "complete", message: "Action complete" };
            }
            if (onStep) {
              onStep({
                step: "complete",
                message: payload.message,
                stopped: payload.stopped,
              });
            }
            finish(null, payload);
            return;
          }
          if (eventName === "action_error") {
            let message = data || "Action failed.";
            try {
              const payload = JSON.parse(data);
              message = payload.message || message;
            } catch (err) {
              message = data || message;
            }
            finish(new Error(message));
          }
        },
        onError: (err) => {
          finish(err || new Error("Action stream closed."));
        },
      }
    );
  });
}



function selectAllProjects() {
  const entries = getVisibleProjectEntries();
  state.selectedProjects = new Set(entries.map((entry) => entry.key));
  renderProjectList();
}

function clearProjects() {
  state.selectedProjects = new Set();
  renderProjectList();
}

function updateProjectSelectToggle(visibleEntries) {
  if (!projectSelectToggle) {
    return;
  }
  if (!visibleEntries.length) {
    projectSelectToggle.checked = false;
    projectSelectToggle.indeterminate = false;
    projectSelectToggle.disabled = true;
    return;
  }
  projectSelectToggle.disabled = false;
  const selectedCount = countSelectedVisible(visibleEntries);
  projectSelectToggle.checked =
    selectedCount > 0 && selectedCount === visibleEntries.length;
  projectSelectToggle.indeterminate =
    selectedCount > 0 && selectedCount < visibleEntries.length;
}

function getSelectedProjectEntries() {
  const entries = buildProjectEntries();
  return entries.filter((entry) => state.selectedProjects.has(entry.key));
}

function clearProjectFilters() {
  if (projectFilterName) {
    projectFilterName.value = "";
  }
  if (headerFilterHosts) {
    Array.from(headerFilterHosts.options).forEach((option) => {
      option.selected = false;
    });
  }
  if (headerFilterStatus) {
    headerFilterStatus.value = "all";
  }
  if (headerFilterUpdates) {
    headerFilterUpdates.value = "all";
  }
  updateProjectFilterState();
  updateProjectFilterIndicators();
  renderProjectList();
}


async function runProjectAction(button, hostId, projectName, action) {
  if (!canManageProjects()) {
    alert("Insufficient permissions for project actions.");
    return;
  }
  if (action === "backup" && !isAdminRole()) {
    alert("Admin access required for backups.");
    return;
  }
  const row = button.closest(".project-row");
  const label = formatActionLabel(action);
  const originalLabel = button.dataset.originalLabel || getActionLabel(button) || label;
  button.dataset.originalLabel = originalLabel;
  const isBackup = action === "backup";
  const projectKey = `${hostId}::${projectName}`;
  const shiftStartRequested =
    action === "start" &&
    row?.dataset.projectRunning === "true" &&
    document.body?.classList.contains("hard-restart-active");
  const shiftUpdateRequested =
    action === "update" &&
    state.updatesEnabled &&
    document.body?.classList.contains("hard-restart-active");
  const runningAction = button.dataset.runningAction || action;
  const isRunning = button.dataset.actionRunning === "true";

  if (isBackup && !state.backupTargetsAvailable) {
    showToast("No enabled backup targets.", "error");
    return;
  }

  if (isRunning) {
    button.disabled = true;
    const actionToStop = runningAction || action;
    try {
      if (actionToStop === "refresh") {
        return;
      }
      if (isBackup) {
        await api.post(`/hosts/${hostId}/projects/${projectName}/backup/stop`);
      } else {
        await api.post(
          `/hosts/${hostId}/projects/${projectName}/actions/${actionToStop}/stop`
        );
      }
    } catch (err) {
      alert(`Stop failed: ${err.message}`);
    } finally {
      if (button.dataset.forceDisabled !== "true") {
        button.disabled = false;
      }
    }
    return;
  }

  setActionRunning(button, true);
  button.dataset.runningAction = action;
  setActionProgress(projectKey, action, true);
  if (row) {
    row.classList.add("action-running");
  }
  let backupRow = null;
  let shouldRefresh = false;
  let skipProjectRefresh = false;
  let completionMessage = "";
  try {
    if (action === "refresh") {
      await api.post(
        `/hosts/${hostId}/projects/${projectName}/state/refresh`
      );
      shouldRefresh = true;
      completionMessage = "Refresh complete";
    } else if (shiftUpdateRequested) {
      const result = await api.get(
        `/hosts/${hostId}/projects/${projectName}/updates`
      );
      const updatesAvailable = Boolean(result?.updates_available);
      completionMessage = updatesAvailable ? "Updates available" : "Updates: none";
      shouldRefresh = true;
      skipProjectRefresh = true;
    } else if (action === "backup") {
      const target = `${hostId}/${projectName}`;
      const totalSteps = 3;
      backupRow = document.querySelector(
        `[data-project-key="${hostId}::${projectName}"]`
      );
      if (backupRow) {
        backupRow.classList.add("working");
      }
      state.backupCancelled.delete(projectKey);
      if (backupRow) {
        const cancelledBadge = backupRow.querySelector(".badge.cancelled");
        if (cancelledBadge) {
          cancelledBadge.classList.add("hidden");
        }
      }
      bulkProgress.classList.remove("hidden");
      let finalBackupMessage = "Backup complete";
      await runBackupStream(hostId, projectName, (payload) => {
        const stepLabel = formatBackupStep(payload.step, payload.message);
        const stepIndex = backupStepIndex(payload.step);
        if (payload.step === "complete") {
          if (payload.stopped) {
            state.backupCancelled.add(projectKey);
          } else {
            state.backupCancelled.delete(projectKey);
          }
          if (backupRow) {
            const cancelledBadge = backupRow.querySelector(".badge.cancelled");
            if (cancelledBadge) {
              cancelledBadge.classList.toggle("hidden", !payload.stopped);
            }
          }
          const finalLabel = payload.stopped ? "Backup stopped" : "Backup complete";
          bulkProgressText.textContent = `${finalLabel} • ${target}`;
          bulkProgressBar.style.width = "100%";
          finalBackupMessage = finalLabel;
          return;
        }
        bulkProgressText.textContent = `Backup • ${target} • ${stepLabel}`;
        bulkProgressBar.style.width = `${Math.round(
          (stepIndex / totalSteps) * 100
        )}%`;
      });
      if (!bulkProgressText.textContent) {
        bulkProgressText.textContent = `Backup complete • ${target}`;
        bulkProgressBar.style.width = "100%";
      }
      shouldRefresh = true;
      completionMessage = finalBackupMessage;
    } else {
      const result = await runActionStream(hostId, projectName, action);
      completionMessage = result?.message || `${label} complete`;
      shouldRefresh = true;
    }
    showToast(`${getProjectDisplayName(hostId, projectName)}: ${completionMessage}`);
  } catch (err) {
    alert(`Action failed: ${err.message}`);
  } finally {
    if (backupRow) {
      backupRow.classList.remove("working");
    }
    if (action === "backup") {
      setActionLabel(button, originalLabel);
    }
    setActionProgress(projectKey, action, false);
    if (row) {
      row.classList.toggle(
        "action-running",
        getActionProgress(projectKey).size > 0 || hasServiceActionRunning(hostId, projectName)
      );
    }
    setActionRunning(button, false);
    button.dataset.runningAction = "";
    if (shiftStartRequested && document.body?.classList.contains("hard-restart-active")) {
      state.shiftStartLocks.add(projectKey);
    }
    updateShiftStartButtons();
    if (!isBackup) {
      setActionLabel(button, originalLabel);
    }
    if (shouldRefresh) {
      if (action !== "refresh" && !skipProjectRefresh) {
        try {
          await api.post(`/hosts/${hostId}/projects/${projectName}/state/refresh`);
        } catch (err) {
          console.error("Project refresh failed", err);
        }
      }
      await loadState();
    }
  }
}

async function runServiceAction(
  button,
  hostId,
  projectName,
  serviceName,
  action,
  event
) {
  if (!canManageProjects()) {
    alert("Insufficient permissions for service actions.");
    return;
  }
  const serviceItem = button.closest(".service-item");
  const row = button.closest(".project-row");
  const isRunning = button.dataset.actionRunning === "true";
  const serviceKeyValue = serviceActionKey(hostId, projectName, serviceName);
  const encodedService = encodeURIComponent(serviceName);
  const resolvedAction =
    action === "restart" && event?.shiftKey ? "hard_restart" : action;
  const runningAction = button.dataset.runningAction || resolvedAction;

  if (isRunning) {
    button.disabled = true;
    const actionToStop = runningAction || resolvedAction;
    try {
      await api.post(
        `/hosts/${hostId}/projects/${projectName}/services/${encodedService}/actions/${actionToStop}/stop`
      );
    } catch (err) {
      alert(`Stop failed: ${err.message}`);
    } finally {
      if (button.dataset.forceDisabled !== "true") {
        button.disabled = false;
      }
    }
    return;
  }

  setActionRunning(button, true);
  button.dataset.runningAction = resolvedAction;
  setServiceActionProgress(serviceKeyValue, resolvedAction, true);
  if (serviceItem) {
    serviceItem.classList.add("action-running");
  }
  if (row) {
    row.classList.add("action-running");
  }
  let shouldRefresh = false;
  let completionMessage = "";
  try {
    const result = await runServiceActionStream(
      hostId,
      projectName,
      serviceName,
      resolvedAction
    );
    completionMessage = result?.message || "Action complete";
    shouldRefresh = true;
    const updatedStatus = resolvedAction === "stop" ? "down" : "up";
    updateLocalServiceStatus(hostId, projectName, serviceName, updatedStatus);
    renderProjectList();
    showToast(`${serviceName}: ${completionMessage}`);
  } catch (err) {
    alert(`Service action failed: ${err.message}`);
  } finally {
    setServiceActionProgress(serviceKeyValue, resolvedAction, false);
    button.dataset.runningAction = "";
    if (serviceItem) {
      serviceItem.classList.remove("action-running");
    }
    if (row) {
      row.classList.toggle(
        "action-running",
        getActionProgress(`${hostId}::${projectName}`).size > 0 || hasServiceActionRunning(hostId, projectName)
      );
    }
    setActionRunning(button, false);
    if (shouldRefresh) {
      try {
        await api.post(`/hosts/${hostId}/projects/${projectName}/state/refresh`);
      } catch (err) {
        console.error("Project refresh failed", err);
      }
      await loadState();
    }
  }
}


function bulkActionParticiple(action) {
  switch (action) {
    case "start":
      return "Starting";
    case "stop":
      return "Stopping";
    case "restart":
      return "Restarting";
    case "update":
      return "Updating";
    case "backup":
      return "Backing up";
    case "sleep":
      return "Sleeping";
    case "wake":
      return "Waking";
    case "restore":
      return "Restoring";
    case "hard_restart":
      return "Hard restarting";
    default:
      return `Running ${action}`;
  }
}

function formatBulkProgressText(action, current, total, currentTarget) {
  const label = bulkActionParticiple(action);
  const target = currentTarget ? ` ${currentTarget}` : "";
  return `${label}${target} (${current}/${total})`;
}

function setBulkProgress(action, current, total, currentTarget = "") {
  if (!total) {
    bulkProgress.classList.add("hidden");
    bulkProgressBar.style.width = "0%";
    bulkProgressText.textContent = "";
    return;
  }
  bulkProgressText.textContent = formatBulkProgressText(
    action,
    current,
    total,
    currentTarget
  );
  bulkProgressBar.style.width = `${Math.round((current / total) * 100)}%`;
  bulkProgress.classList.remove("hidden");
}


function updateBulkVisibility() {
  if (!bulkActions || !bulkActionsWrap) {
    return;
  }
  if (!canManageProjects()) {
    bulkActionsWrap.classList.add("hidden");
    setBulkProgress("", 0, 0);
    return;
  }
  const selectedCount = countSelectedVisible(getVisibleProjectEntries());
  if (selectedCount > 1) {
    bulkActionsWrap.classList.remove("hidden");
  } else {
    bulkActionsWrap.classList.add("hidden");
    setBulkProgress("", 0, 0);
  }
}

function updateBulkBackupAvailability() {
  updateBulkActionPermissions();
}

async function runBulkAction(action, event) {
  if (!canManageProjects()) {
    alert("Insufficient permissions for bulk actions.");
    return;
  }
  const selected = getSelectedProjectEntries();
  if (!selected.length) {
    alert("Select one or more projects first.");
    return;
  }
  const resolvedAction =
    action === "restart" && event?.shiftKey ? "hard_restart" : action;
  if (resolvedAction === "backup" && !isAdminRole()) {
    alert("Admin access required for backups.");
    return;
  }
  if (resolvedAction === "backup" && !state.backupTargetsAvailable) {
    alert("No enabled backup targets.");
    return;
  }

  const buttons = document.querySelectorAll(".bulk-action");
  buttons.forEach((btn) => {
    btn.disabled = true;
  });
  const actionLabel = formatActionLabel(resolvedAction);
  if (stateStatus) {
    stateStatus.textContent = `Running ${actionLabel} on ${selected.length} projects...`;
  }

  const failures = [];
  let completed = 0;
  const rows = document.querySelectorAll(".list-row.project-row");
  rows.forEach((row) => row.classList.remove("working"));
  for (const entry of selected) {
    const currentTarget = getProjectDisplayName(entry.hostId, entry.projectName);
    const row = document.querySelector(`[data-project-key="${entry.key}"]`);
    document
      .querySelectorAll(".list-row.project-row.working")
      .forEach((item) => item.classList.remove("working"));
    if (row) {
      row.classList.add("working");
    }
    let entryFailed = false;
    const currentIndex = completed + 1;
    setBulkProgress(resolvedAction, currentIndex, selected.length, currentTarget);
    const actionForButton = resolvedAction === "hard_restart" ? "restart" : resolvedAction;
    const shouldRefreshAction = ["start", "stop", "restart", "hard_restart", "update"].includes(resolvedAction);
    if (["start", "stop", "restart", "hard_restart", "update", "backup"].includes(resolvedAction)) {
      setActionProgress(entry.key, resolvedAction, true);
      const actionBtn = row?.querySelector(
        `.project-action[data-action="${actionForButton}"]`
      );
      if (actionBtn) {
        setActionRunning(actionBtn, true);
      }
    }
    try {
      if (resolvedAction === "backup") {
        state.backupCancelled.delete(entry.key);
        if (row) {
          const cancelledBadge = row.querySelector(".badge.cancelled");
          if (cancelledBadge) {
            cancelledBadge.classList.add("hidden");
          }
        }
        const totalSteps = 3;
        await runBackupStream(entry.hostId, entry.projectName, (payload) => {
          if (payload.step === "complete") {
            if (payload.stopped) {
              state.backupCancelled.add(entry.key);
            } else {
              state.backupCancelled.delete(entry.key);
            }
            if (row) {
              const cancelledBadge = row.querySelector(".badge.cancelled");
              if (cancelledBadge) {
                cancelledBadge.classList.toggle("hidden", !payload.stopped);
              }
            }
            bulkProgressText.textContent = formatBulkProgressText(
              resolvedAction,
              completed + 1,
              selected.length,
              currentTarget
            );
            bulkProgressBar.style.width = `${Math.round(
              ((completed + 1) / selected.length) * 100
            )}%`;
            return;
          }
          const stepIndex = backupStepIndex(payload.step);
          const fraction =
            (completed + stepIndex / totalSteps) / selected.length;
          bulkProgressText.textContent = formatBulkProgressText(
            resolvedAction,
            completed + 1,
            selected.length,
            currentTarget
          );
          bulkProgressBar.style.width = `${Math.round(fraction * 100)}%`;
          bulkProgress.classList.remove("hidden");
        });
      } else {
        await api.post(
          `/hosts/${entry.hostId}/projects/${entry.projectName}/${resolvedAction}`
        );
      }
    } catch (err) {
      entryFailed = true;
      failures.push(`${getProjectDisplayName(entry.hostId, entry.projectName)}: ${err.message}`);
    }
    const shouldRefresh = !entryFailed && shouldRefreshAction;
    if (shouldRefresh) {
      await refreshProjectStatusAfterAction(entry.hostId, entry.projectName, {
        clearUpdates: resolvedAction === "update",
        render: false,
      });
    }
    completed += 1;
    if (resolvedAction === "backup") {
      setBulkProgress("backup", completed, selected.length, currentTarget);
    } else {
      setBulkProgress(resolvedAction, completed, selected.length, currentTarget);
    }
    if (["start", "stop", "restart", "hard_restart", "update", "backup"].includes(resolvedAction)) {
      setActionProgress(entry.key, resolvedAction, false);
      const actionBtn = row?.querySelector(
        `.project-action[data-action="${actionForButton}"]`
      );
      if (actionBtn) {
        setActionRunning(actionBtn, false);
      }
    }
    if (row) {
      row.classList.remove("working");
    }
    if (shouldRefresh) {
      renderProjectList();
    }
  }

  buttons.forEach((btn) => {
    btn.disabled = false;
  });
  setBulkProgress(resolvedAction, 0, 0);

  const summaryAction = formatActionLabel(resolvedAction);
  const summaryMessage = failures.length
    ? `Bulk ${summaryAction} complete with errors`
    : `Bulk ${summaryAction} complete`;
  showToast(summaryMessage, failures.length ? "error" : "success");

  if (failures.length) {
    alert(`Some actions failed:\\n${failures.join("\\n")}`);
  }
}


async function refreshHosts(hostIds) {
  const uniqueHosts = Array.from(new Set(hostIds.filter(Boolean)));
  if (!uniqueHosts.length) {
    await loadState();
    return;
  }
  if (stateStatus) {
    stateStatus.textContent = `State: refreshing ${uniqueHosts.join(", ")}`;
  }
  try {
    for (const hostId of uniqueHosts) {
      await api.post(`/hosts/${hostId}/state/refresh`);
    }
  } catch (err) {
    if (stateStatus) {
      stateStatus.textContent = "State: refresh failed";
    }
    return;
  }
  await loadState();
}

async function refreshHost(hostId) {
  await refreshHosts([hostId]);
}

async function scanHostProjects(hostId) {
  try {
    const projects = await api.get(`/hosts/${hostId}/projects`);
    const index = state.hosts.findIndex((host) => host.host_id === hostId);
    if (index !== -1) {
      state.hosts[index] = { ...state.hosts[index], ...projects };
    }
    renderLists();
  } catch (err) {
    alert(`Failed to scan projects: ${err.message}`);
  }
}

async function runHostAction(button, hostId, action) {
  if (!canManageProjects()) {
    alert("Insufficient permissions for host actions.");
    return;
  }
  const label = action === "sleep" ? "Sleep" : "Wake";
  const runningLabel = action === "sleep" ? "Sleeping..." : "Waking...";
  const isRunning = button.dataset.actionRunning === "true";
  if (isRunning) {
    return;
  }

  setActionRunning(button, true);
  setHostActionProgress(hostId, action, true);
  button.disabled = true;
  if (stateStatus) {
    stateStatus.textContent = `${runningLabel} ${hostId}`;
  }
  let success = false;
  let response = null;
  try {
    response = await api.post(`/hosts/${hostId}/${action}`);
    success = true;
  } catch (err) {
    alert(`Host ${label.toLowerCase()} failed: ${err.message}`);
  } finally {
    setHostActionProgress(hostId, action, false);
    setActionRunning(button, false);
  }
  if (success) {
    showToast(`${hostId}: ${response?.output || `${label} complete`}`);
    await refreshHosts([hostId]);
  }
}

async function runHostQuickAction(button, hostId, action, handler) {
  if (!canManageProjects()) {
    alert("Insufficient permissions for host actions.");
    return;
  }
  const isRunning = button.dataset.actionRunning === "true";
  if (isRunning) {
    return;
  }
  setActionRunning(button, true);
  setHostActionProgress(hostId, action, true);
  button.disabled = true;
  try {
    await handler();
  } finally {
    setHostActionProgress(hostId, action, false);
    setActionRunning(button, false);
    button.disabled = false;
    if (!button.isConnected) {
      renderHostList();
    }
  }
}

async function loadState() {
  try {
    state.stateSnapshot = await api.get("/state");
    updateStateStatus();
  } catch (err) {
    if (stateStatus) {
      stateStatus.textContent = "State: unavailable";
    }
    state.stateSnapshot = null;
  }
  renderLists();
}

async function loadBackupScheduleStatus() {
  try {
    await api.get("/backup/schedule");
    state.backupScheduleAvailable = true;
    if (openBackupScheduleBtn) {
      openBackupScheduleBtn.disabled = false;
    }
  } catch (err) {
    state.backupScheduleAvailable = false;
    if (openBackupScheduleBtn) {
      openBackupScheduleBtn.disabled = false;
    }
  }
}

async function loadBackupTargetsAvailability() {
  try {
    const backups = await api.get("/config/backups");
    state.backupTargetsAvailable = backups.some((backup) => backup.enabled);
  } catch (err) {
    state.backupTargetsAvailable = false;
  }
  updateBulkBackupAvailability();
  if (state.initialized) {
    renderProjectList();
  }
}

async function loadHosts() {
  const hosts = await api.get("/hosts");
  const hostData = [];
  for (const host of hosts) {
    try {
      const projects = await api.get(`/hosts/${host.host_id}/projects`);
      hostData.push({ ...host, ...projects });
    } catch (err) {
      hostData.push({ ...host, projects: [], project_paths: {} });
    }
  }
  state.hosts = hostData;
  renderHostFilterOptions();
}

async function initApp(forceReload = false) {
  if (state.initialized && !forceReload) {
    return;
  }
  updateProjectFilterState();
  try {
    await loadHosts();
    updateProjectFilterIndicators();
    await loadBackupScheduleStatus();
    await loadBackupTargetsAvailability();
    await loadState();
    state.initialized = true;
    updateRolePermissions();
  } catch (err) {
    const isCompact = document.body.classList.contains("compact-mode");
    if (hostList) {
      hostList.innerHTML = "";
    }
    if (hostTableBody) {
      hostTableBody.innerHTML = "";
    }
    if (isCompact && hostTableBody) {
      const hostError = document.createElement("tr");
      hostError.className = "list-row empty";
      const hostErrorCell = document.createElement("td");
      hostErrorCell.colSpan = 2;
      hostErrorCell.textContent = `Failed to load data: ${err.message}`;
      hostError.appendChild(hostErrorCell);
      hostTableBody.appendChild(hostError);
    } else if (hostList) {
      const hostError = document.createElement("li");
      hostError.className = "list-row empty";
      hostError.textContent = `Failed to load data: ${err.message}`;
      hostList.appendChild(hostError);
    }
    projectList.innerHTML = "";
    const projectError = document.createElement("tr");
    projectError.className = "list-row empty";
    const projectErrorCell = document.createElement("td");
    projectErrorCell.colSpan = isCompact ? 4 : 6;
    projectErrorCell.textContent = "Projects unavailable.";
    projectError.appendChild(projectErrorCell);
    projectList.appendChild(projectError);
  }
}

async function init() {
  const hasToken = loadAuthFromCookie();
  if (!hasToken) {
    showAuthModal("Please sign in to continue.");
    return;
  }
  await initApp();
}

composeEditor.addEventListener("input", handleComposeInput);
if (createProjectCompose) {
  createProjectCompose.addEventListener("input", handleCreateComposeInput);
}
bindSearchControls(getComposeSearchContext);
bindSearchControls(getCreateSearchContext);

previewComposeBtn.addEventListener("click", () => {
  const original = composeEditor.dataset.original || "";
  const current = getComposeValue();
  if (original === current) {
    composeStatus.textContent = "No changes to save.";
    diffPanel.classList.add("hidden");
    confirmComposeBtn.classList.add("hidden");
    return;
  }
  if (diffView) {
    diffView.innerHTML = "";
  }
  diffPanel.classList.remove("hidden");
  if (window.CodeMirror && window.diff_match_patch && diffView) {
    composeDiffView = window.CodeMirror.MergeView(diffView, {
      value: current,
      origRight: original,
      mode: "yaml",
      theme: "material-darker",
      lineNumbers: true,
      lineWrapping: true,
      readOnly: true,
      highlightDifferences: true,
      connect: "align",
      collapseIdentical: true,
    });
    window.setTimeout(() => {
      const editors = [];
      if (composeDiffView && composeDiffView.editor) {
        editors.push(composeDiffView.editor());
      }
      if (composeDiffView && composeDiffView.rightOriginal) {
        editors.push(composeDiffView.rightOriginal());
      }
      if (composeDiffView && composeDiffView.leftOriginal) {
        editors.push(composeDiffView.leftOriginal());
      }
      editors.forEach((editor) => editor && editor.refresh());
    }, 0);
  }
  confirmComposeBtn.classList.remove("hidden");
  if (previewComposeBtn) {
    previewComposeBtn.classList.add("hidden");
  }
  if (composeModal) {
    composeModal.classList.add("reviewing");
  }
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
  composeStatus.textContent = "Review the diff and confirm to save.";
});

confirmComposeBtn.addEventListener("click", async () => {
  if (!composeState.hostId || !composeState.projectName) {
    composeStatus.textContent = "No active project selected.";
    return;
  }
  confirmComposeBtn.disabled = true;
  composeStatus.textContent = "Saving...";
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
  try {
    await api.put(
      `/hosts/${composeState.hostId}/projects/${composeState.projectName}/compose`,
      { content: getComposeValue() }
    );
    setComposeOriginal(getComposeValue());
    composeStatus.textContent = "Saved.";
    diffPanel.classList.add("hidden");
    confirmComposeBtn.classList.add("hidden");
    if (previewComposeBtn) {
      previewComposeBtn.classList.remove("hidden");
    }
    if (composeModal) {
      composeModal.classList.remove("reviewing");
    }
    await refreshHosts([composeState.hostId]);
  } catch (err) {
    composeStatus.textContent = `Error: ${err.message}`;
  } finally {
    confirmComposeBtn.disabled = false;
  }
});

closeComposeModalBtn.addEventListener("click", closeComposeModal);
if (closeCommandModalBtn) {
  closeCommandModalBtn.addEventListener("click", closeCommandModal);
}

if (commandInput) {
  commandInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      runCommandBtn?.click();
    }
  });
}

if (runCommandBtn) {
  runCommandBtn.addEventListener("click", async () => {
    const isRunning = runCommandBtn.dataset.running === "true";
    if (isRunning) {
      if (commandState.stream) {
        commandState.stream.close();
        commandState.stream = null;
      }
      if (commandStatus) {
        commandStatus.textContent = "Cancelled.";
        commandStatus.classList.remove("success");
        commandStatus.classList.add("error");
      }
      setCommandRunning(false);
      return;
    }
    if (!commandState.hostId || !commandState.projectName) {
      if (commandStatus) {
        commandStatus.textContent = "No project selected.";
        commandStatus.classList.add("error");
      }
      return;
    }
    const command = commandInput ? commandInput.value.trim() : "";
    if (!command) {
      if (commandStatus) {
        commandStatus.textContent = "Enter a command to run.";
        commandStatus.classList.add("error");
      }
      return;
    }
    if (commandState.stream) {
      commandState.stream.close();
      commandState.stream = null;
    }
    setCommandRunning(true);
    if (commandStatus) {
      commandStatus.textContent = "Running...";
      commandStatus.classList.remove("error", "success");
    }
    if (commandOutput) {
      commandOutput.textContent = "";
    }
    const outputParts = [];
    const params = new URLSearchParams({ command });
    const streamUrl = `/hosts/${commandState.hostId}/projects/${commandState.projectName}/compose/command/stream?${params.toString()}`;
    const stream = createEventStream(streamUrl, {
      onEvent: (eventName, data) => {
        let payload = {};
        try {
          payload = JSON.parse(data);
        } catch (err) {
          payload = { line: data, message: data };
        }
        if (eventName === "stdout" || eventName === "stderr") {
          const line = payload.line ?? data;
          applyCommandChunk(line, outputParts);
          if (commandOutput) {
            commandOutput.innerHTML = ansiToHtml(outputParts.join("\n"));
          }
          return;
        }
        if (eventName === "complete") {
          const exitCode = Number.isFinite(payload.exit_code) ? payload.exit_code : 0;
          if (commandOutput && !outputParts.length) {
            commandOutput.textContent = "(no output)";
          }
          if (commandStatus) {
            commandStatus.textContent = `Exit code: ${exitCode}`;
            commandStatus.classList.toggle("success", exitCode === 0);
            commandStatus.classList.toggle("error", exitCode !== 0);
          }
          stream.close();
          commandState.stream = null;
          setCommandRunning(false);
          return;
        }
        if (eventName === "error") {
          if (commandStatus) {
            commandStatus.textContent = `Error: ${payload.message || data}`;
            commandStatus.classList.add("error");
          }
          stream.close();
          commandState.stream = null;
          setCommandRunning(false);
        }
      },
      onError: (err) => {
        if (commandStatus) {
          commandStatus.textContent = `Error: ${err.message}`;
          commandStatus.classList.add("error");
        }
        if (commandOutput) {
          commandOutput.textContent = "";
        }
        commandState.stream = null;
        setCommandRunning(false);
      },
    });
    commandState.stream = stream;
  });
}

composeModal
  .querySelector(".modal-backdrop")
  .addEventListener("click", closeComposeModal);
if (commandModal) {
  commandModal
    .querySelector(".modal-backdrop")
    .addEventListener("click", closeCommandModal);
}
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  if (userMenu && !userMenu.classList.contains("hidden")) {
    closeUserMenu();
  }
  if (!composeModal.classList.contains("hidden")) {
    closeComposeModal();
  }
  if (!logsModal.classList.contains("hidden")) {
    closeLogsModal();
  }
  if (commandModal && !commandModal.classList.contains("hidden")) {
    closeCommandModal();
  }
  if (projectDetailsModal && !projectDetailsModal.classList.contains("hidden")) {
    closeProjectDetailsModal();
  }
  if (shellModal && !shellModal.classList.contains("hidden")) {
    closeShellModal();
  }
  if (backupScheduleModal && !backupScheduleModal.classList.contains("hidden")) {
    closeBackupScheduleModal();
  }
  if (restoreModal && !restoreModal.classList.contains("hidden")) {
    closeRestoreModal();
  }
  if (createProjectModal && !createProjectModal.classList.contains("hidden")) {
    closeCreateProjectModal();
  }
  if (deleteProjectModal && !deleteProjectModal.classList.contains("hidden")) {
    closeDeleteProjectModal();
  }
  if (configModal && !configModal.classList.contains("hidden")) {
    closeConfigModal();
  }
});

closeLogsModalBtn.addEventListener("click", closeLogsModal);
logsModal
  .querySelector(".modal-backdrop")
  .addEventListener("click", closeLogsModal);
if (closeShellModalBtn) {
  closeShellModalBtn.addEventListener("click", closeShellModal);
}
if (shellModal) {
  shellModal
    .querySelector(".modal-backdrop")
    .addEventListener("click", closeShellModal);
}
if (closeProjectDetailsModalBtn) {
  closeProjectDetailsModalBtn.addEventListener("click", closeProjectDetailsModal);
}
if (projectDetailsModal) {
  projectDetailsModal
    .querySelector(".modal-backdrop")
    .addEventListener("click", closeProjectDetailsModal);
}
openBackupScheduleBtn.addEventListener("click", openBackupScheduleModal);
closeBackupScheduleModalBtn.addEventListener("click", closeBackupScheduleModal);
backupScheduleModal
  .querySelector(".modal-backdrop")
  .addEventListener("click", closeBackupScheduleModal);
if (openRestoreModalBtn) {
  openRestoreModalBtn.addEventListener("click", handleRestoreButtonClick);
}
if (closeRestoreModalBtn) {
  closeRestoreModalBtn.addEventListener("click", closeRestoreModal);
}
if (restoreModal) {
  restoreModal
    .querySelector(".modal-backdrop")
    .addEventListener("click", closeRestoreModal);
}
if (restoreBackupTarget) {
  restoreBackupTarget.addEventListener("change", loadRestoreProjects);
}
if (runRestoreBtn) {
  runRestoreBtn.addEventListener("click", () => runRestore(false));
}
if (openEventStatusBtn) {
  openEventStatusBtn.addEventListener("click", openEventStatusModal);
}
if (refreshEventStatusBtn) {
  refreshEventStatusBtn.addEventListener("click", () => {
    loadEventStatus();
  });
}
if (toggleEventAutoBtn) {
  toggleEventAutoBtn.addEventListener("click", () => {
    eventStatusState.autoRefreshEnabled = !eventStatusState.autoRefreshEnabled;
    updateEventAutoButton();
    if (eventStatusState.autoRefreshEnabled) {
      startEventStatusAutoRefresh();
      loadEventStatus();
    } else {
      stopEventStatusAutoRefresh();
    }
  });
}
if (openCreateProjectBtn) {
  openCreateProjectBtn.addEventListener("click", openCreateProjectModal);
}
if (closeCreateProjectModalBtn) {
  closeCreateProjectModalBtn.addEventListener("click", closeCreateProjectModal);
}
if (createProjectSubmit) {
  createProjectSubmit.addEventListener("click", submitCreateProject);
}
if (convertRunToComposeBtn) {
  convertRunToComposeBtn.addEventListener("click", convertRunToCompose);
}
if (authSubmit) {
  authSubmit.addEventListener("click", submitAuth);
}
if (authPassword) {
  authPassword.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      submitAuth();
    }
  });
}
if (currentUserBadge) {
  currentUserBadge.addEventListener("click", (event) => {
    event.stopPropagation();
    toggleUserMenu();
  });
}
if (userChangePasswordBtn) {
  userChangePasswordBtn.addEventListener("click", submitPasswordChange);
}
if (userNewPassword) {
  userNewPassword.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      submitPasswordChange();
    }
  });
}
if (logoutBtn) {
  logoutBtn.addEventListener("click", () => {
    closeUserMenu();
    clearAuthToken();
    showAuthModal("Signed out.");
  });
}
if (createProjectModal) {
  createProjectModal
    .querySelector(".modal-backdrop")
    .addEventListener("click", closeCreateProjectModal);
}
if (closeDeleteProjectModalBtn) {
  closeDeleteProjectModalBtn.addEventListener("click", closeDeleteProjectModal);
}
if (confirmDeleteProjectBtn) {
  confirmDeleteProjectBtn.addEventListener("click", submitDeleteProject);
}
if (deleteProjectModal) {
  deleteProjectModal
    .querySelector(".modal-backdrop")
    .addEventListener("click", closeDeleteProjectModal);
}
if (openConfigBtn) {
  openConfigBtn.addEventListener("click", openConfigModal);
}
if (closeConfigModalBtn) {
  closeConfigModalBtn.addEventListener("click", closeConfigModal);
}
if (configModal) {
  configModal.querySelector(".modal-backdrop").addEventListener("click", closeConfigModal);
}
if (addHostConfigBtn) {
  addHostConfigBtn.addEventListener("click", () => {
    if (!hostConfigList) {
      return;
    }
    const entry = buildHostConfigEntry(null, true);
    hostConfigList.prepend(entry);
  });
}
if (addBackupConfigBtn) {
  addBackupConfigBtn.addEventListener("click", () => {
    if (!backupConfigList) {
      return;
    }
    const entry = buildBackupConfigEntry(null, true);
    backupConfigList.prepend(entry);
  });
}
if (addUserConfigBtn) {
  addUserConfigBtn.addEventListener("click", () => {
    if (!userConfigList) {
      return;
    }
    const entry = buildUserConfigEntry(null, true);
    userConfigList.prepend(entry);
  });
}
if (saveTokenExpiryBtn) {
  saveTokenExpiryBtn.addEventListener("click", saveTokenExpiry);
}
refreshLogsBtn.addEventListener("click", fetchLogs);
toggleFollowBtn.addEventListener("click", toggleLogFollow);
logsServiceInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    fetchLogs();
  }
});
logsTailInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    fetchLogs();
  }
});
logsShowStdout.addEventListener("change", updateLogsFilter);
logsShowStderr.addEventListener("change", updateLogsFilter);
document.addEventListener("keydown", handleComposeSearchShortcut);
document.addEventListener("keydown", handleFindShortcut);
document.addEventListener("keydown", handleHardRestartModifier);
document.addEventListener("keyup", handleHardRestartModifier);
window.addEventListener("blur", () => setHardRestartActive(false));
if (projectSelectToggle) {
  projectSelectToggle.addEventListener("change", () => {
    if (projectSelectToggle.checked) {
      selectAllProjects();
    } else {
      clearProjects();
    }
  });
}
filterToggleButtons.forEach((button) => {
  const key = button.dataset.filter;
  if (!key) {
    return;
  }
  const menu = document.querySelector(`.filter-menu[data-filter-menu="${key}"]`);
  if (!menu) {
    return;
  }
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    const willOpen = menu.classList.contains("hidden");
    closeAllFilterMenus(menu);
    menu.classList.toggle("hidden", !willOpen);
  });
  menu.addEventListener("click", (event) => {
    event.stopPropagation();
  });
});
if (!state.filterMenuListenerBound) {
  document.addEventListener("click", () => closeAllFilterMenus());
  state.filterMenuListenerBound = true;
}
document.addEventListener("click", (event) => {
  if (!userMenu || userMenu.classList.contains("hidden")) {
    return;
  }
  if (event.target.closest("#userMenu") || event.target.closest("#currentUserBadge")) {
    return;
  }
  closeUserMenu();
});
if (headerFilterHosts) {
  headerFilterHosts.addEventListener("change", () => {
    updateProjectFilterState();
    updateProjectFilterIndicators();
    renderProjectList();
  });
}
if (headerFilterStatus) {
  headerFilterStatus.addEventListener("change", () => {
    updateProjectFilterState();
    updateProjectFilterIndicators();
    renderProjectList();
  });
}
if (headerFilterUpdates) {
  headerFilterUpdates.addEventListener("change", () => {
    updateProjectFilterState();
    updateProjectFilterIndicators();
    renderProjectList();
  });
}
const hostFilterClear = document.querySelector('[data-filter-clear="hosts"]');
if (hostFilterClear) {
  hostFilterClear.addEventListener("click", () => {
    if (headerFilterHosts) {
      Array.from(headerFilterHosts.options).forEach((option) => {
        option.selected = false;
      });
    }
    updateProjectFilterState();
    updateProjectFilterIndicators();
    renderProjectList();
  });
}
projectSortHeaders.forEach((header) => {
  header.addEventListener("click", () => {
    const sortKey = header.dataset.sort;
    if (!sortKey) {
      return;
    }
    if (state.projectFilters.sortBy === sortKey) {
      state.projectFilters.sortDir =
        state.projectFilters.sortDir === "asc" ? "desc" : "asc";
    } else {
      state.projectFilters.sortBy = sortKey;
      state.projectFilters.sortDir = "asc";
    }
    renderProjectList();
  });
});
if (projectFilterName) {
  projectFilterName.addEventListener("input", () => {
    updateProjectFilterState();
    updateProjectFilterIndicators();
    renderProjectList();
  });
}
if (clearProjectFiltersBtn) {
  clearProjectFiltersBtn.addEventListener("click", clearProjectFilters);
}
document.querySelectorAll(".bulk-action").forEach((button) => {
  button.addEventListener("click", (event) => {
    const action = button.dataset.bulkAction;
    if (action) {
      runBulkAction(action, event);
    }
  });
});

window.addEventListener("resize", handleShellResize);

init();
