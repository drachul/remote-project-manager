const stateStatus = document.getElementById("stateStatus");
const hostList = document.getElementById("hostList");
const projectList = document.getElementById("projectList");
const hostRowTemplate = document.getElementById("hostRowTemplate");
const projectRowTemplate = document.getElementById("projectRowTemplate");
const selectAllHostsBtn = document.getElementById("selectAllHosts");
const clearHostsBtn = document.getElementById("clearHosts");
const selectAllProjectsBtn = document.getElementById("selectAllProjects");
const clearProjectsBtn = document.getElementById("clearProjects");
const projectCount = document.getElementById("projectCount");
const bulkActions = document.getElementById("bulkActions");
const bulkProgress = document.getElementById("bulkProgress");
const bulkProgressText = document.getElementById("bulkProgressText");
const bulkProgressBar = document.getElementById("bulkProgressBar");
const composeModal = document.getElementById("composeModal");
const composeTarget = document.getElementById("composeTarget");
const composePath = document.getElementById("composePath");
const composeEditor = document.getElementById("composeEditor");
const composeStatus = document.getElementById("composeStatus");
const composeLint = document.getElementById("composeLint");
const previewComposeBtn = document.getElementById("previewCompose");
const confirmComposeBtn = document.getElementById("confirmCompose");
const closeComposeModalBtn = document.getElementById("closeComposeModal");
const diffPanel = document.getElementById("diffPanel");
const diffContent = document.getElementById("diffContent");
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
const openBackupScheduleBtn = document.getElementById("openBackupSchedule");
const backupScheduleModal = document.getElementById("backupScheduleModal");
const closeBackupScheduleModalBtn = document.getElementById("closeBackupScheduleModal");
const openCreateProjectBtn = document.getElementById("openCreateProject");
const createProjectModal = document.getElementById("createProjectModal");
const closeCreateProjectModalBtn = document.getElementById("closeCreateProjectModal");
const createProjectHost = document.getElementById("createProjectHost");
const createProjectName = document.getElementById("createProjectName");
const createProjectBackup = document.getElementById("createProjectBackup");
const createProjectRun = document.getElementById("createProjectRun");
const createProjectCompose = document.getElementById("createProjectCompose");
const createProjectStatus = document.getElementById("createProjectStatus");
const createProjectProgressText = document.getElementById("createProjectProgressText");
const createProjectProgressBar = document.getElementById("createProjectProgressBar");
const createProjectSubmit = document.getElementById("createProjectSubmit");
const createProjectCancel = document.getElementById("createProjectCancel");
const convertRunToComposeBtn = document.getElementById("convertRunToCompose");
const deleteProjectModal = document.getElementById("deleteProjectModal");
const closeDeleteProjectModalBtn = document.getElementById("closeDeleteProjectModal");
const deleteProjectTarget = document.getElementById("deleteProjectTarget");
const deleteProjectStatus = document.getElementById("deleteProjectStatus");
const confirmDeleteProjectBtn = document.getElementById("confirmDeleteProject");
const authModal = document.getElementById("authModal");
const authUsername = document.getElementById("authUsername");
const authPassword = document.getElementById("authPassword");
const authSubmit = document.getElementById("authSubmit");
const authStatus = document.getElementById("authStatus");
const logoutBtn = document.getElementById("logoutBtn");
const openConfigBtn = document.getElementById("openConfig");
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
const intervalStateInput = document.getElementById("intervalStateSeconds");
const intervalUpdateInput = document.getElementById("intervalUpdateSeconds");
const updateIntervalGroup = document.getElementById("updateIntervalGroup");
const tokenExpiryInput = document.getElementById("tokenExpirySeconds");
const saveIntervalsBtn = document.getElementById("saveIntervals");
const configStatus = document.getElementById("configStatus");
const toastContainer = document.getElementById("toastContainer");
const scheduleEnabled = document.getElementById("scheduleEnabled");
const scheduleEnabledLabel = document.getElementById("scheduleEnabledLabel");
const scheduleScope = document.getElementById("scheduleScope");
const scheduleScopeHint = document.getElementById("scheduleScopeHint");
const scheduleTime = document.getElementById("scheduleTime");
const daysOfWeekContainer = document.getElementById("scheduleDaysOfWeek");
const daysOfMonthSelect = document.getElementById("scheduleDaysOfMonth");
const monthsSelect = document.getElementById("scheduleMonths");
const cronExpression = document.getElementById("cronExpression");
const customCron = document.getElementById("customCron");
const saveScheduleBtn = document.getElementById("saveSchedule");
const refreshScheduleBtn = document.getElementById("refreshSchedule");
const scheduleStatus = document.getElementById("scheduleStatus");
const scheduleLast = document.getElementById("scheduleLast");
const scheduleNext = document.getElementById("scheduleNext");

const state = {
  hosts: [],
  stateSnapshot: null,
  stateIntervalSeconds: null,
  backupScheduleAvailable: true,
  updatesEnabled: true,
  backupTargetsAvailable: true,
  authToken: null,
  initialized: false,
  configTabsInit: false,
  selectedHosts: new Set(),
  selectedProjects: new Set(),
  backupCancelled: new Set(),
  actionProgress: new Map(),
  hostActionProgress: new Map(),
  serviceActionProgress: new Map(),
  authExpiredNotified: false,
};

const composeState = {
  hostId: null,
  projectName: null,
};

const logsState = {
  hostId: null,
  projectName: null,
  stream: null,
};

const scheduleState = {
  initialized: false,
  lastLoadFailed: false,
};

const deleteProjectState = {
  hostId: null,
  projectName: null,
};

const DEFAULT_CREATE_COMPOSE = `services:\n  app:\n    image: nginx:latest\n    ports:\n      - \"8080:80\"\n`;
const AUTH_COOKIE_NAME = "rpm_token";


async function handleUnauthorized(response) {
  let message = "Unauthorized.";
  const text = await response.text();
  if (text) {
    try {
      const payload = JSON.parse(text);
      if (payload && payload.detail) {
        message = payload.detail;
      } else {
        message = text;
      }
    } catch (err) {
      message = text;
    }
  }
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
    let message = text || response.statusText;
    if (text) {
      try {
        const payload = JSON.parse(text);
        if (payload && payload.detail) {
          message = payload.detail;
        }
      } catch (err) {
        message = text || response.statusText;
      }
    }
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
        throw new Error(text || response.statusText);
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
  if (!updateIntervalGroup || !intervalUpdateInput) {
    return;
  }
  const show = Boolean(state.updatesEnabled);
  updateIntervalGroup.classList.toggle("hidden", !show);
  intervalUpdateInput.disabled = !show;
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
  state.authExpiredNotified = false;
  const expiresAt = new Date(payload.expiration);
  setCookieValue(AUTH_COOKIE_NAME, token, expiresAt);
  scheduleAuthExpiry(payload);
}

function clearAuthToken() {
  state.authToken = null;
  clearAuthExpiryTimeout();
  clearCookieValue(AUTH_COOKIE_NAME);
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
  state.authExpiredNotified = false;
  scheduleAuthExpiry(payload);
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
  scheduleNext.textContent = data.next_run ? formatTimestamp(data.next_run) : "disabled";
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

  const entries = buildProjectEntries();
  const hosts = new Map();
  entries.forEach((entry) => {
    const list = hosts.get(entry.hostId) || [];
    list.push(entry.projectName);
    hosts.set(entry.hostId, list);
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
      scheduleEnabled.checked =
        typeof info.enabled === "boolean" ? info.enabled : Boolean(cron);
      if (scheduleEnabledLabel) {
        scheduleEnabledLabel.textContent = "Enable scheduled backups";
      }
      if (scheduleScopeHint) {
        scheduleScopeHint.textContent = "Applies to enabled projects without overrides.";
      }
      updateScheduleInfo({
        last_run: getGlobalBackupLastRun(),
        next_run: info.next_run,
      });
    } else {
      info = await api.get(
        `/hosts/${scope.hostId}/projects/${scope.projectName}/backup/settings`
      );
      cron = info.cron_override || "";
      scheduleEnabled.checked = Boolean(cron);
      if (scheduleEnabledLabel) {
        scheduleEnabledLabel.textContent = "Override schedule for this project";
      }
      if (scheduleScopeHint) {
        scheduleScopeHint.textContent =
          "Leave disabled to inherit the global schedule.";
      }
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
      await api.put("/backup/schedule", {
        cron: cron || null,
        enabled: scheduleEnabled.checked,
      });
    } else {
      if (!scheduleEnabled.checked) {
        cron = "";
      }
      await api.put(
        `/hosts/${scope.hostId}/projects/${scope.projectName}/backup/settings`,
        { cron_override: cron || null }
      );
    }
    await loadSchedule();
    scheduleStatus.textContent = "Saved.";
  } catch (err) {
    scheduleStatus.textContent = `Save failed: ${err.message}`;
  }
}

function initScheduleControls() {
  populateSelect(daysOfMonthSelect, 1, 31);
  populateSelect(monthsSelect, 1, 12);
  populateScheduleScope();

  scheduleEnabled.addEventListener("change", () => {
    syncCronFromBuilder();
  });

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

  scheduleScope.addEventListener("change", () => {
    loadSchedule();
  });

  saveScheduleBtn.addEventListener("click", saveSchedule);
  refreshScheduleBtn.addEventListener("click", loadSchedule);
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

function setActionRunning(button, running) {
  if (running) {
    button.classList.add("in-progress");
    button.dataset.actionRunning = "true";
  } else {
    button.classList.remove("in-progress");
    button.dataset.actionRunning = "";
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

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function openComposeModal(hostId, projectName) {
  composeState.hostId = hostId;
  composeState.projectName = projectName;
  composeModal.classList.remove("hidden");
  composeTarget.textContent = `${hostId} / ${projectName}`;
  composePath.textContent = "";
  composeEditor.value = "";
  composeEditor.dataset.original = "";
  composeStatus.textContent = "Loading compose file...";
  diffPanel.classList.add("hidden");
  confirmComposeBtn.classList.add("hidden");
  composeLint.classList.add("hidden");
  composeLint.textContent = "";

  api
    .get(`/hosts/${hostId}/projects/${projectName}/compose`)
    .then((data) => {
      composePath.textContent = data.path || "";
      composeEditor.value = data.content || "";
      composeEditor.dataset.original = data.content || "";
      composeStatus.textContent = "";
    })
    .catch((err) => {
      composeStatus.textContent = `Error: ${err.message}`;
    });
}

function closeComposeModal() {
  composeModal.classList.add("hidden");
  composeState.hostId = null;
  composeState.projectName = null;
  diffPanel.classList.add("hidden");
  confirmComposeBtn.classList.add("hidden");
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
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

async function openBackupScheduleModal() {
  if (!backupScheduleModal) {
    return;
  }
  backupScheduleModal.classList.remove("hidden");
  if (!scheduleState.initialized) {
    initScheduleControls();
    scheduleState.initialized = true;
  }
  populateScheduleScope();
  if (scheduleScope && scheduleScope.value === "global" && state.selectedProjects.size === 1) {
    const [onlyProject] = state.selectedProjects;
    const hasOption = Array.from(scheduleScope.options).some(
      (option) => option.value === onlyProject
    );
    if (hasOption) {
      scheduleScope.value = onlyProject;
    }
  }
  const result = await loadSchedule();
  if (!result.ok && result.error) {
    showToast(result.error, "error");
  }
}

function closeBackupScheduleModal() {
  if (backupScheduleModal) {
    backupScheduleModal.classList.add("hidden");
  }
}

function resetCreateProgress() {
  if (createProjectProgressText) {
    createProjectProgressText.textContent = "Awaiting input";
  }
  if (createProjectProgressBar) {
    createProjectProgressBar.style.width = "0%";
  }
}

function setCreateProgress(message, percent) {
  if (createProjectProgressText && message) {
    createProjectProgressText.textContent = message;
  }
  if (createProjectProgressBar && typeof percent === "number") {
    createProjectProgressBar.style.width = `${percent}%`;
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
    createProjectCompose.value = composeText;
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
      throw new Error(text || response.statusText);
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
  if (!createProjectModal) {
    return;
  }
  createProjectModal.classList.remove("hidden");
  populateCreateProjectHosts();
  if (createProjectName) {
    createProjectName.value = "";
  }
  if (createProjectRun) {
    createProjectRun.value = "";
  }
  if (createProjectCompose) {
    createProjectCompose.value = DEFAULT_CREATE_COMPOSE;
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
    await api.delete(
      `/hosts/${encodeURIComponent(deleteProjectState.hostId)}/projects/${encodeURIComponent(
        deleteProjectState.projectName
      )}`
    );
    showToast(`${deleteProjectState.projectName}: project deleted`);
    await loadHosts();
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
  let content = createProjectCompose.value || "";
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
      createProjectCompose.value = content;
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
  if (createProjectCancel) {
    createProjectCancel.disabled = true;
  }
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
    showToast(`${projectName}: project created`);
    await loadHosts();
    await loadState();
    renderLists();
  } catch (err) {
    setCreateProgress("Create failed.", 0);
    createProjectStatus.textContent = `Create failed: ${err.message}`;
    createProjectStatus.classList.add("error");
  } finally {
    createProjectSubmit.disabled = false;
    if (createProjectCancel) {
      createProjectCancel.disabled = false;
    }
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
  if (!configModal) {
    return;
  }
  configModal.classList.remove("hidden");
  initConfigTabs();
  loadConfigEntries();
}

function closeConfigModal() {
  if (!configModal) {
    return;
  }
  configModal.classList.add("hidden");
}

function initConfigTabs() {
  if (state.configTabsInit) {
    return;
  }
  configTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.tab;
      configTabs.forEach((button) => {
        button.classList.toggle("active", button === tab);
      });
      configTabPanels.forEach((panel) => {
        panel.classList.toggle("active", panel.dataset.tabPanel === target);
      });
    });
  });
  state.configTabsInit = true;
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
  idInput.value = host?.id || "";
  rootInput.value = host?.project_root || "";
  addressInput.value = host?.ssh_address || "";
  userInput.value = host?.ssh_username || "";
  portInput.value = host?.ssh_port ?? 22;
  keyInput.value = host?.ssh_key || "";
  if (!isNew) {
    idInput.disabled = true;
  }
  const saveBtn = entry.querySelector(".config-save");
  const deleteBtn = entry.querySelector(".config-delete");
  saveBtn.addEventListener("click", () => saveHostConfig(entry));
  deleteBtn.addEventListener("click", () => deleteHostConfig(entry));
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
  }
  const saveBtn = entry.querySelector(".config-save");
  const deleteBtn = entry.querySelector(".config-delete");
  saveBtn.addEventListener("click", () => saveBackupConfig(entry));
  deleteBtn.addEventListener("click", () => deleteBackupConfig(entry));
  return entry;
}

function buildUserConfigEntry(user, isNew) {
  const entry = userConfigTemplate.content.firstElementChild.cloneNode(true);
  entry.dataset.new = isNew ? "true" : "false";
  const usernameInput = entry.querySelector(".user-name");
  const passwordInput = entry.querySelector(".user-password");
  const lastLogin = entry.querySelector(".user-last-login");
  usernameInput.value = user?.username || "";
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
  deleteBtn.addEventListener("click", () => deleteUserConfig(entry));
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
  if (!payload.password) {
    setConfigStatus("Password is required.", "error");
    return;
  }
  saveBtn.disabled = true;
  setConfigStatus(isNew ? "Creating user..." : "Updating user...");
  try {
    const url = isNew
      ? "/config/users"
      : `/config/users/${encodeURIComponent(payload.username)}`;
    const data = isNew
      ? await api.post(url, payload)
      : await api.put(url, { password: payload.password });
    entry.dataset.new = "false";
    entry.querySelector(".user-name").disabled = true;
    entry.querySelector(".user-password").value = "";
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
  if (!intervalStateInput || !intervalUpdateInput || !tokenExpiryInput) {
    return;
  }
  try {
    const [stateInterval, updateInterval] = await Promise.all([
      api.get("/state/interval"),
      api.get("/update/interval"),
    ]);
    intervalStateInput.value = stateInterval.seconds;
    intervalUpdateInput.value = updateInterval.seconds;
    const tokenExpiry = await api.get("/config/token-expiry");
    tokenExpiryInput.value = tokenExpiry.seconds;
    state.stateIntervalSeconds = stateInterval.seconds;
    updateIntervalVisibility();
  } catch (err) {
    setConfigStatus(`Failed to load intervals: ${err.message}`, "error");
  }
}

async function saveIntervals() {
  if (!intervalStateInput || !intervalUpdateInput || !tokenExpiryInput || !saveIntervalsBtn) {
    return;
  }
  const stateSeconds = Number.parseInt(intervalStateInput.value, 10);
  const tokenSeconds = Number.parseInt(tokenExpiryInput.value, 10);
  if (Number.isNaN(stateSeconds) || stateSeconds < 0) {
    setConfigStatus("State refresh must be 0 or greater.", "error");
    return;
  }
  if (Number.isNaN(tokenSeconds) || tokenSeconds < 30) {
    setConfigStatus("Token expiry must be at least 30 seconds.", "error");
    return;
  }
  saveIntervalsBtn.disabled = true;
  setConfigStatus("Saving settings...");
  try {
    await api.put("/state/interval", { seconds: stateSeconds });
    if (state.updatesEnabled) {
      const updateSeconds = Number.parseInt(intervalUpdateInput.value, 10);
      if (Number.isNaN(updateSeconds) || updateSeconds < 0) {
        setConfigStatus("Update check must be 0 or greater.", "error");
        return;
      }
      await api.put("/update/interval", { seconds: updateSeconds });
    }
    await api.put("/config/token-expiry", { seconds: tokenSeconds });
    state.stateIntervalSeconds = stateSeconds;
    setConfigStatus("Settings saved.", "success");
  } catch (err) {
    setConfigStatus(`Failed to save settings: ${err.message}`, "error");
  } finally {
    saveIntervalsBtn.disabled = false;
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
      span.textContent = data.logs || "No logs returned.";
      logsContent.appendChild(span);
      updateLogsFilter();
      logsContent.scrollTop = logsContent.scrollHeight;
    })
    .catch((err) => {
      logsContent.innerHTML = "";
      const span = document.createElement("span");
      span.className = "log-line stderr";
      span.textContent = `Error: ${err.message}`;
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
    span.textContent = `${line}\n`;
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
      span.textContent = "\n[log stream closed]\n";
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
  if (state.selectedHosts.size) {
    return Array.from(state.selectedHosts);
  }
  return state.hosts.map((host) => host.host_id);
}

function buildProjectEntries() {
  const stateByHost = getStateByHost();
  const activeHostIds = new Set(getActiveHostIds());
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
      entries.push({
        key: `${host.host_id}::${projectName}`,
        hostId: host.host_id,
        projectName,
        path: projectPath,
        status: stateProject?.overall_status,
        updatesAvailable: stateProject?.updates_available,
        sleeping: stateProject?.sleeping,
        refreshedAt: stateProject?.refreshed_at || null,
        backupEnabled: Boolean(backupEnabled),
        lastBackupAt,
        lastBackupSuccess,
        lastBackupMessage,
        services,
        serviceCount: services.length,
      });
    });
  });

  return entries;
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

function renderHostList() {
  hostList.innerHTML = "";
  if (!state.hosts.length) {
    const empty = document.createElement("li");
    empty.className = "list-row empty";
    empty.textContent = "No hosts configured.";
    hostList.appendChild(empty);
    return;
  }

  const hostIds = new Set(state.hosts.map((host) => host.host_id));
  const stateByHost = getStateByHost();
  state.selectedHosts.forEach((hostId) => {
    if (!hostIds.has(hostId)) {
      state.selectedHosts.delete(hostId);
    }
  });
  state.hostActionProgress.forEach((_, hostId) => {
    if (!hostIds.has(hostId)) {
      state.hostActionProgress.delete(hostId);
    }
  });

  state.hosts.forEach((host) => {
    const row = hostRowTemplate.content.firstElementChild.cloneNode(true);
    const checkbox = row.querySelector(".host-checkbox");
    row.querySelector(".host-name").textContent = host.host_id;
    const projectCountText = host.projects?.length ?? Object.keys(host.project_paths || {}).length;
    row.querySelector(".host-meta").textContent = `${host.user}@${host.host}:${host.port} • ${projectCountText} projects`;
    checkbox.checked = state.selectedHosts.has(host.host_id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        state.selectedHosts.add(host.host_id);
      } else {
        state.selectedHosts.delete(host.host_id);
      }
      renderProjectList();
    });

    const refreshBtn = row.querySelector(".refresh-host");
    refreshBtn.addEventListener("click", () =>
      runHostQuickAction(refreshBtn, host.host_id, "refresh", () =>
        refreshHost(host.host_id)
      )
    );
    const scanBtn = row.querySelector(".scan-host");
    scanBtn.addEventListener("click", () =>
      runHostQuickAction(scanBtn, host.host_id, "scan", () =>
        scanHostProjects(host.host_id)
      )
    );
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
    }
    if (wakeBtn) {
      wakeBtn.classList.toggle("hidden", !hasSleeping);
      wakeBtn.addEventListener("click", () =>
        runHostAction(wakeBtn, host.host_id, "wake")
      );
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
    hostList.appendChild(row);
  });
}

function renderProjectList() {
  projectList.innerHTML = "";
  const entries = buildProjectEntries();
  const availableKeys = new Set(entries.map((entry) => entry.key));
  syncProjectSelection(availableKeys);
  syncBackupCancelled(availableKeys);
  syncActionProgress(availableKeys);
  const availableServiceKeys = new Set();
  entries.forEach((entry) => {
    entry.services.forEach((service) => {
      const serviceName = service.id || "unknown";
      availableServiceKeys.add(serviceActionKey(entry.hostId, entry.projectName, serviceName));
    });
  });
  syncServiceActionProgress(availableServiceKeys);

  projectCount.textContent = `${entries.length} projects • ${state.selectedProjects.size} selected`;

  if (!entries.length) {
    const empty = document.createElement("li");
    empty.className = "list-row empty";
    empty.textContent = "No projects available.";
    projectList.appendChild(empty);
    return;
  }

    entries.forEach((entry) => {
      const row = projectRowTemplate.content.firstElementChild.cloneNode(true);
      row.dataset.projectKey = entry.key;
      const checkbox = row.querySelector(".project-checkbox");
    checkbox.checked = state.selectedProjects.has(entry.key);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        state.selectedProjects.add(entry.key);
      } else {
        state.selectedProjects.delete(entry.key);
      }
      projectCount.textContent = `${entries.length} projects • ${state.selectedProjects.size} selected`;
      updateBulkVisibility();
    });

    row.querySelector(".project-name").textContent = entry.projectName;
    const projectMetaText = row.querySelector(".project-meta-text");
    if (projectMetaText) {
      projectMetaText.textContent = `${entry.hostId} • ${entry.path}`;
    }

    const statusBadge = row.querySelector(".badge.status");
    const statusInfo = projectStatusLabel(entry.status);
    statusBadge.textContent = statusInfo.label;
    if (statusInfo.className) {
      statusBadge.classList.add(statusInfo.className);
    }

    const updatesBadge = row.querySelector(".badge.updates");
    const updatesInfo = updateBadgeLabel(entry.updatesAvailable);
    updatesBadge.textContent = updatesInfo.label;
    if (updatesInfo.className) {
      updatesBadge.classList.add(updatesInfo.className);
    }
    if (!state.updatesEnabled) {
      updatesBadge.classList.add("hidden");
    }

    const cancelledBadge = row.querySelector(".badge.cancelled");
    if (state.backupCancelled.has(entry.key)) {
      cancelledBadge.classList.remove("hidden");
    } else {
      cancelledBadge.classList.add("hidden");
    }

    const backupBadge = row.querySelector(".backup-meta");
    const backupInfo = backupBadgeInfo(entry);
    backupBadge.textContent = backupInfo.label;
    backupBadge.classList.remove("backup-ok", "backup-fail");
    if (entry.lastBackupMessage) {
      backupBadge.title = entry.lastBackupMessage;
    } else {
      backupBadge.title = "";
    }

    const stateMeta = row.querySelector(".state-meta");
    if (stateMeta) {
      stateMeta.textContent = `State updated: ${formatTimestamp(entry.refreshedAt)}`;
    }

    const backupToggle = row.querySelector(".backup-checkbox");
    if (backupToggle) {
      backupToggle.checked = Boolean(entry.backupEnabled);
      backupToggle.disabled = !state.backupScheduleAvailable;
      if (!state.backupScheduleAvailable) {
        backupToggle.title = "Backup scheduling unavailable";
      } else {
        backupToggle.title = "";
      }
      backupToggle.addEventListener("change", async () => {
        if (!state.backupScheduleAvailable) {
          backupToggle.checked = Boolean(entry.backupEnabled);
          return;
        }
        const desired = backupToggle.checked;
        backupToggle.disabled = true;
        try {
          const data = await api.put(
            `/hosts/${entry.hostId}/projects/${entry.projectName}/backup/settings`,
            { enabled: desired }
          );
          const host = state.hosts.find((item) => item.host_id === entry.hostId);
          if (host) {
            host.backup_enabled = host.backup_enabled || {};
            host.backup_last_at = host.backup_last_at || {};
            host.backup_last_success = host.backup_last_success || {};
            host.backup_last_message = host.backup_last_message || {};
            host.backup_enabled[entry.projectName] = data.enabled;
            host.backup_last_at[entry.projectName] = data.last_backup_at;
            host.backup_last_success[entry.projectName] = data.last_backup_success;
            host.backup_last_message[entry.projectName] = data.last_backup_message;
          }
          renderProjectList();
        } catch (err) {
          backupToggle.checked = !desired;
          alert(`Failed to update backup setting: ${err.message}`);
        } finally {
          backupToggle.disabled = false;
        }
      });
    }

    const deleteBtn = row.querySelector(".project-delete");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openDeleteProjectModal(entry.hostId, entry.projectName);
      });
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
    updatesIcon.classList.remove("yes");
    if (!state.updatesEnabled) {
      updatesIcon.textContent = "";
      updatesIcon.title = "Updates disabled";
      updatesIcon.classList.add("hidden");
    } else {
      updatesIcon.classList.remove("hidden");
      if (updatesInfo.className === "updates-yes") {
        updatesIcon.classList.add("yes");
        updatesIcon.textContent = "published_with_changes";
        updatesIcon.title = "Updates available";
      } else {
        updatesIcon.textContent = "";
        updatesIcon.title = "Updates: none";
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
    const projectRunning = statusInfo.className === "up" || statusInfo.className === "degraded";
    const startRunning = actionStates.has("start");
    const stopRunning = actionStates.has("stop");
    const restartRunning = actionStates.has("restart");
    const updateRunning = actionStates.has("update");
    const backupRunning = actionStates.has("backup");
    const refreshRunning = actionStates.has("refresh");

    const startBtn = row.querySelector(".project-action[data-action=\"start\"]");
    const stopBtn = row.querySelector(".project-action[data-action=\"stop\"]");
    const restartBtn = row.querySelector(".project-action[data-action=\"restart\"]");
    const updateBtn = row.querySelector(".project-action[data-action=\"update\"]");
    const backupBtn = row.querySelector(".project-action[data-action=\"backup\"]");
    const refreshBtn = row.querySelector(".project-action[data-action=\"refresh\"]");

    const showStart = startRunning || !projectRunning;
    const showStop = stopRunning || projectRunning;
    const showRestart = restartRunning || projectRunning;

    if (startBtn) {
      startBtn.classList.add("action-ready");
      setActionRunning(startBtn, startRunning);
      startBtn.classList.toggle("hidden", !showStart);
    }
    if (stopBtn) {
      stopBtn.classList.add("action-ready");
      setActionRunning(stopBtn, stopRunning);
      stopBtn.classList.toggle("hidden", !showStop);
    }
    if (restartBtn) {
      restartBtn.classList.add("action-ready");
      setActionRunning(restartBtn, restartRunning);
      restartBtn.classList.toggle("hidden", !showRestart);
    }
    if (updateBtn) {
      updateBtn.classList.add("action-ready");
      setActionRunning(updateBtn, updateRunning);
      updateBtn.classList.remove("hidden");
    }
    if (backupBtn) {
      backupBtn.classList.add("action-ready");
      setActionRunning(backupBtn, backupRunning);
      backupBtn.disabled = !state.backupTargetsAvailable;
      backupBtn.classList.remove("hidden");
    }
    if (refreshBtn) {
      refreshBtn.classList.add("action-ready");
      setActionRunning(refreshBtn, refreshRunning);
      refreshBtn.classList.remove("hidden");
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
    const servicesCount = row.querySelector(".services-count");
    servicesCount.textContent = `${entry.serviceCount} total`;
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
        const name = document.createElement("div");
        name.className = "service-name";
        const serviceName = service.id || "unknown";
        const encodedService = encodeURIComponent(serviceName);
        name.textContent = serviceName;
        const meta = document.createElement("div");
        meta.className = "service-meta";

        const metaParts = [];
        if (service.status) {
          metaParts.push(`status: ${service.status}`);
        }
        meta.textContent = metaParts.join(" • ");

        details.appendChild(name);
        details.appendChild(meta);

        const badge = document.createElement("span");
        badge.className = `material-symbols-outlined status-icon service-status-icon ${info.className}`;
        badge.textContent = statusIconName(info.className);
        badge.title = `Status: ${info.label}`;

        const updatesIcon = document.createElement("span");
        updatesIcon.className = "material-symbols-outlined updates-icon service-updates-icon";
        if (state.updatesEnabled && service.update_available) {
          updatesIcon.classList.add("yes");
          updatesIcon.textContent = "published_with_changes";
          updatesIcon.title = "Updates available";
        } else {
          updatesIcon.classList.add("hidden");
          updatesIcon.textContent = "";
          updatesIcon.title = state.updatesEnabled ? "Updates: none" : "Updates disabled";
        }

        const iconsWrap = document.createElement("div");
        iconsWrap.className = "service-icons";
        iconsWrap.appendChild(badge);
        iconsWrap.appendChild(updatesIcon);

        const actions = document.createElement("div");
        actions.className = "service-actions";

        const actionStateKey = serviceActionKey(entry.hostId, entry.projectName, serviceName);
        const serviceActions = getServiceActionProgress(actionStateKey);
        const serviceRunning = info.className === "up" || info.className === "degraded";
        const startRunning = serviceActions.has("start");
        const stopRunning = serviceActions.has("stop");
        const restartRunning = serviceActions.has("restart");

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
          button.addEventListener("click", () =>
            runServiceAction(button, entry.hostId, entry.projectName, serviceName, action)
          );
          return button;
        };

        const startBtn = createServiceActionButton(
          "play_arrow",
          "Start service (docker compose start)",
          "start"
        );
        const stopBtn = createServiceActionButton(
          "stop",
          "Stop service (docker compose stop)",
          "stop"
        );
        const restartBtn = createServiceActionButton(
          "replay",
          "Restart service (docker compose restart)",
          "restart"
        );

        const showStart = startRunning || !serviceRunning;
        const showStop = stopRunning || serviceRunning;
        const showRestart = restartRunning || serviceRunning;

        setActionRunning(startBtn, startRunning);
        setActionRunning(stopBtn, stopRunning);
        setActionRunning(restartBtn, restartRunning);

        startBtn.classList.toggle("hidden", !showStart);
        stopBtn.classList.toggle("hidden", !showStop);
        restartBtn.classList.toggle("hidden", !showRestart);

        const logsBtn = document.createElement("button");
        logsBtn.className = "btn ghost service-action";
        logsBtn.setAttribute("aria-label", "Service logs");
        logsBtn.title = "Service logs";
        const logsIcon = document.createElement("span");
        logsIcon.className = "material-symbols-outlined action-icon";
        logsIcon.textContent = "article";
        logsBtn.appendChild(logsIcon);
        logsBtn.addEventListener("click", () =>
          openLogsModal(entry.hostId, entry.projectName, serviceName)
        );

        actions.appendChild(startBtn);
        actions.appendChild(stopBtn);
        actions.appendChild(restartBtn);
        actions.appendChild(logsBtn);

        item.appendChild(details);
        item.appendChild(iconsWrap);
        item.appendChild(actions);
        servicesList.appendChild(item);
      });
    }

    servicesSummary.addEventListener("click", () => {
      const isHidden = servicesPanel.classList.toggle("hidden");
      servicesSummary.classList.toggle("open", !isHidden);
    });

    row.querySelectorAll(".project-action").forEach((actionBtn) => {
      const action = actionBtn.dataset.action;
      if (!action) {
        return;
      }
      actionBtn.addEventListener("click", () =>
        runProjectAction(actionBtn, entry.hostId, entry.projectName, action)
      );
    });

    const logsBtn = row.querySelector(".logs");
    logsBtn.addEventListener("click", () =>
      openLogsModal(entry.hostId, entry.projectName)
    );

    const composeBtn = row.querySelector(".compose");
    composeBtn.addEventListener("click", () => openComposeModal(entry.hostId, entry.projectName));

    projectList.appendChild(row);
  });
  updateBulkVisibility();
  updateBulkBackupAvailability();
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

function selectAllHosts() {
  state.selectedHosts = new Set(state.hosts.map((host) => host.host_id));
  renderLists();
}

function clearHosts() {
  state.selectedHosts = new Set();
  renderLists();
}

function selectAllProjects() {
  const entries = buildProjectEntries();
  state.selectedProjects = new Set(entries.map((entry) => entry.key));
  renderProjectList();
}

function clearProjects() {
  state.selectedProjects = new Set();
  renderProjectList();
}

function getSelectedProjectEntries() {
  const entries = buildProjectEntries();
  return entries.filter((entry) => state.selectedProjects.has(entry.key));
}

async function runProjectAction(button, hostId, projectName, action) {
  const label = action.charAt(0).toUpperCase() + action.slice(1);
  const originalLabel = button.dataset.originalLabel || getActionLabel(button) || label;
  button.dataset.originalLabel = originalLabel;
  const isBackup = action === "backup";
  const projectKey = `${hostId}::${projectName}`;
  const isRunning = button.dataset.actionRunning === "true";

  if (isBackup && !state.backupTargetsAvailable) {
    showToast("No enabled backup targets.", "error");
    return;
  }

  if (isRunning) {
    button.disabled = true;
    try {
      if (action === "refresh") {
        return;
      }
      if (isBackup) {
        await api.post(`/hosts/${hostId}/projects/${projectName}/backup/stop`);
      } else {
        await api.post(
          `/hosts/${hostId}/projects/${projectName}/actions/${action}/stop`
        );
      }
    } catch (err) {
      alert(`Stop failed: ${err.message}`);
    } finally {
      button.disabled = false;
    }
    return;
  }

  setActionRunning(button, true);
  setActionProgress(projectKey, action, true);
  let backupRow = null;
  let shouldRefresh = false;
  let completionMessage = "";
  try {
    if (action === "refresh") {
      await api.post(
        `/hosts/${hostId}/projects/${projectName}/state/refresh`
      );
      shouldRefresh = true;
      completionMessage = "Refresh complete";
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
    showToast(`${projectName}: ${completionMessage}`);
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
    setActionRunning(button, false);
    button.disabled = false;
    if (!isBackup) {
      setActionLabel(button, originalLabel);
    }
    if (shouldRefresh) {
      if (action === "update") {
        await loadState();
      } else if (action === "refresh") {
        await loadState();
      } else {
        await refreshHosts([hostId]);
      }
    }
  }
}

async function runServiceAction(button, hostId, projectName, serviceName, action) {
  const isRunning = button.dataset.actionRunning === "true";
  const serviceKeyValue = serviceActionKey(hostId, projectName, serviceName);
  const encodedService = encodeURIComponent(serviceName);

  if (isRunning) {
    button.disabled = true;
    try {
      await api.post(
        `/hosts/${hostId}/projects/${projectName}/services/${encodedService}/actions/${action}/stop`
      );
    } catch (err) {
      alert(`Stop failed: ${err.message}`);
    } finally {
      button.disabled = false;
    }
    return;
  }

  setActionRunning(button, true);
  setServiceActionProgress(serviceKeyValue, action, true);
  let shouldRefresh = false;
  let completionMessage = "";
  try {
    const result = await runServiceActionStream(hostId, projectName, serviceName, action);
    completionMessage = result?.message || "Action complete";
    shouldRefresh = true;
    showToast(`${serviceName}: ${completionMessage}`);
  } catch (err) {
    alert(`Service action failed: ${err.message}`);
  } finally {
    setServiceActionProgress(serviceKeyValue, action, false);
    setActionRunning(button, false);
    button.disabled = false;
    if (shouldRefresh) {
      await refreshHosts([hostId]);
    }
  }
}

function setBulkProgress(action, current, total, currentTarget = "") {
  if (!total) {
    bulkProgress.classList.add("hidden");
    bulkProgressBar.style.width = "0%";
    bulkProgressText.textContent = "";
    return;
  }
  let label = action === "update" ? "Updating" : `Running ${action}`;
  if (action === "sleep") {
    label = "Sleeping";
  } else if (action === "wake") {
    label = "Waking";
  }
  const targetText = currentTarget ? ` • ${currentTarget}` : "";
  bulkProgressText.textContent = `${label} ${current}/${total}${targetText}`;
  bulkProgressBar.style.width = `${Math.round((current / total) * 100)}%`;
  bulkProgress.classList.remove("hidden");
}


function updateBulkVisibility() {
  if (!bulkActions) {
    return;
  }
  if (state.selectedProjects.size > 1) {
    bulkActions.classList.remove("hidden");
  } else {
    bulkActions.classList.add("hidden");
    setBulkProgress("", 0, 0);
  }
}

function updateBulkBackupAvailability() {
  if (!bulkActions) {
    return;
  }
  const backupBtn = bulkActions.querySelector(
    ".bulk-action[data-bulk-action=\"backup\"]"
  );
  if (backupBtn) {
    backupBtn.disabled = !state.backupTargetsAvailable;
  }
}

async function runBulkAction(action) {
  const selected = getSelectedProjectEntries();
  if (!selected.length) {
    alert("Select one or more projects first.");
    return;
  }
  if (action === "backup" && !state.backupTargetsAvailable) {
    alert("No enabled backup targets.");
    return;
  }

  const buttons = document.querySelectorAll(".bulk-action");
  buttons.forEach((btn) => {
    btn.disabled = true;
  });
  if (stateStatus) {
    stateStatus.textContent = `Running ${action} on ${selected.length} projects...`;
  }
  setBulkProgress(action, 0, selected.length);

  const failures = [];
  let completed = 0;
  const rows = document.querySelectorAll(".list-row.project-row");
  rows.forEach((row) => row.classList.remove("working"));
  for (const entry of selected) {
    const currentTarget = `${entry.hostId}/${entry.projectName}`;
    const row = document.querySelector(`[data-project-key="${entry.key}"]`);
    document
      .querySelectorAll(".list-row.project-row.working")
      .forEach((item) => item.classList.remove("working"));
    if (row) {
      row.classList.add("working");
    }
    let entryFailed = false;
    if (["start", "stop", "restart", "update", "backup"].includes(action)) {
      setActionProgress(entry.key, action, true);
      const actionBtn = row?.querySelector(
        `.project-action[data-action="${action}"]`
      );
      if (actionBtn) {
        setActionRunning(actionBtn, true);
      }
    }
    try {
      if (action === "backup") {
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
            const finalLabel = payload.stopped ? "Backup stopped" : "Backup complete";
            bulkProgressText.textContent = `${finalLabel} • ${currentTarget}`;
            bulkProgressBar.style.width = `${Math.round(
              ((completed + 1) / selected.length) * 100
            )}%`;
            return;
          }
          const stepLabel = formatBackupStep(payload.step, payload.message);
          const stepIndex = backupStepIndex(payload.step);
          const fraction =
            (completed + stepIndex / totalSteps) / selected.length;
          bulkProgressText.textContent = `Backing up ${completed + 1}/${selected.length} • ${currentTarget} • ${stepLabel}`;
          bulkProgressBar.style.width = `${Math.round(fraction * 100)}%`;
          bulkProgress.classList.remove("hidden");
        });
      } else {
        await api.post(
          `/hosts/${entry.hostId}/projects/${entry.projectName}/${action}`
        );
      }
    } catch (err) {
      entryFailed = true;
      failures.push(`${entry.hostId}/${entry.projectName}: ${err.message}`);
    }
    completed += 1;
    if (action === "backup") {
      setBulkProgress("backup", completed, selected.length, currentTarget);
    } else {
      setBulkProgress(action, completed, selected.length, currentTarget);
    }
    if (["start", "stop", "restart", "update", "backup"].includes(action)) {
      setActionProgress(entry.key, action, false);
      const actionBtn = row?.querySelector(
        `.project-action[data-action="${action}"]`
      );
      if (actionBtn) {
        setActionRunning(actionBtn, false);
      }
    }
    if (row) {
      row.classList.remove("working");
    }
  }

  if (action === "update") {
    await loadState();
  } else {
    const hostsToRefresh = Array.from(new Set(selected.map((entry) => entry.hostId)));
    await refreshHosts(hostsToRefresh);
  }
  buttons.forEach((btn) => {
    btn.disabled = false;
  });
  setBulkProgress(action, 0, 0);

  const summaryMessage = failures.length
    ? `Bulk ${action} complete with errors`
    : `Bulk ${action} complete`;
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
    button.disabled = false;
  }
  if (success) {
    showToast(`${hostId}: ${response?.output || `${label} complete`}`);
    await refreshHosts([hostId]);
  }
}

async function runHostQuickAction(button, hostId, action, handler) {
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
    state.updatesEnabled = state.stateSnapshot?.updates_enabled !== false;
    updateIntervalVisibility();
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
}

async function initApp(forceReload = false) {
  if (state.initialized && !forceReload) {
    return;
  }
  try {
    await loadHosts();
    await loadBackupScheduleStatus();
    await loadBackupTargetsAvailability();
    await loadState();
    state.initialized = true;
  } catch (err) {
    hostList.innerHTML = "";
    const hostError = document.createElement("li");
    hostError.className = "list-row empty";
    hostError.textContent = `Failed to load data: ${err.message}`;
    hostList.appendChild(hostError);
    projectList.innerHTML = "";
    const projectError = document.createElement("li");
    projectError.className = "list-row empty";
    projectError.textContent = "Projects unavailable.";
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

composeEditor.addEventListener("input", () => {
  diffPanel.classList.add("hidden");
  confirmComposeBtn.classList.add("hidden");
  composeStatus.textContent = "";
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
});

previewComposeBtn.addEventListener("click", () => {
  const original = composeEditor.dataset.original || "";
  const current = composeEditor.value || "";
  if (original === current) {
    composeStatus.textContent = "No changes to save.";
    diffPanel.classList.add("hidden");
    confirmComposeBtn.classList.add("hidden");
    return;
  }
  const diff = buildDiff(original, current);
  diffContent.innerHTML = renderDiff(diff);
  diffPanel.classList.remove("hidden");
  confirmComposeBtn.classList.remove("hidden");
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
  composeStatus.textContent = "Validating...";
  composeLint.classList.add("hidden");
  composeLint.textContent = "";
  try {
    const validation = await api.post(
      `/hosts/${composeState.hostId}/projects/${composeState.projectName}/compose/validate`,
      { content: composeEditor.value }
    );
    if (!validation.ok) {
      composeStatus.textContent = "Validation failed.";
      composeLint.textContent = validation.output || "Compose validation failed.";
      composeLint.classList.remove("hidden");
      return;
    }
    if (validation.output) {
      composeLint.textContent = validation.output;
      composeLint.classList.remove("hidden");
    }
    composeStatus.textContent = "Saving...";
    await api.put(
      `/hosts/${composeState.hostId}/projects/${composeState.projectName}/compose`,
      { content: composeEditor.value }
    );
    composeEditor.dataset.original = composeEditor.value;
    composeStatus.textContent = "Saved.";
    diffPanel.classList.add("hidden");
    confirmComposeBtn.classList.add("hidden");
    await refreshHosts([composeState.hostId]);
  } catch (err) {
    composeStatus.textContent = `Error: ${err.message}`;
  } finally {
    confirmComposeBtn.disabled = false;
  }
});

closeComposeModalBtn.addEventListener("click", closeComposeModal);
composeModal
  .querySelector(".modal-backdrop")
  .addEventListener("click", closeComposeModal);
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  if (!composeModal.classList.contains("hidden")) {
    closeComposeModal();
  }
  if (!logsModal.classList.contains("hidden")) {
    closeLogsModal();
  }
  if (backupScheduleModal && !backupScheduleModal.classList.contains("hidden")) {
    closeBackupScheduleModal();
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
openBackupScheduleBtn.addEventListener("click", openBackupScheduleModal);
closeBackupScheduleModalBtn.addEventListener("click", closeBackupScheduleModal);
backupScheduleModal
  .querySelector(".modal-backdrop")
  .addEventListener("click", closeBackupScheduleModal);
if (openCreateProjectBtn) {
  openCreateProjectBtn.addEventListener("click", openCreateProjectModal);
}
if (closeCreateProjectModalBtn) {
  closeCreateProjectModalBtn.addEventListener("click", closeCreateProjectModal);
}
if (createProjectCancel) {
  createProjectCancel.addEventListener("click", closeCreateProjectModal);
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
if (logoutBtn) {
  logoutBtn.addEventListener("click", () => {
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
if (saveIntervalsBtn) {
  saveIntervalsBtn.addEventListener("click", saveIntervals);
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
selectAllHostsBtn.addEventListener("click", selectAllHosts);
clearHostsBtn.addEventListener("click", clearHosts);
selectAllProjectsBtn.addEventListener("click", selectAllProjects);
clearProjectsBtn.addEventListener("click", clearProjects);
document.querySelectorAll(".bulk-action").forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.dataset.bulkAction;
    if (action) {
      runBulkAction(action);
    }
  });
});

init();
