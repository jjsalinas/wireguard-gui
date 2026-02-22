// WireGuard GUI — gui.js
// State management, validation, config generation

/*****************************************************************************
 * State
 *****************************************************************************/

let state = {
  server: {
    iface: "",
    address: "",
    port: "",
    lanBetweenClients: false,
    allowedPorts: "",
    privateKey: "",
    publicKey: "",
    publicAddress: "",
    docker: false,
    dockerIface: "",
  },
  clients: [],
};

let activeClientId = null;
let clientCounter = 0;

/*****************************************************************************
 * Validation index
 * Each entry: { regex, hint, optional, isBool }
 * - isBool:   skips regex check entirely (checkboxes)
 * - optional: empty string is accepted as valid
 * - extra:    additional predicate run after regex passes
 *****************************************************************************/

const SERVER_VALIDATORS = {
  iface: {
    regex: /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/,
    hint: "Interface name: letters, numbers, dash, underscore (max 15 chars)",
  },
  address: {
    regex: /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
    hint: "CIDR notation required, e.g. 10.0.0.1/24",
    extra: (v) => {
      const [ip, prefix] = v.split("/");
      const parts = ip.split(".").map(Number);
      return (
        parts.every((p) => p >= 0 && p <= 255) && +prefix >= 0 && +prefix <= 32
      );
    },
  },
  port: {
    regex: /^\d{1,5}$/,
    hint: "Port number between 1 and 65535",
    extra: (v) => +v >= 1 && +v <= 65535,
  },
  lanBetweenClients: { isBool: true },
  allowedPorts: {
    regex: /^(\d{1,5}(\s*,\s*\d{1,5})*)?$/,
    hint: "Comma-separated port numbers, e.g. 22, 80, 443",
    optional: true,
  },
  privateKey: {
    regex: /^[A-Za-z0-9+/]{43}=$/,
    hint: "WireGuard base64 private key (44 chars ending in =)",
  },
  publicKey: {
    regex: /^[A-Za-z0-9+/]{43}=$/,
    hint: "WireGuard base64 public key (44 chars ending in =)",
  },
  publicAddress: {
    regex: /^[a-zA-Z0-9.-]+$/,
    hint: "Hostname or IP address, e.g. vpn.example.com or 203.0.113.1",
  },
  docker: { isBool: true },
  dockerIface: {
    regex: /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/,
    hint: "Docker host interface name, e.g. eth0 or enp1s0",
    optional: true,
  },
};

const CLIENT_VALIDATORS = {
  name: {
    regex: /^.{1,32}$/,
    hint: "Client name required (max 32 chars)",
  },
  internetTraffic: { isBool: true },
  privateKey: {
    regex: /^[A-Za-z0-9+/]{43}=$/,
    hint: "WireGuard base64 private key (44 chars ending in =)",
  },
  publicKey: {
    regex: /^[A-Za-z0-9+/]{43}=$/,
    hint: "WireGuard base64 public key (44 chars ending in =)",
  },
};

/*****************************************************************************
 * Validation helpers
 *****************************************************************************/

/**
 * Runs the validator spec for a single field against a given value.
 *
 * Looks up the field key in the provided validators map and applies, in order:
 * the isBool shortcut, the optional-empty shortcut, the regex test, and any
 * extra predicate. Returns a result object so the caller can decide how to
 * surface the error.
 *
 * @param {Object} validators - One of SERVER_VALIDATORS or CLIENT_VALIDATORS.
 * @param {string} fieldKey   - Key matching an entry in the validators map.
 * @param {string} value      - Current field value to test.
 * @returns {{ valid: boolean, hint?: string }}
 */
function validateValue(validators, fieldKey, value) {
  const spec = validators[fieldKey];
  if (!spec) return { valid: true };
  if (spec.isBool) return { valid: true };
  if (spec.optional && (value === "" || value === undefined || value === null))
    return { valid: true };
  if (!spec.regex) return { valid: true };
  if (!spec.regex.test(String(value))) return { valid: false, hint: spec.hint };
  if (spec.extra && !spec.extra(value))
    return { valid: false, hint: spec.hint };
  return { valid: true };
}

/**
 * Applies or clears visual validation state on an input element.
 *
 * Toggles the field-invalid / field-valid CSS classes and injects or removes
 * a .field-hint <span> inside the parent .field-row. Safe to call repeatedly;
 * it updates the existing hint element rather than appending duplicates.
 *
 * @param {HTMLInputElement} inputEl - The input to decorate.
 * @param {boolean}          valid   - Whether the current value is valid.
 * @param {string}           [hint]  - Error message shown below the input.
 */
function markField(inputEl, valid, hint) {
  const wrapper = inputEl.closest(".field-row") || inputEl.parentElement;
  const existingHint = wrapper.querySelector(".field-hint");

  inputEl.classList.toggle("field-invalid", !valid);
  inputEl.classList.toggle("field-valid", valid);

  if (!valid && hint) {
    if (!existingHint) {
      const hintEl = document.createElement("span");
      hintEl.className = "field-hint";
      hintEl.textContent = hint;
      wrapper.appendChild(hintEl);
    } else {
      existingHint.textContent = hint;
    }
  } else if (existingHint) {
    existingHint.remove();
  }
}

/*****************************************************************************
 * IP utilities
 *****************************************************************************/

/** Returns the host part of a CIDR string, e.g. "10.0.0.1/24" -> "10.0.0.1". */
function parseBaseIP(cidr) {
  return cidr ? cidr.split("/")[0] : "";
}

/** Returns the prefix length of a CIDR string, defaulting to "24". */
function parsePrefix(cidr) {
  return cidr && cidr.includes("/") ? cidr.split("/")[1] : "24";
}

/** Converts a dotted-decimal IPv4 string to a 32-bit unsigned integer. */
function ipToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0);
}

/** Converts a 32-bit unsigned integer back to a dotted-decimal IPv4 string. */
function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255,
  ].join(".");
}

/**
 * Returns the network base address for a CIDR, e.g. "10.0.0.3/24" -> "10.0.0.0/24".
 * Used to build the AllowedIPs line in client configs.
 *
 * @param {string} cidr - e.g. "10.0.0.1/24"
 * @returns {string}    - e.g. "10.0.0.0/24"
 */
function getNetworkAddress(cidr) {
  const [ip, prefix] = cidr.split("/");
  const mask = prefix === "0" ? 0 : (~0 << (32 - +prefix)) >>> 0;
  return intToIp((ipToInt(ip) & mask) >>> 0) + "/" + prefix;
}

/**
 * Derives the IP address to assign to a specific client.
 *
 * Clients are allocated sequentially from the server's own address.
 * e.g. if the server is 10.0.0.1/24, client 1 gets 10.0.0.2/24,
 * client 2 gets 10.0.0.3/24, and so on.
 *
 * @param {string} serverCIDR  - Server address in CIDR notation.
 * @param {number} clientIndex - 1-based index of the client.
 * @returns {string}           - Client CIDR, e.g. "10.0.0.2/24".
 */
function getClientIP(serverCIDR, clientIndex) {
  const [ip] = serverCIDR.split("/");
  const prefix = parsePrefix(serverCIDR);
  const parts = ip.split(".").map(Number);
  parts[3] = parts[3] + clientIndex;
  return parts.join(".") + "/" + prefix;
}

/*****************************************************************************
 * Config generators
 *****************************************************************************/

/**
 * Builds the complete wg0.conf text for the server side.
 *
 * Assembles the [Interface] block with all iptables PostUp/PostDown rules,
 * then appends a [Peer] block for every client that has a public key set.
 * Rules vary based on: NAT/internet forwarding (always on), LAN-between-clients
 * flag, per-port DNAT forwards, and whether the server runs inside Docker
 * (which changes the outbound interface used in iptables rules).
 *
 * @returns {string} Full .conf file content, or a placeholder comment if
 *                   required fields are missing.
 */
function generateServerConf() {
  const s = state.server;
  if (!s.iface || !s.address || !s.port || !s.privateKey) {
    return "# Fill in required server fields (Interface, Address, Port, Private Key) and click Sync";
  }

  // When running in Docker the host's physical interface is used for iptables
  // rules rather than the WireGuard interface itself.
  const outIface = s.docker && s.dockerIface ? s.dockerIface : s.iface;
  const ports = s.allowedPorts
    ? s.allowedPorts
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean)
    : [];
  const serverIP = parseBaseIP(s.address);

  let lines = [];

  lines.push("[Interface]");
  lines.push(`Address = ${s.address}`);
  lines.push("SaveConfig = false");
  lines.push("");

  lines.push("# Internet access for VPN clients");
  lines.push(
    `PostUp = iptables -A FORWARD -i ${s.iface} -o ${outIface} -j ACCEPT`,
  );
  lines.push(
    `PostUp = iptables -A FORWARD -i ${outIface} -o ${s.iface} -m state --state RELATED,ESTABLISHED -j ACCEPT`,
  );
  lines.push(
    `PostUp = iptables -t nat -A POSTROUTING -o ${outIface} -j MASQUERADE`,
  );

  if (s.lanBetweenClients) {
    lines.push("");
    lines.push("# Allow VPN clients to talk to each other");
    lines.push(
      `PostUp = iptables -A FORWARD -i ${s.iface} -o ${s.iface} -j ACCEPT`,
    );
  }

  ports.forEach((port) => {
    lines.push("");
    lines.push(`# Port ${port} forward`);
    lines.push(
      `PostUp = iptables -t nat -A PREROUTING -i ${outIface} -p tcp --dport ${port} -j DNAT --to-destination ${serverIP}:${port}`,
    );
    lines.push(
      `PostUp = iptables -A FORWARD -i ${outIface} -o ${s.iface} -p tcp --dport ${port} -j ACCEPT`,
    );
  });

  lines.push("");
  lines.push("# Cleanup");
  lines.push(
    `PostDown = iptables -D FORWARD -i ${s.iface} -o ${outIface} -j ACCEPT`,
  );
  lines.push(
    `PostDown = iptables -D FORWARD -i ${outIface} -o ${s.iface} -m state --state RELATED,ESTABLISHED -j ACCEPT`,
  );
  lines.push(
    `PostDown = iptables -t nat -D POSTROUTING -o ${outIface} -j MASQUERADE`,
  );

  if (s.lanBetweenClients) {
    lines.push(
      `PostDown = iptables -D FORWARD -i ${s.iface} -o ${s.iface} -j ACCEPT`,
    );
  }

  ports.forEach((port) => {
    lines.push(
      `PostDown = iptables -t nat -D PREROUTING -i ${outIface} -p tcp --dport ${port} -j DNAT --to-destination ${serverIP}:${port}`,
    );
    lines.push(
      `PostDown = iptables -D FORWARD -i ${outIface} -o ${s.iface} -p tcp --dport ${port} -j ACCEPT`,
    );
  });

  lines.push("");
  lines.push(`ListenPort = ${s.port}`);
  lines.push(`PrivateKey = ${s.privateKey}`);

  state.clients.forEach((client, idx) => {
    if (!client.publicKey) return;
    const clientAddr = getClientIP(s.address, idx + 1);
    const clientIP = parseBaseIP(clientAddr);
    lines.push("");
    lines.push(`# ${client.name || "Client " + (idx + 1)}`);
    lines.push("[Peer]");
    lines.push(`PublicKey = ${client.publicKey}`);
    lines.push(`AllowedIPs = ${clientIP}/32`);
    lines.push(
      `#Endpoint = ${s.publicAddress || "<server-public-address>"}:${s.port}`,
    );
  });

  return lines.join("\n");
}

/**
 * Builds the client-side .conf text for a single peer.
 *
 * The AllowedIPs line differs based on the client's internetTraffic flag:
 * when true, 0.0.0.0/0 is included so all traffic routes through the VPN;
 * when false, only the VPN subnet is routed (LAN-only access).
 *
 * @param {Object} client      - Client object from state.clients.
 * @param {number} clientIndex - 0-based index in state.clients, used to
 *                               derive this client's VPN IP address.
 * @returns {string} Full .conf file content.
 */
function generateClientConf(client, clientIndex) {
  const s = state.server;
  if (!client) return "";

  const clientAddr = getClientIP(s.address, clientIndex + 1);
  const networkBase = s.address ? getNetworkAddress(s.address) : "10.0.0.0/24";
  const allowedIPs = client.internetTraffic
    ? `${networkBase}, 0.0.0.0/0`
    : networkBase;

  let lines = [];
  lines.push("# Client configuration");
  lines.push("[Interface]");
  lines.push(`Address = ${clientAddr || "<client-address>/<prefix>"}`);
  lines.push("DNS = 1.1.1.1");
  lines.push(`PrivateKey = ${client.privateKey || "<client-private-key>"}`);
  lines.push("");
  lines.push("# Server configuration");
  lines.push("[Peer]");
  lines.push(`PublicKey = ${s.publicKey || "<server-public-key>"}`);
  lines.push(`AllowedIPs = ${allowedIPs}`);
  lines.push(
    `Endpoint = ${s.publicAddress || "<server-public-address>"}:${s.port || "<port>"}`,
  );
  lines.push("PersistentKeepalive = 25");

  return lines.join("\n");
}

/*****************************************************************************
 * DOM helpers
 *****************************************************************************/

/** Shorthand for document.getElementById. */
function $(id) {
  return document.getElementById(id);
}

/** Reads all server form inputs into a plain object matching the state shape. */
function getServerFormValues() {
  return {
    iface: $("s-iface").value.trim(),
    address: $("s-address").value.trim(),
    port: $("s-port").value.trim(),
    lanBetweenClients: $("s-lan").checked,
    allowedPorts: $("s-ports").value.trim(),
    privateKey: $("s-privkey").value.trim(),
    publicKey: $("s-pubkey").value.trim(),
    publicAddress: $("s-pubaddr").value.trim(),
    docker: $("s-docker").checked,
    dockerIface: $("s-docker-iface").value.trim(),
  };
}

/**
 * Reads the currently visible client form inputs.
 * Returns safe defaults when the form elements don't exist (no active client).
 */
function getActiveClientFormValues() {
  return {
    name: $("c-name") ? $("c-name").value.trim() : "",
    internetTraffic: $("c-internet") ? $("c-internet").checked : true,
    privateKey: $("c-privkey") ? $("c-privkey").value.trim() : "",
    publicKey: $("c-pubkey") ? $("c-pubkey").value.trim() : "",
  };
}

/**
 * Writes server state back into all form inputs and updates toggle labels.
 * Called after loading a JSON config file.
 */
function populateServerForm() {
  const s = state.server;
  $("s-iface").value = s.iface;
  $("s-address").value = s.address;
  $("s-port").value = s.port;
  $("s-lan").checked = s.lanBetweenClients;
  $("s-ports").value = s.allowedPorts;
  $("s-privkey").value = s.privateKey;
  $("s-pubkey").value = s.publicKey;
  $("s-pubaddr").value = s.publicAddress;
  $("s-docker").checked = s.docker;
  $("s-docker-iface").value = s.dockerIface;

  const lanLabel = $("s-lan-label");
  if (lanLabel)
    lanLabel.textContent = s.lanBetweenClients ? "Enabled" : "Disabled";
  const dockerLabel = $("s-docker-label");
  if (dockerLabel) dockerLabel.textContent = s.docker ? "Yes" : "No";

  toggleDockerField();
}

/** Shows or hides the Docker host interface row based on the Docker checkbox. */
function toggleDockerField() {
  const dockerRow = $("docker-iface-row");
  if (dockerRow) {
    dockerRow.style.display = $("s-docker").checked ? "flex" : "none";
  }
}

/*****************************************************************************
 * Client panel
 *****************************************************************************/

/**
 * Re-renders the client tab strip from state.clients.
 *
 * Creates one button per client. The active tab gets the .active class.
 * Each tab includes an x delete button that stops click propagation so it
 * doesn't also trigger the tab-switch handler.
 */
function renderClientTabs() {
  const tabsEl = $("client-tabs");
  tabsEl.innerHTML = "";

  state.clients.forEach((client) => {
    const tab = document.createElement("button");
    tab.className =
      "client-tab" + (client.id === activeClientId ? " active" : "");
    tab.textContent = client.name || "Client";
    tab.title = client.name;
    tab.addEventListener("click", () => {
      saveActiveClient();
      activeClientId = client.id;
      renderClientTabs();
      renderClientForm();
      updateClientConf();
    });

    const del = document.createElement("span");
    del.className = "tab-del";
    del.textContent = "x";
    del.title = "Remove client";
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      removeClient(client.id);
    });

    tab.appendChild(del);
    tabsEl.appendChild(tab);
  });
}

/**
 * Renders the client form area for the currently active client.
 *
 * Injects HTML for all client fields, then wires up live validation listeners
 * and the name-change handler that keeps the tab label in sync. Shows an
 * empty-state placeholder when no client is selected.
 */
function renderClientForm() {
  const formEl = $("client-form-area");

  if (!activeClientId || state.clients.length === 0) {
    formEl.innerHTML = `<div class="empty-client">
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/>
      </svg>
      <p>Add a client to get started</p>
    </div>`;
    return;
  }

  const client = state.clients.find((c) => c.id === activeClientId);
  if (!client) return;

  formEl.innerHTML = `
    <div class="field-row">
      <label for="c-name">Client name</label>
      <input id="c-name" type="text" value="${escHtml(client.name)}" placeholder="e.g. laptop, phone" />
    </div>
    <div class="field-row toggle-row">
      <label for="c-internet">Internet traffic</label>
      <label class="toggle-switch">
        <input id="c-internet" type="checkbox" ${client.internetTraffic ? "checked" : ""} />
        <span class="toggle-slider"></span>
      </label>
      <span class="toggle-label">${client.internetTraffic ? "Allowed" : "Blocked"}</span>
    </div>
    <div class="field-row">
      <label for="c-privkey">Private key</label>
      <input id="c-privkey" type="text" value="${escHtml(client.privateKey)}" placeholder="Base64 WireGuard key" class="mono-input" />
    </div>
    <div class="field-row">
      <label for="c-pubkey">Public key</label>
      <input id="c-pubkey" type="text" value="${escHtml(client.publicKey)}" placeholder="Base64 WireGuard key" class="mono-input" />
    </div>
  `;

  // Live validation for text fields
  const cFields = {
    "c-name": "name",
    "c-privkey": "privateKey",
    "c-pubkey": "publicKey",
  };
  Object.entries(cFields).forEach(([elId, fieldKey]) => {
    const el = $(elId);
    if (!el) return;
    el.addEventListener("input", () => {
      const result = validateValue(
        CLIENT_VALIDATORS,
        fieldKey,
        el.value.trim(),
      );
      markField(el, result.valid, result.hint);
    });
  });

  // Keep the toggle label in sync with the checkbox
  const internetToggle = $("c-internet");
  if (internetToggle) {
    internetToggle.addEventListener("change", () => {
      const label = internetToggle
        .closest(".toggle-row")
        .querySelector(".toggle-label");
      label.textContent = internetToggle.checked ? "Allowed" : "Blocked";
    });
  }

  // Reflect name changes immediately in the tab strip
  const nameInput = $("c-name");
  if (nameInput) {
    nameInput.addEventListener("input", () => {
      const clientRef = state.clients.find((c) => c.id === activeClientId);
      if (clientRef) {
        clientRef.name = nameInput.value.trim() || "Client";
        renderClientTabs();
      }
    });
  }
}

/** Flushes the currently visible client form values into the matching state.clients entry. */
function saveActiveClient() {
  if (!activeClientId) return;
  const client = state.clients.find((c) => c.id === activeClientId);
  if (!client) return;
  Object.assign(client, getActiveClientFormValues());
}

/** Creates a new client entry with defaults, appends it to state, and activates it. */
function addClient() {
  saveActiveClient();
  clientCounter++;
  const newClient = {
    id: "client-" + clientCounter,
    name: "Client " + clientCounter,
    internetTraffic: true,
    privateKey: "",
    publicKey: "",
  };
  state.clients.push(newClient);
  activeClientId = newClient.id;
  renderClientTabs();
  renderClientForm();
  updateClientConf();
}

/** Removes a client by id, falls back the active selection, and redraws. */
function removeClient(id) {
  state.clients = state.clients.filter((c) => c.id !== id);
  if (activeClientId === id) {
    activeClientId =
      state.clients.length > 0
        ? state.clients[state.clients.length - 1].id
        : null;
  }
  renderClientTabs();
  renderClientForm();
  syncAll();
}

/*****************************************************************************
 * Validation pass
 *****************************************************************************/

/**
 * Validates every server form field and marks each input accordingly.
 * Maps element IDs to their validator key and current value, then delegates
 * to validateValue + markField for each.
 *
 * @returns {boolean} True if all fields are valid.
 */
function validateServerForm() {
  const s = getServerFormValues();
  let allValid = true;

  const fieldMap = {
    "s-iface": ["iface", s.iface],
    "s-address": ["address", s.address],
    "s-port": ["port", s.port],
    "s-ports": ["allowedPorts", s.allowedPorts],
    "s-privkey": ["privateKey", s.privateKey],
    "s-pubkey": ["publicKey", s.publicKey],
    "s-pubaddr": ["publicAddress", s.publicAddress],
    "s-docker-iface": ["dockerIface", s.dockerIface],
  };

  Object.entries(fieldMap).forEach(([elId, [fieldKey, value]]) => {
    const el = $(elId);
    if (!el) return;
    const result = validateValue(SERVER_VALIDATORS, fieldKey, value);
    markField(el, result.valid, result.hint);
    if (!result.valid) allValid = false;
  });

  return allValid;
}

/**
 * Validates the active client's fields and marks each input accordingly.
 * No-ops cleanly when no client is selected.
 *
 * @returns {boolean} True if all fields are valid (or no client is active).
 */
function validateActiveClientForm() {
  if (!activeClientId) return true;
  saveActiveClient();

  const client = state.clients.find((c) => c.id === activeClientId);
  if (!client) return true;
  let allValid = true;

  const fieldMap = {
    "c-name": ["name", client.name],
    "c-privkey": ["privateKey", client.privateKey],
    "c-pubkey": ["publicKey", client.publicKey],
  };

  Object.entries(fieldMap).forEach(([elId, [fieldKey, value]]) => {
    const el = $(elId);
    if (!el) return;
    const result = validateValue(CLIENT_VALIDATORS, fieldKey, value);
    markField(el, result.valid, result.hint);
    if (!result.valid) allValid = false;
  });

  return allValid;
}

/*****************************************************************************
 * Sync and update
 *****************************************************************************/

/**
 * Main sync handler called by the Sync button.
 *
 * Commits form values to state, runs validation on both panels, regenerates
 * both config outputs, and flashes the button green on success.
 */
function syncAll() {
  state.server = getServerFormValues();
  saveActiveClient();

  const serverOk = validateServerForm();
  validateActiveClientForm();

  updateServerConf();
  updateClientConf();

  const btn = $("sync-btn");
  if (serverOk) {
    btn.classList.add("synced");
    setTimeout(() => btn.classList.remove("synced"), 1200);
  }
}

function updateServerConf() {
  const el = $("server-conf-output");
  if (el) el.textContent = generateServerConf();
}

function updateClientConf() {
  const el = $("client-conf-output");
  const titleEl = $("client-conf-name");
  if (!el) return;

  if (!activeClientId || state.clients.length === 0) {
    el.textContent = "# No client selected";
    if (titleEl) titleEl.textContent = "";
    return;
  }

  const idx = state.clients.findIndex((c) => c.id === activeClientId);
  const client = state.clients[idx];
  el.textContent = generateClientConf(client, idx);
  if (titleEl) titleEl.textContent = client.name || "Client";
}

/*****************************************************************************
 * Copy, download, load
 *****************************************************************************/

/**
 * Copies the text content of a config output element to the clipboard and
 * briefly updates the button label to give visual confirmation.
 *
 * @param {string} outputId - ID of the <pre> element containing the config.
 * @param {string} btnId    - ID of the button to flash "Copied!".
 */
function copyConf(outputId, btnId) {
  const text = $(outputId)?.textContent || "";
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const btn = $(btnId);
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("copied");
    }, 1500);
  });
}

/**
 * Serialises the current state (server + all clients) to a timestamped JSON
 * file and triggers a browser download.
 */
function downloadConfig() {
  state.server = getServerFormValues();
  saveActiveClient();

  const payload = {
    exportedAt: new Date().toISOString(),
    server: state.server,
    clients: state.clients,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `wireguard-config-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Opens a file picker for a previously saved JSON config, parses it, merges
 * it into state, and fully re-renders the UI. Shows a toast on success or
 * failure.
 */
function loadConfigFromFile() {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".json,application/json";
  input.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        if (data.server) state.server = { ...state.server, ...data.server };
        if (Array.isArray(data.clients)) state.clients = data.clients;
        if (state.clients.length > 0) {
          activeClientId = state.clients[state.clients.length - 1].id;
          clientCounter = state.clients.length;
        }
        populateServerForm();
        renderClientTabs();
        renderClientForm();
        syncAll();
        showToast("Configuration loaded");
      } catch {
        showToast("Failed to parse JSON file", true);
      }
    };
    reader.readAsText(file);
  });
  input.click();
}

/*****************************************************************************
 * Toast
 *****************************************************************************/

/**
 * Displays a transient notification at the bottom-right of the screen.
 *
 * @param {string}  msg       - Message to display.
 * @param {boolean} [isError] - If true, renders with error styling.
 */
function showToast(msg, isError = false) {
  const toast = document.createElement("div");
  toast.className = "toast" + (isError ? " toast-error" : "");
  toast.textContent = msg;
  document.body.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add("toast-show"));
  setTimeout(() => {
    toast.classList.remove("toast-show");
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

/*****************************************************************************
 * Utility
 *****************************************************************************/

/** Escapes a string for safe injection into HTML attribute values. */
function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/*****************************************************************************
 * Init
 *****************************************************************************/

/**
 * Bootstraps the application once the DOM is ready.
 *
 * Wires up all event listeners: live validation for server inputs, toggle
 * label updates, the Sync button, client add button, copy/download/load
 * buttons. Then performs an initial render so the UI is in a consistent
 * state before the user interacts.
 */
function init() {
  // Map element ID -> validator key for all server text inputs
  const serverFieldMap = {
    "s-iface": "iface",
    "s-address": "address",
    "s-port": "port",
    "s-ports": "allowedPorts",
    "s-privkey": "privateKey",
    "s-pubkey": "publicKey",
    "s-pubaddr": "publicAddress",
    "s-docker-iface": "dockerIface",
  };

  Object.entries(serverFieldMap).forEach(([elId, fieldKey]) => {
    const el = $(elId);
    if (!el) return;
    el.addEventListener("input", () => {
      const result = validateValue(
        SERVER_VALIDATORS,
        fieldKey,
        el.value.trim(),
      );
      markField(el, result.valid, result.hint);
    });
  });

  $("s-lan").addEventListener("change", () => {
    const label = $("s-lan-label");
    if (label) label.textContent = $("s-lan").checked ? "Enabled" : "Disabled";
  });

  $("s-docker").addEventListener("change", () => {
    const label = $("s-docker-label");
    if (label) label.textContent = $("s-docker").checked ? "Yes" : "No";
    toggleDockerField();
  });
  toggleDockerField();

  $("sync-btn").addEventListener("click", syncAll);
  $("add-client-btn").addEventListener("click", addClient);
  $("copy-server-btn").addEventListener("click", () =>
    copyConf("server-conf-output", "copy-server-btn"),
  );
  $("copy-client-btn").addEventListener("click", () =>
    copyConf("client-conf-output", "copy-client-btn"),
  );
  $("download-btn").addEventListener("click", downloadConfig);
  $("load-btn").addEventListener("click", loadConfigFromFile);

  renderClientTabs();
  renderClientForm();
  updateServerConf();
  updateClientConf();
}

document.addEventListener("DOMContentLoaded", init);
