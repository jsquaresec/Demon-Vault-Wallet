const privacyButton = document.getElementById("privacyToggle");
const portfolio = document.getElementById("portfolioValue");
const balances = Array.from(document.querySelectorAll("[data-balance]"));
const securityList = document.getElementById("securityList");
const securitySummary = document.getElementById("securitySummary");
let hidden = false;

privacyButton.addEventListener("click", () => {
  hidden = !hidden;
  privacyButton.textContent = hidden ? "Show balances" : "Hide balances";
  portfolio.textContent = hidden ? "$••••••" : "$0.00";
  balances.forEach((node) => {
    if (!node.dataset.value) node.dataset.value = node.textContent;
    node.textContent = hidden ? "••••••••" : node.dataset.value;
  });
});

function renderSecurity(raw) {
  const rows = raw.split("\n").filter(Boolean).map((line) => {
    const [category, control, assurance, detail] = line.split("|");
    return { category, control, assurance, detail };
  });
  securityList.replaceChildren();
  rows.forEach((row) => {
    const item = document.createElement("div");
    item.className = "security-row";
    const copy = document.createElement("div");
    const control = document.createElement("strong");
    control.textContent = row.control;
    const detail = document.createElement("span");
    detail.textContent = row.detail;
    copy.append(control, detail);
    const badge = document.createElement("em");
    badge.className = `assurance ${row.assurance}`;
    badge.textContent = row.assurance.toUpperCase();
    item.append(copy, badge);
    securityList.append(item);
  });
  const verified = rows.filter((row) => row.assurance === "verified").length;
  const unknown = rows.filter((row) => row.assurance === "unknown").length;
  securitySummary.textContent = `${verified} verified · ${unknown} unknown · no unsupported claims`;
}

async function loadSecurity() {
  try {
    if (window.__TAURI__?.core?.invoke) {
      renderSecurity(await window.__TAURI__.core.invoke("security_status"));
    }
  } catch {
    securitySummary.textContent = "Security state unavailable";
  }
}
loadSecurity();


async function loadMonero() {
  const nodeStatus = document.getElementById("moneroNodeStatus");
  const details = document.getElementById("moneroDetails");
  try {
    if (!window.__TAURI__?.core?.invoke) return;
    const raw = await window.__TAURI__.core.invoke("monero_status");
    const values = Object.fromEntries(raw.split(";").map((part) => part.split("=")));
    nodeStatus.textContent = `${values.mode} · ${values.network}`;
    details.replaceChildren();
    [
      ["Network", values.network],
      ["Node mode", values.mode],
      ["Wallet keys", values.keys],
      ["Remote trust", values["remote-trust"]],
    ].forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "check-row";
      const left = document.createElement("span");
      left.textContent = label;
      const right = document.createElement("strong");
      right.className = value === "local-only" ? "good" : "pending";
      right.textContent = value;
      row.append(left, right);
      details.append(row);
    });
  } catch {
    nodeStatus.textContent = "Monero state unavailable";
    details.textContent = "Unable to read Monero configuration from the Rust core.";
  }
}
loadMonero();


async function loadZcash() {
  const status = document.getElementById("zcashStatus");
  const details = document.getElementById("zcashDetails");
  try {
    if (!window.__TAURI__?.core?.invoke) return;
    const raw = await window.__TAURI__.core.invoke("zcash_status");
    const values = Object.fromEntries(raw.split(";").map((part) => part.split("=")));
    status.textContent = `${values.privacy} · ${values.network}`;
    details.replaceChildren();
    [
      ["Network", values.network],
      ["Privacy policy", values.privacy],
      ["Transparent addresses", values.transparent],
      ["Shielded scanner", values.scanner],
      ["Signer", values.signer],
      ["Backend trust", values.backend],
    ].forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "check-row";
      const left = document.createElement("span");
      left.textContent = label;
      const right = document.createElement("strong");
      right.className = value === "local-only" || value === "shielded-required" ? "good" : "pending";
      right.textContent = value;
      row.append(left, right);
      details.append(row);
    });
  } catch {
    status.textContent = "Zcash state unavailable";
    details.textContent = "Unable to read Zcash configuration from the Rust core.";
  }
}
loadZcash();


async function loadSwapDesk() {
  const details = document.getElementById("swapdeskDetails");
  try {
    if (!window.__TAURI__?.core?.invoke || !details) return;
    const raw = await window.__TAURI__.core.invoke("swapdesk_status");
    const values = Object.fromEntries(raw.split(";").map((part) => part.split("=")));
    details.replaceChildren();
    [
      ["Provider boundary", values["provider-boundary"]],
      ["Webhook transport", values["webhook-transport"]],
      ["Webhook configured", values["webhook-configured"]],
      ["Anonymous schema", values["anonymous-schema"]],
      ["Notification fields", values["notification-fields"]],
    ].forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "check-row";
      const left = document.createElement("span");
      left.textContent = label;
      const right = document.createElement("strong");
      right.className = value === "true" ? "good" : "pending";
      right.textContent = value;
      row.append(left, right);
      details.append(row);
    });
  } catch {
    details.textContent = "Unable to read SwapDesk security state from the Rust core.";
  }
}
loadSwapDesk();


async function loadExternalSigning() {
  const details = document.getElementById("externalSigningDetails");
  try {
    if (!window.__TAURI__?.core?.invoke || !details) return;
    const raw = await window.__TAURI__.core.invoke("external_signing_status");
    const values = Object.fromEntries(raw.split(";").map((part) => part.split("=")));
    details.replaceChildren();
    [
      ["Hardware boundary", values["hardware-boundary"]],
      ["Offline packages", values["offline-packages"]],
      ["Private-key export", values["private-key-export"]],
      ["Live device", values["live-device"]],
    ].forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "check-row";
      const left = document.createElement("span");
      left.textContent = label;
      const right = document.createElement("strong");
      right.className =
        value === "true" && label !== "Live device" ? "good" : "pending";
      right.textContent = value;
      row.append(left, right);
      details.append(row);
    });
  } catch {
    details.textContent = "Unable to read external signing state from the Rust core.";
  }
}
loadExternalSigning();
