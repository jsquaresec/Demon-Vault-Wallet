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
