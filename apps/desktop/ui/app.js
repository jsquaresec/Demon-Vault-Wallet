const privacyButton = document.getElementById("privacyToggle");
const portfolio = document.getElementById("portfolioValue");
const balances = Array.from(document.querySelectorAll("[data-balance]"));
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
