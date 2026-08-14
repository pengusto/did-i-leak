const root = document.documentElement;
const themeToggle = document.querySelector("[data-theme-toggle]");
const themeLabel = document.querySelector("[data-theme-label]");

try {
  const savedTheme = localStorage.getItem("did-i-leak-theme");
  if (savedTheme === "light") root.dataset.theme = "light";
} catch {
  // The default dark theme still works when browser storage is unavailable.
}

function setTheme(theme) {
  root.dataset.theme = theme;
  const light = theme === "light";
  themeToggle?.setAttribute("aria-pressed", String(light));
  themeToggle?.setAttribute("aria-label", `Switch to ${light ? "dark" : "light"} theme`);
  if (themeLabel) themeLabel.textContent = light ? "Dark" : "Light";
  try {
    localStorage.setItem("did-i-leak-theme", theme);
  } catch {
    // Theme preference is optional, never a reason to break the page.
  }
}

setTheme(root.dataset.theme === "light" ? "light" : "dark");
themeToggle?.addEventListener("click", () => setTheme(root.dataset.theme === "light" ? "dark" : "light"));

const copyButton = document.querySelector("[data-copy]");
const copyStatus = document.querySelector(".copy-status");

copyButton?.addEventListener("click", async () => {
  const command = copyButton.dataset.copy;
  try {
    await navigator.clipboard.writeText(command);
    copyButton.textContent = "Copied";
    copyStatus.textContent = "command copied";
  } catch {
    copyStatus.textContent = "select the command above";
  }
  window.setTimeout(() => {
    copyButton.textContent = "Copy";
    copyStatus.textContent = "";
  }, 2200);
});

const demoOutput = document.querySelector("[data-terminal-output]");
const demoCode = document.querySelector("[data-terminal-code]");
const demoTitle = document.querySelector("[data-terminal-title]");
const demoTabs = document.querySelectorAll("[data-demo-tab]");

const demos = {
  leak: {
    title: "did-i-leak / verdict",
    code: "2",
    output: `<span class="terminal-muted">DID I LEAK?</span>\n\n<span class="terminal-danger">NO-GO</span>\n\n<span class="terminal-strong">1 blocker</span>\n\n<span class="terminal-strong">Historical credential detected</span>\nCommit: a83f2c1\nFile: scripts/test_api.py\nStatus: deleted from current tree\nConfidence: high\n\n<span class="terminal-action">Action: Revoke/rotate before publishing.</span>\n\n<span class="terminal-muted">Coverage</span>\nGitleaks: completed\nTruffleHog: completed\nGit history: all reachable commits`,
  },
  clean: {
    title: "did-i-leak / verdict",
    code: "0",
    output: `<span class="terminal-muted">DID I LEAK?</span>\n\n<span class="terminal-action">GO</span>\n\n<span class="terminal-strong">No blockers</span>\n\nCurrent tree: clean\nReachable history: clean\nPII / internal paths: none found\n\n<span class="terminal-action">Action: safe to continue.</span>\n\n<span class="terminal-muted">Coverage</span>\nGitleaks: completed\nTruffleHog: completed\nGit history: all reachable commits`,
  },
};

demoTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const demo = demos[tab.dataset.demoTab];
    if (!demo || !demoOutput) return;
    demoTabs.forEach((item) => item.classList.toggle("active", item === tab));
    demoOutput.innerHTML = demo.output;
    if (demoCode) demoCode.textContent = demo.code;
    if (demoTitle) demoTitle.textContent = demo.title;
  });
});
