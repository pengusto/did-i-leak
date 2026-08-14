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

const ambientField = document.querySelector(".ambient-field");
const ambientCanvas = document.querySelector(".ambient-canvas");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const finePointer = window.matchMedia("(pointer: fine)");
const ambientPointer = { x: .58, y: .42, targetX: .58, targetY: .42 };

if (ambientField && !reducedMotion.matches && finePointer.matches) {
  let frame = 0;
  window.addEventListener("pointermove", (event) => {
    if (event.pointerType && event.pointerType !== "mouse") return;
    ambientPointer.targetX = event.clientX / window.innerWidth;
    ambientPointer.targetY = event.clientY / window.innerHeight;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      root.style.setProperty("--mx", `${(event.clientX / window.innerWidth) * 100}%`);
      root.style.setProperty("--my", `${(event.clientY / window.innerHeight) * 100}%`);
      root.style.setProperty("--shift-x", `${(event.clientX / window.innerWidth - .5) * 24}px`);
      root.style.setProperty("--shift-y", `${(event.clientY / window.innerHeight - .38) * 20}px`);
    });
  }, { passive: true });
}

if (ambientCanvas && !reducedMotion.matches) {
  const context = ambientCanvas.getContext("2d");
  let width = 0;
  let height = 0;
  let scale = 1;

  const resizeAmbient = () => {
    const bounds = ambientCanvas.getBoundingClientRect();
    scale = Math.min(window.devicePixelRatio || 1, 2);
    width = bounds.width;
    height = bounds.height;
    ambientCanvas.width = width * scale;
    ambientCanvas.height = height * scale;
    context.setTransform(scale, 0, 0, scale, 0, 0);
  };

  const drawAmbient = (time) => {
    ambientPointer.x += (ambientPointer.targetX - ambientPointer.x) * .035;
    ambientPointer.y += (ambientPointer.targetY - ambientPointer.y) * .035;
    context.clearRect(0, 0, width, height);
    context.lineCap = "round";

    const colors = [
      getComputedStyle(root).getPropertyValue("--accent").trim(),
      getComputedStyle(root).getPropertyValue("--danger").trim(),
    ];
    colors.forEach((color, index) => {
      const phase = index * 2.4;
      const base = height * (.34 + index * .2);
      const amplitude = height * (.09 - index * .015);
      const path = new Path2D();
      for (let step = 0; step <= 28; step += 1) {
        const progress = step / 28;
        const x = -90 + progress * (width + 180);
        const y = base + Math.sin(progress * 6.4 + time * (.00042 - index * .00012) + phase) * amplitude + (ambientPointer.y - .42) * height * .1;
        if (step === 0) path.moveTo(x, y);
        else path.lineTo(x, y);
      }
      context.strokeStyle = color;
      context.shadowColor = color;
      context.globalAlpha = .055;
      context.shadowBlur = 36;
      context.lineWidth = 28;
      context.stroke(path);
      context.globalAlpha = .24 - index * .05;
      context.shadowBlur = 14;
      context.lineWidth = 1.4;
      context.stroke(path);
    });
    context.globalAlpha = 1;
    requestAnimationFrame(drawAmbient);
  };

  resizeAmbient();
  window.addEventListener("resize", resizeAmbient, { passive: true });
  requestAnimationFrame(drawAmbient);
}

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
