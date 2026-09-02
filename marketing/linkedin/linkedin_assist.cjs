#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline/promises");
const { stdin: input, stdout: output } = require("node:process");
const { chromium } = require("/home/jcosat/mcp/playwright/node_modules/playwright");

const ROOT = path.resolve(__dirname);
const PAYLOAD_PATH = path.join(ROOT, "linkedin_payload.json");
const PROFILE_DIR = path.join(process.env.HOME || "/tmp", ".frostgate-linkedin-browser");
const BRAVE = process.env.LINKEDIN_BROWSER || "/usr/bin/brave-browser";
const payload = JSON.parse(fs.readFileSync(PAYLOAD_PATH, "utf8"));

async function main() {
  const context = await chromium.launchPersistentContext(PROFILE_DIR, {
    executablePath: BRAVE,
    headless: false,
    viewport: { width: 1440, height: 1000 },
    args: [
      "--disable-blink-features=AutomationControlled",
      "--no-first-run",
      "--start-maximized"
    ]
  });

  const page = context.pages()[0] || await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto("https://www.linkedin.com/", { waitUntil: "domcontentloaded" });

  const timer = setInterval(() => {
    installPanel(page).catch(() => {});
  }, 2000);

  await installPanel(page);
  console.log("FrostGate LinkedIn assist mode is running.");
  console.log("Navigate LinkedIn normally in Brave.");
  console.log("Click into a LinkedIn field, then use the lower-right FrostGate panel to Fill Active or Copy.");
  console.log("Final Create, Save, and Post actions stay manual.");
  console.log("Press Enter here when you are finished.");

  const rl = readline.createInterface({ input, output });
  await rl.question("");
  rl.close();
  clearInterval(timer);
  await context.close();
}

async function installPanel(page) {
  await page.evaluate((data) => {
    if (document.getElementById("fg-linkedin-assist")) return;

    const fields = [
      ["Company Name", data.company.name],
      ["Company Slug", data.company.slug],
      ["Website", data.company.website],
      ["Industry", data.company.industry],
      ["Company Type", data.company.companyType],
      ["Tagline", data.company.tagline],
      ["Brand Principle", data.company.brandPrinciple],
      ["Company About", data.company.about],
      ["Specialties", data.company.specialties],
      ["Founder Headline", data.founder.headline],
      ["Founder About", data.founder.about],
      ["Experience Title", data.founder.experienceTitle],
      ["Experience Company", data.founder.experienceCompany],
      ["Experience Description", data.founder.experienceDescription],
      ["Company Launch Post", data.posts[0].body],
      ["Founder Launch Post", data.posts[1].body]
    ];

    const style = document.createElement("style");
    style.id = "fg-linkedin-assist-style";
    style.textContent = `
      #fg-linkedin-assist {
        position: fixed;
        right: 18px;
        bottom: 18px;
        z-index: 2147483647;
        width: 360px;
        max-height: 72vh;
        overflow: auto;
        background: #05070A;
        color: #E9EEF5;
        border: 1px solid rgba(255, 90, 31, 0.65);
        box-shadow: 0 16px 42px rgba(0, 0, 0, 0.42);
        border-radius: 10px;
        padding: 12px;
        font: 13px/1.35 Arial, sans-serif;
      }
      #fg-linkedin-assist * { box-sizing: border-box; }
      #fg-linkedin-assist header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 8px;
      }
      #fg-linkedin-assist strong { color: #fff; font-size: 14px; }
      #fg-linkedin-assist .fg-note { color: #B8C2CC; font-size: 12px; margin: 0 0 10px; }
      #fg-linkedin-assist .fg-row {
        border-top: 1px solid rgba(233, 238, 245, 0.12);
        padding: 8px 0;
      }
      #fg-linkedin-assist .fg-label { color: #fff; font-weight: 700; margin-bottom: 6px; }
      #fg-linkedin-assist button {
        border: 1px solid rgba(255, 90, 31, 0.7);
        background: transparent;
        color: #E9EEF5;
        border-radius: 6px;
        padding: 5px 8px;
        cursor: pointer;
        margin-right: 6px;
        margin-bottom: 4px;
        font: 12px Arial, sans-serif;
      }
      #fg-linkedin-assist button:hover { background: rgba(255, 90, 31, 0.18); }
      #fg-linkedin-assist .fg-close { border-color: rgba(233, 238, 245, 0.25); }
    `;

    const panel = document.createElement("aside");
    panel.id = "fg-linkedin-assist";
    panel.innerHTML = `
      <header>
        <strong>FrostGate LinkedIn Assist</strong>
        <button class="fg-close" type="button" data-close="1">Close</button>
      </header>
      <p class="fg-note">Click into a LinkedIn field, then use Fill Active. Final save/post stays manual.</p>
      <div id="fg-linkedin-assist-fields"></div>
    `;

    function setActiveValue(value) {
      const active = document.activeElement;
      if (!active) return false;

      if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) {
        active.focus();
        active.value = value;
        active.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
        active.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      }

      if (active.isContentEditable) {
        active.focus();
        document.execCommand("selectAll", false);
        document.execCommand("insertText", false, value);
        active.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
        return true;
      }

      return false;
    }

    async function copyValue(value) {
      try {
        await navigator.clipboard.writeText(value);
      } catch (_) {
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        textarea.remove();
      }
    }

    const list = panel.querySelector("#fg-linkedin-assist-fields");
    for (const [label, value] of fields) {
      const row = document.createElement("div");
      row.className = "fg-row";
      row.innerHTML = `
        <div class="fg-label"></div>
        <button type="button" data-action="fill">Fill Active</button>
        <button type="button" data-action="copy">Copy</button>
      `;
      row.querySelector(".fg-label").textContent = label;
      row.querySelector('[data-action="fill"]').addEventListener("click", () => {
        const ok = setActiveValue(value);
        if (!ok) copyValue(value);
      });
      row.querySelector('[data-action="copy"]').addEventListener("click", () => copyValue(value));
      list.appendChild(row);
    }

    panel.querySelector("[data-close]").addEventListener("click", () => panel.remove());
    document.documentElement.appendChild(style);
    document.documentElement.appendChild(panel);
  }, JSON.parse(JSON.stringify(payload)));
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
