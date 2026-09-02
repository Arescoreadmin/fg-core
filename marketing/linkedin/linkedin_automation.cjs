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

function usage() {
  console.log(`Usage:
  node marketing/linkedin/linkedin_automation.cjs company
  node marketing/linkedin/linkedin_automation.cjs founder
  node marketing/linkedin/linkedin_automation.cjs post company
  node marketing/linkedin/linkedin_automation.cjs post founder

This opens Brave with a dedicated local profile at:
  ${PROFILE_DIR}

It fills fields where LinkedIn exposes stable labels, copies fallback text into the page,
and stops before any final Save/Create/Post action. You review and click the final button.`);
}

async function main() {
  const [mode, submode] = process.argv.slice(2);
  if (!mode || mode === "--help" || mode === "-h") {
    usage();
    return;
  }

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
  page.setDefaultTimeout(6000);

  await ensureLinkedInSession(page);

  if (mode === "company") {
    await openCompanySetup(page);
    await fillCompanyBasics(page, payload.company);
    await printCompanyFallback(payload.company);
  } else if (mode === "founder") {
    await openProfile(page);
    await printFounderFallback(payload.founder);
  } else if (mode === "post") {
    await openPostComposer(page);
    const post = submode === "founder" ? payload.posts[1] : payload.posts[0];
    await fillPostComposer(page, post.body);
    console.log(`Loaded post draft: ${post.title}`);
    console.log("Review the text in Brave. Click Post manually when ready.");
  } else {
    usage();
  }

  console.log("\nBrowser remains open for review. Press Enter here when you are done.");
  const rl = readline.createInterface({ input, output });
  await rl.question("");
  rl.close();
  await context.close();
}

async function ensureLinkedInSession(page) {
  await page.goto("https://www.linkedin.com/feed/", { waitUntil: "domcontentloaded" });
  if (/\/login|checkpoint|uas\/login/.test(page.url())) {
    console.log("LinkedIn needs login. Complete login/MFA in Brave, then press Enter here.");
    const rl = readline.createInterface({ input, output });
    await rl.question("");
    rl.close();
    await page.goto("https://www.linkedin.com/feed/", { waitUntil: "domcontentloaded" });
  }
}

async function openCompanySetup(page) {
  await page.goto("https://www.linkedin.com/company/setup/new/", { waitUntil: "domcontentloaded" });
  console.log("Opened LinkedIn company page setup.");
}

async function openProfile(page) {
  await page.goto("https://www.linkedin.com/in/me/", { waitUntil: "domcontentloaded" });
  console.log("Opened your LinkedIn profile. LinkedIn profile edit dialogs are intentionally left manual.");
}

async function openPostComposer(page) {
  await page.goto("https://www.linkedin.com/feed/", { waitUntil: "domcontentloaded" });
  await clickByText(page, /start a post|create a post/i);
}

async function fillCompanyBasics(page, company) {
  await fillByLabel(page, [/name/i], company.name);
  await fillByLabel(page, [/website/i], company.website);
  await fillByLabel(page, [/tagline/i], company.tagline);
  await fillByLabel(page, [/linkedin.*public.*url|public.*url|url/i], company.slug);
  await fillByLabel(page, [/description|about/i], company.about);

  await selectOrType(page, [/industry/i], company.industry);
  await selectOrType(page, [/organization.*type|company.*type|type/i], company.companyType);

  console.log("Filled company basics where LinkedIn exposed matching fields.");
  console.log("Do not click Create/Save until you review every field.");
}

async function fillPostComposer(page, text) {
  const editor = page.locator("[contenteditable='true']").first();
  await editor.waitFor({ state: "visible", timeout: 10000 });
  await editor.fill(text).catch(async () => {
    await editor.click();
    await page.keyboard.insertText(text);
  });
}

async function fillByLabel(page, patterns, value) {
  for (const pattern of patterns) {
    const label = page.getByLabel(pattern).first();
    try {
      await label.fill(value);
      console.log(`Filled label ${pattern}`);
      return true;
    } catch (_) {
      // Try the next strategy.
    }
  }

  for (const pattern of patterns) {
    const field = page.locator("input, textarea").filter({ hasText: pattern }).first();
    try {
      await field.fill(value);
      console.log(`Filled field ${pattern}`);
      return true;
    } catch (_) {
      // Try the next pattern.
    }
  }
  return false;
}

async function selectOrType(page, patterns, value) {
  for (const pattern of patterns) {
    try {
      const combo = page.getByRole("combobox", { name: pattern }).first();
      await combo.click();
      await page.keyboard.insertText(value);
      await page.keyboard.press("Enter");
      console.log(`Selected/typed ${value} for ${pattern}`);
      return true;
    } catch (_) {
      // Try label fallback.
    }
  }
  return fillByLabel(page, patterns, value);
}

async function clickByText(page, pattern) {
  const candidates = [
    page.getByRole("button", { name: pattern }).first(),
    page.getByText(pattern).first()
  ];
  for (const candidate of candidates) {
    try {
      await candidate.click();
      return true;
    } catch (_) {
      // Try next candidate.
    }
  }
  throw new Error(`Could not find clickable text: ${pattern}`);
}

async function printCompanyFallback(company) {
  console.log("\nFallback copy for manual fields:");
  console.log(`Name: ${company.name}`);
  console.log(`Slug: ${company.slug}`);
  console.log(`Industry: ${company.industry}`);
  console.log(`Type: ${company.companyType}`);
  console.log(`Website: ${company.website}`);
  console.log(`Tagline: ${company.tagline}`);
  console.log(`Specialties: ${company.specialties}`);
  console.log("\nAbout:\n" + company.about);
}

async function printFounderFallback(founder) {
  console.log("\nFounder profile copy:");
  console.log(`Headline: ${founder.headline}`);
  console.log("\nAbout:\n" + founder.about);
  console.log("\nExperience:");
  console.log(`Title: ${founder.experienceTitle}`);
  console.log(`Company: ${founder.experienceCompany}`);
  console.log(founder.experienceDescription);
  console.log("\nOpen the edit dialogs in Brave and paste these fields. Final save is manual.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
