# FrostGate LinkedIn Automation

This folder contains a human-in-the-loop LinkedIn setup helper.

It uses local Playwright and Brave:

```bash
node marketing/linkedin/linkedin_automation.cjs company
node marketing/linkedin/linkedin_automation.cjs founder
node marketing/linkedin/linkedin_automation.cjs post company
node marketing/linkedin/linkedin_automation.cjs post founder
```

The runner opens Brave with a dedicated local browser profile:

```text
~/.frostgate-linkedin-browser
```

If LinkedIn asks for login or MFA, complete that in the opened Brave window and press Enter in the terminal.

The script is intentionally review-gated. It does not click the final Create, Save, or Post button. Review every LinkedIn field before submitting.

## Files

- `frostgate_linkedin_buildout.md` - full copy package and content plan.
- `linkedin_payload.json` - structured automation payload.
- `linkedin_automation.cjs` - browser automation runner.
