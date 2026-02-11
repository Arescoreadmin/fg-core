# FrostGate Brand Kit (Authoritative)

This directory is the **single source of truth** for UI branding:
- Logo assets
- Brand tokens (colors, radius, etc.)
- Rules for usage

If you hardcode colors in UI components, the build will fail. Good.

---

## Authoritative Files

- `brand/BRAND.json`  
  Canonical brand tokens (versioned). Do not add UI-only fields here.

- `brand/logo.svg` / `brand/mark.svg`  
  Canonical logo assets.

- `ui/theme.css`  
  The **only** file allowed to contain raw colors (hex/rgb/hsl).  
  It exposes tokens via CSS variables.

---

## Non-Negotiable Rules

### Rule 1: No raw colors in UI (except theme.css)
**Forbidden** anywhere in UI code:
- Hex: `#RRGGBB`, `#RGB` (and variants)
- `rgb(...)`, `rgba(...)`
- `hsl(...)`, `hsla(...)`

**Allowed only in**: `ui/theme.css`  
(and optionally the brand token file `brand/BRAND.json`, because that’s literally the point)

### Rule 2: Components use tokens only
UI code must use:
- CSS variables: `var(--primary)`, `var(--bg)` etc.
- Or theme helpers that resolve to variables

Example:
```css
.buttonPrimary { background: var(--primary); color: var(--fg); }
