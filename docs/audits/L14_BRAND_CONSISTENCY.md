# L14 Brand Consistency Audit

**Date:** 2026-11-05
**Audit:** L14-UNIFIED-EXPERIENCE-001
**Method:** Code inspection — tailwind.config.ts, globals.css, layout.tsx, package.json for each app

---

## Canonical Authority

The portal (`apps/portal/globals.css`) and console (`apps/console/globals.css`) share **identical** CSS variable definitions for both light and dark themes. These files represent the design system authority for authenticated user-facing properties.

The marketing website (`apps/web`) does **not** participate in this design system. It uses a bespoke Tailwind palette.

The `packages/ui` shared package (used by portal and console) provides component primitives that reference CSS variables via Tailwind semantic classes.

---

## A. Marketing Website (apps/web) — frostgate.ai

### Framework
- Next.js 14.2.35
- Tailwind CSS 3.4.17
- React 18.3.1
- **No shared `@fg/ui` or `@fg/navigation` package**

### Color Palette (tailwind.config.ts)
```
steel-50:  #eef3f7
steel-100: #d5e2ec
steel-200: #a9c4d8
steel-300: #7aa5c2
steel-400: #5589ae
steel-500: #3d6f95
steel-600: #2e5878  ← primary action (buttons, border accents)
steel-700: #234460
steel-800: #1a3349
steel-900: #122435

rust-50:  #faf0ee
rust-100: #f2d8d3
rust-200: #e4ada4
rust-300: #d27e72
rust-400: #be5547  ← motto text, accents
rust-500: #9b3830
rust-600: #7d2c25
rust-700: #61221c  ← step number text
rust-800: #471a15
rust-900: #31120e
```

### Typography
- `font-family: sans`: `['Inter', 'system-ui', 'sans-serif']`
- `font-family: mono`: `['JetBrains Mono', 'monospace']`
- Google Fonts import: `Inter` weights 300–700 in `globals.css`

### Body defaults (layout.tsx + globals.css)
- Background: `bg-gray-950` (Tailwind default — `#030712`)
- Text: `text-gray-100`
- Always dark — no light/dark mode toggle

### Logo treatment
- PNG file: `public/logo-original.png`
- Rendered via Next.js `<Image>` with `mix-blend-screen`
- Multiple sizes: 18px (footer), 32px (nav), 56px (CTA section), 96px (hero)

### Primary CTA pattern
```tsx
className="px-6 py-2.5 rounded bg-steel-600 text-white font-medium hover:bg-steel-500 transition-colors border border-steel-500/30"
```

---

## B. Customer Portal (apps/portal) — app.frostgate.ai

### Framework
- Next.js 14.2.5 (older minor than web and console)
- Tailwind CSS 3.4.17
- React 18.3.1
- **Dependencies:** `@fg/ui`, `@fg/navigation`, TanStack Query, React Hook Form, Zod, Zustand, lucide-react

### Color Tokens (globals.css CSS variables)
**Light mode:**
```
--background: #FFFFFF
--foreground: #0F172A
--primary: #FF5A1F
--primary-hover: #CC4919
--primary-foreground: #FFFFFF
--border: #E2E8F0
--muted: #64748B
--muted-foreground: #94A3B8
--surface: #F8FAFC
--surface-2: #F1F5F9
--surface-3: #E2E8F0
```

**Dark mode:**
```
--background: #05070A
--foreground: #E9EEF5
--primary: #FF5A1F          ← same orange in both modes
--primary-hover: #CC4919
--primary-foreground: #FFFFFF
--border: #0B3A4A
--muted: #94A3B8
--muted-foreground: #CBD5E1
--surface: #0D1117
--surface-2: #161B22
--surface-3: #1C2333
```

### Tailwind semantic tokens (tailwind.config.ts)
```
colors.primary.DEFAULT = var(--primary)
colors.background = var(--background)
colors.foreground = var(--foreground)
colors.border = var(--border)
colors.muted = var(--muted)
colors.surface = var(--surface)
colors.surface-2 = var(--surface-2)
colors.surface-3 = var(--surface-3)
colors.success = #22C55E
colors.warning = #F59E0B
colors.danger = #EF4444
colors.info = #3B82F6
colors.risk.critical = #EF4444
colors.risk.high = #F97316
colors.risk.medium = #F59E0B
colors.risk.low = #22C55E
```

### Typography
- `font-family: sans`: `['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif']`
- `font-family: mono`: `['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']`
- No Google Fonts import

### Dark mode
- Class-based (`darkMode: 'class'`)
- Toggle persisted in `localStorage` under key `fg-theme`
- Inline `<script>` in `<head>` applies dark class before paint

### Logo treatment
- Text: `"FrostGate "` + `<span>Client Portal</span>`
- No shield image or SVG in navigation

### Primary CTA pattern
```tsx
className="w-full rounded bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
```

---

## C. Enterprise Console (apps/console) — console.frostgate.ai

### Framework
- Next.js 14.2.35
- Tailwind CSS 3.4.17
- React 18.3.1
- **Dependencies:** `@fg/ui`, `@fg/navigation`, TanStack Query, React Hook Form, Zod, Zustand, lucide-react, Radix UI, Recharts, Cytoscape, next-auth

### Color Tokens (globals.css)
**Identical to portal** — same CSS variable values in both light and dark modes.

### Tailwind semantic tokens (tailwind.config.ts)
**Nearly identical to portal.** Console adds:
```
animation.fade-in
animation.slide-up
animation.pulse
keyframes.fadeIn
keyframes.slideUp
```
These additions are non-breaking additions to the portal token set.

### Typography
Identical to portal (system-UI stack, no Google Fonts).

### Dark mode
Identical implementation to portal.

### Logo treatment
- SVG component: `<FrostGateShield size={N} />` from `@/components/governance/FrostGateShield`
- Used in: `dashboard/layout.tsx` mobile header, `login/page.tsx`, console landing page nav + footer

---

## Divergence Summary

| Dimension | Web | Portal | Console | Divergence |
|---|---|---|---|---|
| Color family | steel/rust (blue-grey/red) | orange primary #FF5A1F | orange primary #FF5A1F | HIGH — different hue families |
| Background default | Always dark (`gray-950`) | Light (white) + dark toggle | Light (white) + dark toggle | MEDIUM — user expects dark on web, light on portal |
| Font | Inter (Google) | System-UI | System-UI | LOW |
| Mono font | JetBrains Mono | ui-monospace stack | ui-monospace stack | LOW |
| Button shape | `rounded` (4px per default) | `rounded` + explicit `rounded-lg` | `rounded` | LOW |
| Logo | PNG image | Text label | SVG component | MEDIUM — no unified asset |
| Design system | None — bespoke | @fg/ui package | @fg/ui package | HIGH — web is excluded |
| Token architecture | Hardcoded Tailwind | CSS variables | CSS variables | HIGH — no cross-site token bridge |
| Next.js version | 14.2.35 | 14.2.5 | 14.2.35 | LOW — portal is behind |

---

## Recommendations

| ID | Description | Effort |
|---|---|---|
| BRAND-001 | Migrate `apps/web` to use the same CSS variable token system as portal/console. Replace `steel-*`/`rust-*` with the shared `--primary`, `--background`, etc. | L |
| BRAND-002 | Adopt the `FrostGateShield` SVG component as the canonical logo across all three properties. Add it to `packages/ui`. | M |
| BRAND-003 | Add Inter (or a system-compatible match) to the portal/console font stack so the transition from web → portal doesn't change typography. | S |
| BRAND-004 | Upgrade portal's Next.js from 14.2.5 to 14.2.35 to match web and console. | S |
| BRAND-005 | Add `apps/web` as a consumer of `@fg/ui` and `@fg/navigation` to enforce token consistency going forward. | M |
