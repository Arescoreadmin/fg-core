# Brand Rules

## Token Policy
- **No raw colors outside `ui/theme.css`.**
- Components must use brand tokens via CSS variables (for example: `var(--fg-color-primary)`).
- `brand/BRAND.json` is the token source of truth and may contain raw color literals as token values.

## Component Usage
- UI components must reference CSS variables only.
- Do not hardcode `#hex`, `rgb(...)`, `rgba(...)`, `hsl(...)`, or `hsla(...)` in component/source files.

## Logo Usage
- Primary logo asset path: `brand/logo.svg`.
- Keep logo proportions unchanged.
- Preserve clear space around the mark and avoid recoloring outside approved tokenized variants.

## Gate Execution
Run the brand token gate:

```bash
make bp-d-000-gate
```

The gate writes evidence to `artifacts/gates/bp_d_000_report.json`.
