# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chicago Pug Rescue is a static informational website that connects Chicago-area residents with pug adoption and fostering resources. It is **not** a shelter — it educates users and links to established local rescue organizations.

## Running Locally

No build step is required. Open files directly in a browser or serve with:

```bash
python3 -m http.server 8000
```

There are no package managers, bundlers, linters, or test frameworks.

## Architecture

The site is three HTML pages sharing one stylesheet — no JavaScript, no dependencies.

| File | Purpose |
|---|---|
| `index.html` | Main landing page: adoption steps, fostering guide, rescue org directory, Chicago care tips |
| `about.html` | Mission, volunteer team, values, FAQ |
| `privacy.html` | Privacy policy |
| `styles.css` | Single stylesheet for all pages (609 lines) |

## CSS Conventions

- **Color variables** are defined at the top of `styles.css` using CSS custom properties (`--color-*`). Add new colors there.
- **Single breakpoint:** `@media (max-width: 700px)` handles all mobile/tablet adjustments.
- **Fluid type:** Use `clamp()` for font sizes (e.g., `clamp(1.6rem, 3vw, 2.2rem)`).
- **Grid cards:** Use CSS Grid with `auto-fit` and `minmax()` — avoid fixed column counts.
- **Component classes:** `.btn-primary`, `.btn-secondary`, `.card`, `.org-card` — reuse these before adding new ones.

## HTML Conventions

- Every page includes the same `<nav>` and `<footer>` blocks — keep them in sync across all three files.
- The active nav link gets `class="active"` on the `<a>` tag.
- Section anchors (`id="adopt"`, `id="foster"`, etc.) are used for in-page navigation — preserve them when restructuring.
- Emoji is used intentionally throughout for warmth; maintain this tone in new content.
