---
name: OPNsense Manager
description: Operational firewall console embedded in PegaProx
colors:
  dark-accent: "#e57000"
  dark-bg: "#0f1117"
  dark-card: "#1a1d27"
  dark-surface: "#141720"
  dark-border: "#2a2d3a"
  dark-text: "#e4e4e7"
  dark-muted: "#a1a1aa"
  dark-accent-soft: "rgba(229, 112, 0, .12)"
  light-accent: "#a64b00"
  light-bg: "#f6f7f9"
  light-card: "#ffffff"
  light-surface: "#eef1f5"
  light-border: "#e4e7eb"
  light-text: "#1e2230"
  light-muted: "#4b5563"
  light-accent-soft: "#fff0e2"
  cloud-accent: "#22d3ee"
  cloud-bg: "#060f1e"
  cloud-card: "#16304a"
  cloud-surface: "#0d2033"
  cloud-border: "#1e3a52"
  cloud-text: "#e6f1f8"
  cloud-muted: "#8aa4b8"
  cloud-accent-soft: "rgba(34, 211, 238, .10)"
  primary-bg: "#b75300"
  primary-ink: "#ffffff"
  cloud-primary-ink: "#082033"
  light-success-ink: "#166534"
typography:
  body:
    fontFamily: '"Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif'
    fontSize: "14px"
    lineHeight: 1.5
  product-title:
    fontSize: "24px"
    fontWeight: 700
    letterSpacing: "-0.01em"
  view-title:
    fontSize: "21px"
    fontWeight: 650
    letterSpacing: "-0.02em"
  card-title:
    fontSize: "14px"
    fontWeight: 600
  card-value:
    fontSize: "24px"
    fontWeight: 650
    lineHeight: 1.15
rounded:
  field: "6px"
  button: "7px"
  navigation: "10px"
  panel: "12px"
spacing:
  field-gap: "12px"
  grid-gap: "16px"
  panel-gap: "20px"
components:
  button-primary:
    backgroundColor: "{colors.primary-bg}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.button}"
    padding: "8px 14px"
  button-primary-cloud:
    backgroundColor: "{colors.cloud-accent}"
    textColor: "{colors.cloud-primary-ink}"
    rounded: "{rounded.button}"
    padding: "8px 14px"
---

# Design System: OPNsense Manager

## Overview

An operational console for inspecting and managing firewalls inside PegaProx. The incumbent system uses native controls, system typography, restrained surfaces and persistent status information. It supports Spanish labels and three host-compatible themes without external font, icon or animation dependencies.

This is a factual extraction from `opnsense.html` on 2026-09-18. The HTML owns runtime styles; update this document with intentional style changes. The current refinement scope and acceptance criteria live in `docs/UI_DESIGN_20260918.md`.

## Colors

The frontmatter records the reused theme primitives. `corp-dark` is the default; `corp-light` applies the light overrides; `cloud` applies the navy/cyan overrides. Themes are selected through the iframe query parameter, not inherited from the host DOM.

The accent identifies selection, focus and key values. Background, card and surface tokens distinguish page, content and secondary controls. Text and muted tokens distinguish primary content from metadata. Green, blue, yellow and red badges communicate states with accompanying labels; light mode supplies darker text variants. Check text against its composited badge background, not only against the page background.

## Typography

The body stack is shared throughout. Product, view, section and metric roles use the frontmatter hierarchy. The product title becomes 21 px on mobile; node headings use 15 px, while compact System/CARP values use 18 px. Table cells and supporting card text use 13 px; metadata generally uses 12 px. Some chart axes and compact status labels retain 10 px.

Addresses and machine values use the existing UI monospace stack. Numeric metrics use tabular figures. Content headings use sentence case; role labels such as MASTER/BACKUP retain uppercase.

## Layout

The centered shell has a maximum width of 1600 px and padding of 28 px vertically / 32 px horizontally. The page grid has 12 explicit `minmax(0, 1fr)` columns, reducing to 6 at 1024 px and 1 at 768 px. Full-width cards span `1 / -1`. Mobile shell padding is 14 px; wide tables scroll inside cards.

HA uses two node panels, stacking below 900 px. Each panel has two explicit inner columns: its heading spans both, System/CARP share a row, and the remaining service, certificate and VPN cards span both. Inner cards use separators rather than nested borders.

Nine navigation destinations remain present. Desktop tabs wrap as needed; mobile tabs use three equal columns and a minimum height of 44 px. Forms use an auto-fitting grid with a 190 px minimum field width and the established field gap.

## Elevation & Depth

Cards and node panels rely on tonal surfaces, borders and spacing. The selected tab adds an inset border. Focus uses a two-layer ring: 2 px of page background followed by 4 px of accent. The existing interface drilldown dialog retains its `0 20px 60px rgba(0, 0, 0, 0.5)` shadow; ordinary cards do not use that modal elevation.

## Shapes

The frontmatter records the established corner sizes. Cards and panels have 1 px theme borders, 20 px padding on desktop and 16 px on mobile. Navigation has a padded outer container and smaller rounded tab surfaces. Icons are inline outlined SVGs; status chips remain compact pills.

## Components

- **Header:** product identity, health-derived plugin version, explicit effective access label and refresh control. Discovery pending/failed does not claim write access. HA context names the pair.
- **Navigation:** icon plus text, selected accent surface, keyboard arrows/Home/End and visible focus. Preserve all nine destinations.
- **HA panels:** the badge reflects the node's observed CARP state. Missing state and unreachable nodes are explicit, rather than inferred as backup from the cluster summary.
- **Buttons and fields:** native elements with brief hover/press feedback. Buttons are at least 36 px high on desktop and 44 px on mobile. Mobile text inputs use 16 px type. Disabled controls remain visible; explanatory text communicates read-only/permission restrictions.
- **Lists and editors:** read-only lists precede their corresponding disabled editors. Editors remain available, retaining drafts and validation messages. Writable views keep the existing edit workflow.
- **Tables:** subdued header surfaces, 12 px cell padding, aligned numeric columns and internally scrollable cards. Table cards can receive keyboard focus.
- **Motion:** content does not replay entrance animation during polling. Control transitions provide brief feedback; reduced-motion mode disables animations and transitions.

## Do's and Don'ts

- **Do** reuse the theme primitives, native controls and existing SVG treatment.
- **Do** verify all three themes at 390, 768, 1024 and 1440 px, including long addresses and HA panels.
- **Do** preserve visible focus, actual node states, effective permissions and every existing destination.
- **Don't** introduce implicit grid columns through page-span classes inside node panels.
- **Don't** hide content to suppress overflow; preserve it through internal scrolling where necessary.
- **Don't** infer successful connectivity, write permission or configuration state from appearance.
- **Don't** add decorative dependencies or repeated entrance animation to this operational console.
