# Phantom Dashboard

Local management dashboard for the ShadowStrike Phantom security platform.

## Overview

This is the **localhost dashboard** — a single-page application that communicates
with the Phantom agent's embedded REST API running on the same machine.  It gives
users a graphical interface for:

- Real-time protection status & module health
- On-demand and scheduled scanning
- Threat & alert timeline
- Quarantine management
- Threat intelligence feed viewer
- Configuration & settings

The dashboard is served by the agent's built-in HTTP listener on
`http://localhost:<port>` and is **not** intended to be exposed to the network.

## Tech Stack

| Layer     | Technology                       |
|-----------|----------------------------------|
| Framework | React 18 + TypeScript            |
| Build     | Vite 6                           |
| Styling   | Tailwind CSS 3                   |
| Charts    | Recharts                         |
| Icons     | Lucide React                     |
| Routing   | React Router 6                   |

## Quick Start

```bash
cd dashboard
npm install
npm run dev        # http://localhost:5173
npm run build      # production bundle → dist/
npm run lint       # ESLint
npm run type-check # TypeScript strict check
```

During development the Vite dev server proxies `/api/v1/*` requests to the
Phantom agent.  In production the built `dist/` is embedded into the agent
binary and served directly.

## Project Structure

```
dashboard/
├── public/              Static assets (favicon, icons)
├── src/
│   ├── api/             Type-safe API client (mirrors RESTServer.cpp)
│   ├── components/      Reusable UI components
│   ├── hooks/           Custom React hooks (polling, auth, etc.)
│   ├── pages/           Route-level page components
│   ├── types/           Shared TypeScript interfaces
│   └── utils/           Helpers (formatting, dates, etc.)
├── index.html           SPA entry point
├── vite.config.ts       Vite configuration
├── tailwind.config.js   Tailwind theme
└── tsconfig.json        TypeScript configuration
```

## License

GNU Affero General Public License v3.0 — see [LICENSE.txt](../LICENSE.txt).
