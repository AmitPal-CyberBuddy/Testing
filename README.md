# Nessus & Qualys → Excel Vulnerability Register

A single, fully offline, client-side web application that converts **Tenable Nessus (`.nessus`)** and **QualysGuard / Qualys (`.xml`)** vulnerability scan reports into a professional Excel vulnerability register.

Part of **Toolbox by AmitPal** — [amitpal-cyberbuddy.github.io/Testing](https://amitpal-cyberbuddy.github.io/Testing/).

## Live URLs

| Page | URL |
| :--- | :--- |
| Tools hub (landing page) | [amitpal-cyberbuddy.github.io/Testing](https://amitpal-cyberbuddy.github.io/Testing/) |
| This tool (clean URL, no `.html`) | [amitpal-cyberbuddy.github.io/Testing/vulnerability-register/](https://amitpal-cyberbuddy.github.io/Testing/vulnerability-register/) |

> **Note:** The old URL `nessus-iva-to-excel.html` still works — it automatically redirects to `/vulnerability-register/`, so previously shared links are not broken.

## How to use

1. Open the [live tool](https://amitpal-cyberbuddy.github.io/Testing/vulnerability-register/), or download [`vulnerability-register/index.html`](vulnerability-register/index.html) for fully offline use.
2. Double-click the file to open it in Chrome, Edge, or Firefox.
3. Drag and drop your Tenable Nessus (`.nessus`) or Qualys (`.xml`) file (or click **Browse**).
4. The application automatically detects the scanner format and displays the scan summary.
5. Review severity filters and optionally fill in register settings (Project, Activity Type, Date Raised, Expected Date to Close, Status, Owner).
6. Click **Download Excel Register**.

The output file is named like:

```text
MyScan_Vulnerability_Register.xlsx
```

## Privacy

The application is **100% client-side and offline**:

- No backend, API, cloud processing, database, telemetry, analytics, tracking, or external requests.
- No CDN libraries or other external resources.
- All JavaScript and the XLSX writer are bundled into the single HTML file.
- Scan files are parsed locally in the browser memory and never transmitted anywhere.
- Works completely offline with no internet connection required.

## Supported input formats

- **Tenable Nessus v2 XML** (`.nessus` or `.xml`)
- **QualysGuard / Qualys Vulnerability Scan XML** (`.xml`)

## Output format

Both Nessus and Qualys scans produce the exact same professional 18-column Excel register:

```text
1.  Project
2.  Activity Type
3.  Finding Type
4.  Vulnerability No.
5.  IP/URL
6.  Port
7.  Testing Instance
8.  Date Raised
9.  Expected Date to Close
10. Status
11. System Component
12. Observation
13. Risk
14. Implication
15. Recommendation
16. Comments
17. Vulnerability
18. Owner (Manager or Action Owner User ID)
```

Findings are sorted by severity (`Critical` → `High` → `Medium` → `Low` → `Informational`) before sequential `VUL-0001` numbering is assigned. Only severities selected in the UI are exported.

## Severity mappings

| Normalized Severity | Nessus Severity | Qualys Severity |
| :--- | :--- | :--- |
| **Critical** | `4` / Critical | `5` / Urgent |
| **High** | `3` / High | `4` / Serious |
| **Medium** | `2` / Medium | `3` / Medium |
| **Low** | `1` / Low | `2` / Minimal |
| **Informational** | `0` / Informational | `1` / `0` / Info |

## Requirements

- No web server required.
- No internet connection required.
- Modern browser: Chrome, Edge, Firefox, Safari.

## Building / development

The application is a self-contained HTML file. It depends only on standard browser APIs (`DOMParser`, `TextEncoder`, `CompressionStream` / standard deflate) and includes its own minimal XLSX/ZIP writer, so it does not require a build step or external libraries.

## License

Not specified. Use the code as appropriate for your own project.
