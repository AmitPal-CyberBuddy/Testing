# Nessus IVA → Excel Vulnerability Register

A single, fully offline, client-side web application that converts a Tenable Nessus `.nessus` scan report into a formatted Excel vulnerability register.

## How to use

1. Download [`nessus-iva-to-excel.html`](nessus-iva-to-excel.html).
2. Double-click the file to open it in Chrome, Edge, or Firefox.
3. Drag and drop your Tenable Nessus `.nessus` file (or click **Browse**).
4. Review the scan summary and severity filters.
5. Optionally fill in register settings (Project, Activity Type, Date Raised, Expected Date to Close, Status, Owner).
6. Click **Download Excel Register**.

The output file is named like:

```text
MyScan_Vulnerability_Register.xlsx
```

## Privacy

The application is **100% client-side and offline**:

- No backend, API, cloud processing, database, telemetry, analytics, tracking, or external requests.
- No CDN libraries or other external resources.
- All JavaScript and the XLSX writer are bundled into the HTML file.
- The `.nessus` file is read only in the browser and never leaves the computer.
- It works with the internet disconnected.

No sample `.nessus` file and no client `.xlsx` template are required or included in this repository.

## Supported input

- Tenable Nessus v2 XML (`.nessus` files produced by Nessus scans).

## Output

The generated workbook has exactly 18 columns:

```text
Project
Activity Type
Finding Type
Vulnerability No.
IP/URL
Port
Testing Instance
Date Raised
Expected Date to Close
Status
System Component
Observation
Risk
Implication
Recommendation
Comments
Vulnerability
Owner (Manager or Action Owner User ID)
```

Findings are sorted by severity (Critical → High → Medium → Low → Informational) before sequential `VUL-0001` numbering is assigned. Only the severities selected in the UI are exported.

## Requirements

- No web server required.
- No internet connection required.
- Chrome, Edge, or Firefox (current versions).

## Building / development

The application is a self-contained HTML file. It depends only on standard browser APIs and includes its own minimal XLSX/ZIP writer, so it does not need a build step.

## License

Not specified. Use the code as appropriate for your own project.
