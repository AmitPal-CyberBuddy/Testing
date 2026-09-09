# Nessus & Qualys → Excel Vulnerability Register

A fully offline, client-side web application that converts either a Tenable Nessus v2 report or a Qualys Vulnerability Scan XML report into the **same formatted Excel Vulnerability Register**.

## How to use

1. Download [`nessus-iva-to-excel.html`](nessus-iva-to-excel.html).
2. Open it in a current Chrome, Edge, or Firefox browser.
3. Drag in a Nessus `.nessus` file or a Qualys `.xml` scan report (or select **Browse**).
4. The application inspects the XML root structure and identifies the scanner automatically.
5. Review the scan summary and severity filters, optionally enter the register settings, and select **Download Excel Register**.

The output file is named like:

```text
MyScan_Vulnerability_Register.xlsx
```

## Supported input

| Scanner | Input | Detection |
| --- | --- | --- |
| Tenable Nessus | Nessus v2 XML (`.nessus`, or XML with a `NessusClientData` / `NessusClientData_v2` root) | XML root structure |
| QualysGuard / Qualys | Vulnerability Scan XML (`.xml`, with a `SCAN` root) | XML root structure |

File extensions are accepted for convenience but **are not used as the source of truth**. Unsupported XML receives a clear error rather than being sent to the wrong parser.

## Architecture

```text
Input XML
  → FormatDetector
  → NessusParser or QualysParser
  → common normalized finding model
  → existing RegisterBuilder and ExcelExporter
  → Excel Vulnerability Register
```

The project intentionally remains a single self-contained HTML application. Scanner-specific logic is isolated in the `NessusParser`, `QualysParser`, and `FormatDetector` sections of that file; the Excel writer and its template are shared.

### Qualys normalization

| Qualys XML | Normalized field | Existing Excel destination |
| --- | --- | --- |
| `IP @value` | `hostIP` | `IP/URL` |
| `IP @name` | `hostnamePreferred` | `System Component` |
| `CAT @value` | `pluginFamily` | Existing finding-type mapper → `Finding Type` |
| `CAT @port` | `port` / `portNumeric` | `Port` |
| `CAT @protocol` | `protocol` | `Testing Instance` |
| `INFO`, `SERVICE`, `VULN`, or `PRACTICE` `@number` | `pluginID` | Retained for common-model sorting; no dedicated pre-existing Excel column |
| `INFO`, `SERVICE`, `VULN`, or `PRACTICE` `@severity` | `severity` / `severityName` | `Risk` |
| `TITLE` | `pluginName` and `synopsis` | `Vulnerability` and `Observation` |
| `DIAGNOSIS` | `description` | `Implication` |
| `CONSEQUENCE` | `impact` | `Implication` under **Impact / Consequence** |
| `SOLUTION` | `solution` | `Recommendation` |
| `RESULT` | `pluginOutput` | `Implication` under **Result** |
| `HEADER/KEY[@value="DATE"]` | report date | Default value for the existing `Date Raised` control |
| `LAST_UPDATE` | `lastUpdate` | Retained in the normalized finding; no dedicated pre-existing Excel column |

Both `INFO` and `SERVICE` are treated as findings, along with the `VULN` and `PRACTICE` finding shapes used by classic Qualys `VULNS` and `PRACTICES` sections. Multiple `IP` hosts and multiple `CAT` categories are processed. Missing optional category attributes such as `port`, `protocol`, `misc`, and `RESULT @format` are safely represented as empty values.

### Qualys severity mapping

Qualys uses a 1–5 QID severity scale whose source labels are **Minimal**, **Medium**, **Serious**, **Critical**, and **Urgent**. The existing register has Nessus-style labels, so Qualys severity is normalized by relative priority rather than writing the source number into the workbook:

| Qualys value | Qualys meaning | Excel `Risk` |
| ---: | --- | --- |
| `0` | Legacy/information-only defensive fallback | Informational |
| `1` | Minimal | Informational |
| `2` | Medium | Low |
| `3` | Serious | Medium |
| `4` | Critical | High |
| `5` | Urgent | Critical |

This centralized mapping preserves the existing severity filters, sort order, and risk-cell styles. It does not change Nessus severity handling.

### Evidence and table results

The parsers use the browser's standard `DOMParser`; XML is never parsed with regular expressions. XML entities and CDATA are decoded by the XML parser. The text sanitizer preserves embedded line breaks, including HTTP requests/responses and scanner output. For `RESULT format="table"` values containing XML table rows, rows are converted into tab-separated text before they enter the existing single evidence path; plain-text tables retain their original whitespace.

## Output contract

The existing workbook layout is reused without a Qualys-specific template. It has the same worksheet name (`Vulnerabilities`), 18 columns, ordering, styles, filters, frozen header pane, widths, risk styling, and row behavior for both scanners:

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

Findings are sorted by severity (Critical → High → Medium → Low → Informational) before sequential `VUL-0001` numbering is assigned. Only the severities selected in the UI are exported. As in the original application, there is no deduplication pass: each scanner finding is retained as a record.

## Error handling

The application reports actionable errors for empty or invalid XML, unsupported XML roots, missing Nessus reports/hosts/findings, and missing required Qualys `IP`, `CAT`, or finding structure. A malformed Qualys `INFO`, `SERVICE`, `VULN`, or `PRACTICE` record with a missing/non-numeric QID or unsupported/missing numeric severity is skipped while the remaining report is imported; the UI reports how many records were skipped.

## Privacy

The application is **100% client-side and offline**:

- No backend, API, cloud processing, database, telemetry, analytics, tracking, or external requests.
- No CDN libraries or other runtime resources.
- All application JavaScript and the XLSX writer are bundled into the HTML file.
- The source scan is read only in the browser and never leaves the computer.
- It works with the internet disconnected.

## Tests

Representative synthetic fixtures cover Qualys `INFO`, `SERVICE`, `VULN`, and `PRACTICE` records, multiple hosts/categories, missing optional attributes, CDATA, entities (including escaped entities within CDATA), multiline and table `RESULT` content, every supported severity, format detection, malformed findings, Nessus regression behavior, and the generated workbook contract.

```bash
npm ci
npm test
```

`jsdom` is a development-only test dependency; the delivered browser application has no runtime package, server, or build-step dependency.

## Limitations

The existing register does not have dedicated columns for a Qualys QID, `LAST_UPDATE`, `PCI_FLAG`, category `misc`, source severity label, CVE, or `RESULT` format. These are retained where useful in the normalized model, but are not given new Excel columns. `RESULT`, diagnosis, and consequence are preserved through the existing `Implication` column. CVEs present in `VULN` or `PRACTICE` records are preserved in the model; the application does not fabricate missing CVE/CVSS values or perform external vulnerability enrichment.

## License

Not specified. Use the code as appropriate for your own project.
