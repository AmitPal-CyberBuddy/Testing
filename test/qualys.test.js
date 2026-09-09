"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const test = require("node:test");
const { inflateRawSync } = require("node:zlib");
const { JSDOM } = require("jsdom");

const repositoryRoot = join(__dirname, "..");
const appHtml = readFileSync(join(repositoryRoot, "nessus-iva-to-excel.html"), "utf8");

function loadApp() {
  const dom = new JSDOM(appHtml, {
    runScripts: "dangerously",
    pretendToBeVisual: true,
    beforeParse(window) {
      // The production application uses browser-standard APIs. These Node
      // implementations let the bundled Excel exporter be tested as well.
      window.TextEncoder = globalThis.TextEncoder;
      window.TextDecoder = globalThis.TextDecoder;
      window.Blob = globalThis.Blob;
      window.Response = globalThis.Response;
      if (typeof globalThis.CompressionStream === "function") {
        window.CompressionStream = globalThis.CompressionStream;
      }
    }
  });

  assert.ok(dom.window.VulnerabilityRegisterApp, "The bundled application should expose its test surface.");
  return { dom, app: dom.window.VulnerabilityRegisterApp };
}

const loaded = loadApp();
const app = loaded.app;

test.after(() => loaded.dom.window.close());

function fixture(name) {
  return readFileSync(join(repositoryRoot, "test", "fixtures", name), "utf8");
}

function waitFor(predicate, timeoutMs = 1000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    function check() {
      if (predicate()) return resolve();
      if (Date.now() - started >= timeoutMs) return reject(new Error("Timed out waiting for browser UI state."));
      setTimeout(check, 10);
    }
    check();
  });
}

function registerSettings() {
  return {
    project: "Project Atlas",
    activityType: "Vulnerability Assessment",
    dateRaised: "2026-07-15",
    expectedDateToClose: "2026-08-15",
    status: "Open",
    owner: "security.owner"
  };
}

function littleEndianU32(view, offset) {
  return view.getUint32(offset, true);
}

function zipEntryText(zip, expectedName) {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  let offset = 0;

  while (offset + 30 <= zip.length && littleEndianU32(view, offset) === 0x04034b50) {
    const flags = view.getUint16(offset + 6, true);
    const method = view.getUint16(offset + 8, true);
    const compressedSize = littleEndianU32(view, offset + 18);
    const nameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    assert.equal(flags & 0x0008, 0, "The minimal ZIP writer should not use data descriptors.");

    const nameStart = offset + 30;
    const name = Buffer.from(zip.subarray(nameStart, nameStart + nameLength)).toString("utf8");
    const dataStart = nameStart + nameLength + extraLength;
    const compressed = zip.subarray(dataStart, dataStart + compressedSize);

    if (name === expectedName) {
      const data = method === 8 ? inflateRawSync(compressed) : compressed;
      return Buffer.from(data).toString("utf8");
    }
    offset = dataStart + compressedSize;
  }

  throw new Error("ZIP entry not found: " + expectedName);
}

test("Qualys INFO findings normalize to the existing vulnerability model", async () => {
  const result = await app.ScanParser.parse(fixture("qualys-basic.xml"));
  const finding = result.findings[0];

  assert.equal(result.format, "qualys");
  assert.equal(result.sourceName, "Qualys");
  assert.equal(result.hostCount, 1);
  assert.equal(result.totalFindings, 1);
  assert.equal(result.earliestHostStart, "2026-07-15");
  assert.deepEqual(Array.from(result.warnings), []);

  assert.equal(finding.source, "qualys");
  assert.equal(finding.findingKind, "INFO");
  assert.equal(finding.hostIP, "192.0.2.10");
  assert.equal(finding.hostnamePreferred, "app.example.test");
  assert.equal(finding.port, "443");
  assert.equal(finding.portNumeric, 443);
  assert.equal(finding.protocol, "tcp");
  assert.equal(finding.pluginID, "12345");
  assert.equal(finding.pluginFamily, "CGI");
  assert.equal(finding.pluginName, "Example TLS configuration weakness");
  assert.equal(finding.synopsis, "Example TLS configuration weakness");
  assert.equal(finding.lastUpdate, "2026-07-01");
  assert.equal(finding.pciFlag, "1");
  assert.equal(finding.severity, 2);
  assert.equal(finding.severityName, "Medium");
  assert.equal(finding.sourceSeverity, "3");
  assert.equal(finding.sourceSeverityName, "Serious");
  assert.equal(finding.description, "Qualys detected a configuration weakness on the HTTPS service.");
  assert.equal(finding.impact, "An attacker may be able to weaken the TLS connection.");
  assert.equal(finding.solution, "Disable the affected protocol and deploy a supported TLS configuration.");
  assert.equal(finding.pluginOutput, "HTTPS service responded on port 443.");
});

test("Qualys SERVICE findings normalize exactly like INFO findings", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-service.xml"));
  const finding = result.findings[0];

  assert.equal(result.hostCount, 1);
  assert.equal(result.totalFindings, 1);
  assert.equal(finding.findingKind, "SERVICE");
  assert.equal(finding.pluginID, "34011");
  assert.equal(finding.severityName, "High");
  assert.equal(finding.portNumeric, 22);
  assert.equal(finding.service, "ssh");
  assert.equal(finding.protocol, "tcp");
});

test("Qualys parser processes multiple hosts and categories", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-multiple.xml"));

  assert.equal(result.hostCount, 2);
  assert.equal(result.totalFindings, 3);
  assert.deepEqual(Array.from(result.findings, (finding) => finding.pluginID), ["20001", "20002", "34012"]);
  assert.deepEqual(Array.from(result.findings, (finding) => finding.hostIP), ["192.0.2.30", "192.0.2.30", "192.0.2.31"]);
  assert.deepEqual(Array.from(result.findings, (finding) => finding.pluginFamily), ["CGI", "Firewall", "Services"]);
});

test("Qualys CAT entries without port or protocol remain importable", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-multiple.xml"));
  const finding = result.findings.find((item) => item.pluginID === "20002");
  const sorted = app.RegisterBuilder.sortAndNumber([finding]);
  const row = app.RegisterBuilder.buildRows(sorted, registerSettings())[0];

  assert.ok(finding);
  assert.equal(finding.port, "");
  assert.equal(finding.portNumeric, null);
  assert.equal(finding.protocol, "");
  assert.equal(row.port, "");
  assert.equal(row.testingInstance, "");
});

test("Qualys CDATA content is extracted without losing meaningful text", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-multiple.xml"));
  const finding = result.findings.find((item) => item.pluginID === "20001");

  assert.equal(finding.description, "The response contains <script>content</script> and must remain readable.");
  assert.equal(finding.impact, "An attacker could use the observed response.");
  assert.equal(finding.solution, "Encode output before returning it.");
});

test("Qualys XML entities are decoded by the XML parser", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-multiple.xml"));
  const finding = result.findings.find((item) => item.pluginID === "20002");

  assert.equal(finding.pluginName, "Entity \"test\" & comparison");
  assert.equal(finding.description, "Observed A < B and C > D with \"quoted\" values & symbols.");
});

test("Qualys HTML/XML block content keeps meaningful line boundaries", async () => {
  const xml = [
    "<SCAN><IP value=\"192.0.2.70\"><INFOS><CAT value=\"General\">",
    "<INFO number=\"70001\" severity=\"3\">",
    "<TITLE><p>First title line</p><p>Second title line</p></TITLE>",
    "<DIAGNOSIS><p>First diagnosis line</p><p>Second diagnosis line</p></DIAGNOSIS>",
    "</INFO></CAT></INFOS></IP></SCAN>"
  ].join("");
  const result = await app.QualysParser.parse(xml);

  assert.match(result.findings[0].pluginName, /^First title line\n+Second title line$/);
  assert.match(result.findings[0].description, /^First diagnosis line\n+Second diagnosis line$/);
});

test("Qualys multiline RESULT values preserve HTTP evidence", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-multiple.xml"));
  const finding = result.findings.find((item) => item.pluginID === "20001");

  assert.equal(
    finding.pluginOutput,
    "GET / HTTP/1.1\nHost: web.example.test\nConnection: Keep-Alive\n\nHTTP/1.1 200 OK\nServer: Example"
  );
});

test("Qualys table-format RESULT values are preserved as readable tab-separated rows", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-multiple.xml"));
  const finding = result.findings.find((item) => item.pluginID === "34012");

  assert.equal(finding.resultFormat, "table");
  assert.equal(
    finding.pluginOutput,
    "Port\tService\tDescription\n80\thttp\tWeb Server\n443\thttps\tSecure Web Server"
  );
});

test("plain-text Qualys table RESULT values retain their rows and columns", async () => {
  const xml = [
    "<SCAN><IP value=\"192.0.2.71\"><INFOS><CAT value=\"Services\">",
    "<INFO number=\"71001\" severity=\"2\"><TITLE>Plain table</TITLE>",
    "<RESULT format=\"table\">Port\tService\tDescription\n80\thttp\tWeb Server\n443\thttps\tSecure Web Server</RESULT>",
    "</INFO></CAT></INFOS></IP></SCAN>"
  ].join("");
  const result = await app.QualysParser.parse(xml);

  assert.equal(
    result.findings[0].pluginOutput,
    "Port\tService\tDescription\n80\thttp\tWeb Server\n443\thttps\tSecure Web Server"
  );
});

test("all supported Qualys severity values use the centralized normalized mapping", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-severities.xml"));

  assert.deepEqual(
    Array.from(result.findings, (finding) => finding.severityName),
    ["Informational", "Informational", "Low", "Medium", "High", "Critical"]
  );
  assert.deepEqual(
    Array.from(result.findings, (finding) => finding.severity),
    [0, 0, 1, 2, 3, 4]
  );
  assert.deepEqual(JSON.parse(JSON.stringify(app.normalizeQualysSeverity("5"))), {
    raw: "5",
    level: 4,
    severityName: "Critical",
    sourceName: "Urgent"
  });
  assert.equal(app.normalizeQualysSeverity("6"), null);
  assert.equal(app.normalizeQualysSeverity("critical"), null);
});

test("format detection selects Nessus or Qualys by XML structure, not extension", async () => {
  const nessusXml = fixture("nessus-minimal.nessus");
  const qualysXml = fixture("qualys-basic.xml");

  assert.equal(app.FormatDetector.detect(nessusXml), "nessus");
  assert.equal(app.FormatDetector.detect(qualysXml), "qualys");
  assert.throws(
    () => app.FormatDetector.detect("<inventory><host /></inventory>"),
    /Unsupported XML format/
  );
  assert.throws(() => app.FormatDetector.detect("<SCAN>"), /valid XML/);
  assert.throws(() => app.FormatDetector.detect("   \n\t "), /empty or contains only whitespace/);

  const nessusResult = await app.ScanParser.parse(nessusXml);
  assert.equal(nessusResult.format, "nessus");
  assert.equal(nessusResult.sourceName, "Nessus");
});

test("file upload UI automatically detects Qualys XML and enables the shared export flow", async () => {
  const isolated = loadApp();
  try {
    // Let the document finish dispatching DOMContentLoaded so its input handlers
    // are attached before the synthetic browser file-selection event.
    await new Promise((resolve) => setTimeout(resolve, 0));
    const { window } = isolated.dom;
    const input = window.document.getElementById("fileInput");
    const file = new window.File([fixture("qualys-basic.xml")], "scan.xml", { type: "application/xml" });
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    input.dispatchEvent(new window.Event("change", { bubbles: true }));

    await waitFor(() => window.document.getElementById("totalFindings").textContent === "1");
    assert.equal(window.document.getElementById("hostCount").textContent, "1");
    assert.equal(window.document.getElementById("dateRaised").value, "2026-07-15");
    assert.equal(window.document.getElementById("exportBtn").disabled, false);
    assert.match(window.document.getElementById("messageBox").textContent, /Ready\. Qualys report/);
  } finally {
    isolated.dom.window.close();
  }
});

test("Qualys structural validation returns actionable errors", async () => {
  await assert.rejects(
    () => app.QualysParser.parse("<SCAN />"),
    /does not contain any <IP> host entries/
  );
  await assert.rejects(
    () => app.QualysParser.parse("<SCAN><IP value=\"192.0.2.60\" /></SCAN>"),
    /does not contain any <CAT> finding categories/
  );
  await assert.rejects(
    () => app.QualysParser.parse("<SCAN><IP value=\"192.0.2.60\"><INFOS><CAT value=\"General\" /></INFOS></IP></SCAN>"),
    /No Qualys <INFO> or <SERVICE> findings/
  );
});

test("Qualys malformed findings are skipped without losing valid findings", async () => {
  const xml = [
    "<SCAN>",
    "  <IP value=\"192.0.2.50\"><INFOS><CAT value=\"General\">",
    "    <INFO severity=\"3\"><TITLE>Missing QID</TITLE></INFO>",
    "    <SERVICE number=\"50002\" severity=\"6\"><TITLE>Bad severity</TITLE></SERVICE>",
    "    <INFO number=\"50003\" severity=\"2\"><TITLE>Good finding</TITLE></INFO>",
    "  </CAT></INFOS></IP>",
    "</SCAN>"
  ].join("\n");
  const result = await app.QualysParser.parse(xml);

  assert.equal(result.totalFindings, 1);
  assert.equal(result.findings[0].pluginID, "50003");
  assert.equal(result.warnings.length, 2);
  assert.match(result.warnings[0], /required number.*missing/);
  assert.match(result.warnings[1], /not a supported numeric Qualys severity/);
});

test("Nessus parser and its existing implication behavior remain intact", async () => {
  const result = await app.NessusParser.parse(fixture("nessus-minimal.nessus"));
  const finding = result.findings[0];
  const sorted = app.RegisterBuilder.sortAndNumber(result.findings);
  const row = app.RegisterBuilder.buildRows(sorted, registerSettings())[0];

  assert.equal(result.hostCount, 1);
  assert.equal(result.totalFindings, 1);
  assert.equal(result.earliestHostStart, "2026-07-10");
  assert.equal(finding.hostIP, "198.51.100.10");
  assert.equal(finding.hostnamePreferred, "nessus-host.example.test");
  assert.equal(finding.osPreferred, "Example OS");
  assert.equal(finding.portNumeric, 443);
  assert.equal(finding.severityName, "High");
  assert.equal(finding.pluginID, "98765");
  assert.deepEqual(Array.from(finding.cves), ["CVE-2026-0001"]);
  assert.equal(row.implication, "Nessus description\n\nPlugin Output:\nNessus evidence");
  assert.equal(row.vulnerability, "Nessus regression finding");
});

test("Qualys uses the unchanged 18-column Excel register and existing workbook generator", async () => {
  const result = await app.QualysParser.parse(fixture("qualys-basic.xml"));
  const sorted = app.RegisterBuilder.sortAndNumber(result.findings);
  const rows = app.RegisterBuilder.buildRows(sorted, registerSettings());
  const expectedTitles = [
    "Project", "Activity Type", "Finding Type", "Vulnerability No.", "IP/URL", "Port",
    "Testing Instance", "Date Raised", "Expected Date to Close", "Status", "System Component",
    "Observation", "Risk", "Implication", "Recommendation", "Comments", "Vulnerability",
    "Owner (Manager or Action Owner User ID)"
  ];

  assert.deepEqual(Array.from(app.COLUMNS, (column) => column.title), expectedTitles);
  assert.equal(Object.keys(rows[0]).length, 18);
  assert.equal(rows[0].vulnNo, "VUL-0001");
  assert.equal(rows[0].ipUrl, "192.0.2.10");
  assert.equal(rows[0].findingType, "Other");
  assert.equal(rows[0].risk, "Medium");
  assert.equal(
    rows[0].implication,
    "Qualys detected a configuration weakness on the HTTPS service.\n\n" +
      "Impact / Consequence:\nAn attacker may be able to weaken the TLS connection.\n\n" +
      "Result:\nHTTPS service responded on port 443."
  );

  const blob = await app.ExcelExporter.export({
    rows,
    dateRaisedSerial: 46218,
    expectedCloseSerial: 46249
  });
  const zip = Buffer.from(await blob.arrayBuffer());
  const workbookXml = zipEntryText(zip, "xl/workbook.xml");
  const sheetXml = zipEntryText(zip, "xl/worksheets/sheet1.xml");

  assert.match(workbookXml, /<sheet name="Vulnerabilities" sheetId="1"/);
  assert.match(sheetXml, /<dimension ref="A1:R2"\/>/);
  assert.match(sheetXml, /<autoFilter ref="A1:R2"\/>/);
  assert.match(sheetXml, /<pane ySplit="1" topLeftCell="A2"/);
  assert.match(sheetXml, /Owner \(Manager or Action Owner User ID\)/);
  assert.match(sheetXml, /Result:\nHTTPS service responded on port 443\./);
});
