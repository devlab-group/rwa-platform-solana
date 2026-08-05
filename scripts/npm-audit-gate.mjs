#!/usr/bin/env node
// Fail-closed `npm audit` gate with a reviewed, expiring exception list.
//
// `npm audit` itself has no way to except a single advisory: the only knob is
// --audit-level, which is a blunt severity floor. Lowering that floor to let one
// unpatchable transitive through also blinds the gate to every *future*
// advisory at that severity, which is the opposite of what a security gate is
// for. This script keeps the floor at `high` and suppresses only the specific
// advisory IDs recorded in scripts/npm-audit-allowlist.json.
//
// Every exception carries an `expires` date. An expired exception fails the
// build, so accepting an advisory is a decision with a review date attached
// rather than a permanent hole. An exception that no longer matches anything is
// reported as STALE (upstream shipped a fix — delete the entry) but does not
// fail, so a good outcome never turns the build red.
//
// Usage: node scripts/npm-audit-gate.mjs <package-dir> [--audit-level=high]

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ALLOWLIST = resolve(HERE, "npm-audit-allowlist.json");

// Ordered so a severity floor is a simple index comparison.
const SEVERITIES = ["info", "low", "moderate", "high", "critical"];

const [dirArg, ...rest] = process.argv.slice(2);
if (!dirArg) {
  console.error("usage: npm-audit-gate.mjs <package-dir> [--audit-level=high]");
  process.exit(2);
}
const dir = resolve(process.cwd(), dirArg);
const levelArg = rest.find((a) => a.startsWith("--audit-level="));
const floor = levelArg ? levelArg.split("=")[1] : "high";
if (!SEVERITIES.includes(floor)) {
  console.error(`npm-audit-gate: unknown --audit-level=${floor}`);
  process.exit(2);
}
const floorIndex = SEVERITIES.indexOf(floor);

// `npm audit` exits non-zero whenever it finds anything at or above its own
// default floor, so a thrown error is the normal path — the JSON we want is on
// stdout either way. Only a genuinely absent stdout means npm itself failed.
function runAudit() {
  const args = ["audit", "--omit=dev", "--json"];
  try {
    return execFileSync("npm", args, { cwd: dir, encoding: "utf8" });
  } catch (err) {
    if (typeof err.stdout === "string" && err.stdout.trim() !== "") {
      return err.stdout;
    }
    console.error(`npm-audit-gate: npm audit failed in ${dir}`);
    console.error(err.stderr || err.message);
    process.exit(2);
  }
}

const report = JSON.parse(runAudit());

// npm's `vulnerabilities` map has one entry per affected package, but a package
// is listed whether it is the advisory's subject or merely a parent that
// depends on one. Parents carry their `via` as plain strings (the name of the
// package they inherit from); only the subject carries the advisory object. So
// collecting the object-valued `via` entries yields the distinct advisories,
// with each parent folded back in as an affected path rather than counted as
// its own finding.
const advisories = new Map();
for (const [name, vuln] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of vuln.via ?? []) {
    if (typeof via !== "object" || !via.url) continue;
    const id = via.url.split("/").pop(); // GHSA-xxxx-xxxx-xxxx
    const found = advisories.get(id) ?? {
      id,
      title: via.title,
      severity: via.severity,
      subject: via.name ?? name,
      paths: new Set(),
    };
    found.paths.add(name);
    advisories.set(id, found);
  }
}

const raw = readFileSync(ALLOWLIST, "utf8");
const allowlist = JSON.parse(raw).advisories ?? [];
const allowed = new Map(allowlist.map((a) => [a.id, a]));

// Compare dates as YYYY-MM-DD strings in UTC: an exception expires at the start
// of its `expires` day everywhere, rather than at whatever local midnight the
// machine running the gate happens to observe.
const today = new Date().toISOString().slice(0, 10);

const blocking = [];
const suppressed = [];
const expired = [];

for (const adv of advisories.values()) {
  if (SEVERITIES.indexOf(adv.severity) < floorIndex) continue;
  const exception = allowed.get(adv.id);
  if (!exception) {
    blocking.push(adv);
  } else if (exception.expires <= today) {
    expired.push({ adv, exception });
  } else {
    suppressed.push({ adv, exception });
  }
}

const stale = allowlist.filter((a) => !advisories.has(a.id));

const rel = dirArg.replace(/\/$/, "");
const counts = report.metadata?.vulnerabilities ?? {};
console.log(
  `npm-audit-gate ${rel}: floor=${floor}  ` +
    `(critical ${counts.critical ?? 0}, high ${counts.high ?? 0}, ` +
    `moderate ${counts.moderate ?? 0}, low ${counts.low ?? 0})`,
);

for (const { adv, exception } of suppressed) {
  console.log(
    `  ACCEPTED ${adv.id} [${adv.severity}] ${adv.subject} — ` +
      `expires ${exception.expires}\n` +
      `           ${exception.reason}`,
  );
}
for (const a of stale) {
  console.log(
    `  STALE    ${a.id} — no longer present; remove it from ${ALLOWLIST}`,
  );
}
for (const { adv, exception } of expired) {
  console.error(
    `  EXPIRED  ${adv.id} [${adv.severity}] ${adv.subject} — ` +
      `exception lapsed ${exception.expires}; re-review and extend or fix`,
  );
}
for (const adv of blocking) {
  console.error(
    `  BLOCKING ${adv.id} [${adv.severity}] ${adv.subject}: ${adv.title}\n` +
      `           via ${[...adv.paths].sort().join(", ")}`,
  );
}

if (blocking.length || expired.length) {
  console.error(
    `npm-audit-gate ${rel}: FAILED ` +
      `(${blocking.length} unreviewed, ${expired.length} expired)`,
  );
  process.exit(1);
}
console.log(`npm-audit-gate ${rel}: OK`);
