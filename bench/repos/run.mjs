/**
 * Reproduce the UniQueS public-repo precision benchmark.
 *
 * For each repo in manifest.json: clone it at the pinned ref (into ./clones/<slug>,
 * gitignored), scan it with the built engine, and compare the actionable findings
 * against the published ground-truth labels in ./labels/<slug>.json. Prints
 * per-repo and overall precision, and flags any finding NOT covered by the labels
 * (i.e. drift since the corpus was labeled — those need a human to adjudicate).
 *
 * Requires the server to be built: `npm --prefix ../../server run build`.
 * Labels are the auditable artifact: labels/<slug>.json maps "<file>:<line>" to
 * { label: "TP"|"FP", algorithm, reason }. Read them; challenge them.
 */
import { scanDirectory } from "../../server/dist/discovery/scanner.js";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const manifest = JSON.parse(readFileSync(join(here, "manifest.json"), "utf8"));
const clonesDir = join(here, "clones");
mkdirSync(clonesDir, { recursive: true });

let TP = 0, FP = 0, UNLABELED = 0;
const rows = [];
for (const r of manifest.repos) {
  const dir = join(clonesDir, r.slug);
  if (!existsSync(dir)) {
    process.stderr.write(`cloning ${r.repo}@${r.ref} ...\n`);
    // execFileSync (no shell) — args are passed as an array, so nothing is
    // interpolated into a command line.
    execFileSync("git", ["clone", "--depth", "1", "--branch", r.ref,
      `https://github.com/${r.repo}.git`, dir], { stdio: "ignore" });
  }
  const labelPath = join(here, "labels", `${r.slug}.json`);
  const labels = existsSync(labelPath) ? JSON.parse(readFileSync(labelPath, "utf8")) : {};
  const { assets } = scanDirectory(dir, r.slug);
  const actionable = assets.filter((a) => a.confidence !== "low");
  let tp = 0, fp = 0, un = 0;
  for (const a of actionable) {
    const lab = labels[`${a.file}:${a.line}`];
    if (!lab) { un++; continue; }
    if (lab.label === "TP") tp++;
    else if (lab.label === "FP") fp++;
  }
  TP += tp; FP += fp; UNLABELED += un;
  rows.push({ slug: r.slug, lang: r.lang, actionable: actionable.length, tp, fp, unlabeled: un,
    precision: (tp + fp) ? (100 * tp / (tp + fp)).toFixed(1) + "%" : "n/a" });
}

console.log("\nUniQueS public-repo precision benchmark\n");
console.log("repo               lang         actionable   TP   FP  unlabeled  precision");
for (const r of rows) {
  console.log(r.slug.padEnd(18), (r.lang || "").padEnd(11), String(r.actionable).padStart(9),
    String(r.tp).padStart(5), String(r.fp).padStart(4), String(r.unlabeled).padStart(9), "   " + r.precision);
}
console.log("\nOVERALL PRECISION: " + TP + "/" + (TP + FP) + " = " + (TP + FP ? (100 * TP / (TP + FP)).toFixed(1) : "n/a") + "%");
if (UNLABELED) console.log(`NOTE: ${UNLABELED} finding(s) not covered by published labels (drift since labeling) — adjudicate before quoting.`);
