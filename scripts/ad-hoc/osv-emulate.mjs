#!/usr/bin/env node
// scripts/ad-hoc/osv-emulate.mjs
// AD-HOC (não faz parte de nenhum gate): reproduz localmente a contagem do
// check:vuln-ratchet, que delega ao binário `osv-scanner` (SIGSYS no Android).
//
// Usa a API pública do OSV (POST /v1/querybatch) sobre o MESMO package-lock.json e
// monta o JSON no formato do osv-scanner v1+ (results[].packages[].{package,
// vulnerabilities, groups}) para contar com o parseOsvJson() do gate real — mesma
// lógica de contagem, sem o binário nativo.
//
// Uso: node scripts/ad-hoc/osv-emulate.mjs [--out-json caminho]

import fs from "node:fs";
import path from "node:path";
import { parseOsvJson } from "../check/check-vuln-ratchet.mjs";

const ROOT = process.cwd();
const outIdx = process.argv.indexOf("--out-json");
const OUT = outIdx > -1 ? process.argv[outIdx + 1] : null;

/** Pacotes (name@version) do lockfile, na mesma ordem que o osv-scanner percorre. */
function collectPackages(lock) {
  const pkgs = [];
  for (const [p, meta] of Object.entries(lock.packages || {})) {
    if (!p.startsWith("node_modules/")) continue;
    if (!meta.version) continue;
    if (meta.link) continue;
    const name = p.slice(p.lastIndexOf("node_modules/") + "node_modules/".length);
    pkgs.push({ name, version: meta.version });
  }
  return pkgs;
}

/** ID canônico de um advisory: o menor alias serve de chave de grupo. */
function groupKey(vuln) {
  const ids = [vuln.id, ...(Array.isArray(vuln.aliases) ? vuln.aliases : [])].filter(Boolean);
  return [...new Set(ids)].sort()[0];
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

async function main() {
  const lock = JSON.parse(fs.readFileSync(path.join(ROOT, "package-lock.json"), "utf8"));
  const pkgs = collectPackages(lock);
  process.stderr.write(`[emulate] ${pkgs.length} pacote(s) no lockfile\n`);

  const CHUNK = 200;
  const hits = new Map(); // name@version → Set(id)
  for (let i = 0; i < pkgs.length; i += CHUNK) {
    const slice = pkgs.slice(i, i + CHUNK);
    const data = await postJson("https://api.osv.dev/v1/querybatch", {
      queries: slice.map((p) => ({
        package: { name: p.name, ecosystem: "npm" },
        version: p.version,
      })),
    });
    data.results.forEach((res, idx) => {
      const vulns = res.vulns || [];
      if (!vulns.length) return;
      const p = slice[idx];
      const set = hits.get(`${p.name}@${p.version}`) || new Set();
      for (const v of vulns) set.add(v.id);
      hits.set(`${p.name}@${p.version}`, set);
    });
    process.stderr.write(
      `[emulate] ${Math.min(i + CHUNK, pkgs.length)}/${pkgs.length} consultados\n`
    );
  }

  // Detalhes completos (aliases + database_specific.severity) para agrupar/deduplicar
  // exatamente como o osv-scanner faz (GHSA-xxx e CVE-yyy do mesmo advisory = 1 grupo).
  const allIds = [...new Set([...hits.values()].flatMap((s) => [...s]))];
  const details = new Map();
  const CONC = 8;
  for (let i = 0; i < allIds.length; i += CONC) {
    const slice = allIds.slice(i, i + CONC);
    const fetched = await Promise.all(
      slice.map(async (id) => {
        const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
        if (!res.ok) return { id };
        return res.json();
      })
    );
    for (const v of fetched) details.set(v.id, v);
  }

  const packages = [];
  for (const [key, ids] of hits) {
    const [name, version] = [
      key.slice(0, key.lastIndexOf("@")),
      key.slice(key.lastIndexOf("@") + 1),
    ];
    const vulns = [...ids].map((id) => details.get(id) || { id });
    const groups = new Map();
    for (const v of vulns) {
      const k = groupKey(v);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(v.id);
    }
    packages.push({
      package: { name, version, ecosystem: "npm" },
      vulnerabilities: vulns,
      groups: [...groups.values()].map((ids) => ({ ids, summary: undefined })),
    });
  }
  packages.sort((a, b) => a.package.name.localeCompare(b.package.name));

  const osvJson = {
    results: [{ source: { path: "package-lock.json", type: "lockfile" }, packages }],
  };
  if (OUT) fs.writeFileSync(path.resolve(ROOT, OUT), JSON.stringify(osvJson, null, 2));

  const { vulnCount, bySeverity } = parseOsvJson(osvJson);
  const rows = packages
    .map(
      (p) =>
        `${p.groups.length}\t${p.vulnerabilities.length}\t${p.package.name}@${p.package.version}\t${p.groups
          .map((g) => g.ids.join("/"))
          .join(" ")}`
    )
    .sort((a, b) => Number(b.split("\t")[0]) - Number(a.split("\t")[0]));
  process.stdout.write(rows.join("\n") + "\n\n");
  process.stdout.write(
    `EMULATED vulnCount=${vulnCount} (${Object.entries(bySeverity)
      .map(([k, v]) => `${k}=${v}`)
      .join(", ")}) pacotesAfetados=${packages.length} ids=${allIds.length}\n`
  );
}

main().catch((err) => {
  process.stderr.write(`[emulate] ERRO: ${err.message}\n`);
  process.exit(1);
});
