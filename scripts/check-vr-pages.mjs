import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const pages = [
  "vr/index.html",
  "vr/chat.html",
  "vr/action-center.html",
  "vr/project-board.html"
];
const expected = {
  "vr/index.html": [
    "navigator.xr.requestSession('immersive-vr'",
    "workspaceTargets",
    "function visitRoom(",
    "function interact(",
    "intersectObject(floor",
    "./project-board.html",
    "BACKEND NOT DEPLOYED",
    "manifest.webmanifest",
    "serviceWorker.register",
    "OPEN GITHUB EDITOR",
    "INSTALL / UPDATE"
  ],
  "vr/project-board.html": [
    "ghostcorp-project-board-v1",
    "Export backup",
    "Import backup",
    "localStorage"
  ],
  "vr/chat.html": [
    "navigator.gpu",
    "new Worker('./ai/worker.js'",
    "SmolLM2-360M-Instruct-q4f32_1-MLC"
  ],
  "vr/action-center.html": [
    "/api/owner/action-center",
    "backend is not connected"
  ]
};

function fail(message) {
  console.error("FAIL:", message);
  process.exitCode = 1;
}
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ghostcorp-vr-"));
try {
  for (const page of pages) {
    const file = path.join(root, page);
    if (!fs.existsSync(file)) {
      fail("Missing page: " + page);
      continue;
    }
    const html = fs.readFileSync(file, "utf8");
    for (const token of expected[page] || []) {
      if (!html.toLowerCase().includes(token.toLowerCase())) {
        fail(page + " is missing expected feature marker: " + token);
      }
    }
    const links = [...html.matchAll(/(?:href|src)=["']([^"'#]+)["']/gi)]
      .map(match => match[1])
      .filter(link => link.startsWith("./") && !/^\.\//.test(link.slice(0, 2)) === false);
    for (const link of links) {
      const target = path.resolve(path.dirname(file), link.split(/[?#]/)[0]);
      if (link.endsWith(".html") && !fs.existsSync(target)) {
        fail(page + " links to missing local page: " + link);
      }
    }

    let index = 0;
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    for (const match of scripts) {
      const attrs = match[1];
      const source = match[2].trim();
      if (!source || /\bsrc\s*=/.test(attrs) || /type=["']importmap["']/.test(attrs)) continue;
      const isModule = /type=["']module["']/.test(attrs);
      const extension = isModule ? ".mjs" : ".js";
      const tempFile = path.join(temp, path.basename(page).replace(".html", "") + "-" + index++ + extension);
      fs.writeFileSync(tempFile, source);
      const check = spawnSync(process.execPath, ["--check", tempFile], { encoding: "utf8" });
      if (check.status !== 0) fail(page + " inline JavaScript syntax error:\n" + (check.stderr || check.stdout));
    }
    console.log("PASS:", page, "parsed", scripts.length, "script block(s)");
  }


  const manifestPath = path.join(root, "vr/manifest.webmanifest");
  const iconPath = path.join(root, "vr/icon.svg");
  const serviceWorkerPath = path.join(root, "vr/sw.js");
  if (!fs.existsSync(manifestPath)) fail("Missing PWA manifest: vr/manifest.webmanifest");
  if (!fs.existsSync(iconPath)) fail("Missing PWA icon: vr/icon.svg");
  if (!fs.existsSync(serviceWorkerPath)) fail("Missing service worker: vr/sw.js");
  if (fs.existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (manifest.start_url !== "/vr/" || manifest.scope !== "/vr/") fail("PWA manifest must be scoped to /vr/");
      if (!Array.isArray(manifest.icons) || !manifest.icons.some(icon => icon.src === "./icon.svg")) fail("PWA manifest icon is missing");
    } catch (error) { fail("Invalid PWA manifest JSON: " + error.message); }
  }
  if (fs.existsSync(serviceWorkerPath)) {
    const serviceWorker = fs.readFileSync(serviceWorkerPath, "utf8");
    const serviceWorkerFile = path.join(temp, "sw.js");
    fs.writeFileSync(serviceWorkerFile, serviceWorker);
    const swCheck = spawnSync(process.execPath, ["--check", serviceWorkerFile], { encoding: "utf8" });
    if (swCheck.status !== 0) fail("vr/sw.js syntax error:\\n" + (swCheck.stderr || swCheck.stdout));
    else console.log("PASS: vr/sw.js");
    for (const token of ['"/api/"', '"/auth/"', "skipWaiting", "clients.claim"]) {
      if (!serviceWorker.includes(token)) fail("vr/sw.js missing safety/update marker: " + token);
    }
  }

  const worker = fs.readFileSync(path.join(root, "vr/ai/worker.js"), "utf8");
  const workerFile = path.join(temp, "worker.mjs");
  fs.writeFileSync(workerFile, worker);
  const workerCheck = spawnSync(process.execPath, ["--check", workerFile], { encoding: "utf8" });
  if (workerCheck.status !== 0) fail("vr/ai/worker.js syntax error:\n" + (workerCheck.stderr || workerCheck.stdout));
  else console.log("PASS: vr/ai/worker.js");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
if (!process.exitCode) console.log("GhostCorp VR static smoke checks passed.");
