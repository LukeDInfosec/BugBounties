/* bbhunter interface.
   No build step and no framework: this file is served as-is, which means you
   can read exactly what the page does, and an update never has to rebuild
   anything. */

const S = {
  meta: null, programs: [], program: null, tools: null,
  running: false, seq: 0, logFilter: "all", counters: {}, stages: {},
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
}

/* ── navigation ─────────────────────────────────────────────────────────── */
const TITLES = {
  scope: ["Step 1 — Scope", "What may be touched, and what may never be"],
  run: ["Step 2 — Run", "Each step feeds the next; run the chain or one step"],
  gallery: ["Gallery", "What each distinct application looks like"],
  findings: ["Findings", "Triage state persists across runs"],
  assets: ["Assets", "Everything discovered, in scope and out"],
  diff: ["What's new", "Changes since the previous completed run"],
  tools: ["Tools", "What is installed and what is missing"],
  settings: ["Settings", "Defaults and API keys"],
  update: ["Update", "Pull the latest version from GitHub"],
};

document.querySelectorAll("nav button").forEach(btn => {
  btn.onclick = () => show(btn.dataset.page);
});

function show(page) {
  document.querySelectorAll("nav button").forEach(b =>
    b.classList.toggle("on", b.dataset.page === page));
  document.querySelectorAll(".page").forEach(p =>
    p.classList.toggle("on", p.id === "page-" + page));
  const [title, sub] = TITLES[page] || [page, ""];
  $("pageTitle").textContent = title;
  $("pageSub").textContent = sub;
  if (page === "gallery") loadGallery();
  if (page === "findings") loadFindings();
  if (page === "assets") loadAssets();
  if (page === "diff") loadDiff();
  if (page === "tools") loadTools();
  if (page === "run") loadRuns();
}

function modal(html) {
  $("modalbox").innerHTML = html;
  $("modal").classList.add("on");
}
function closeModal() { $("modal").classList.remove("on"); }
$("modal").onclick = (e) => { if (e.target.id === "modal") closeModal(); };

/* ── boot ───────────────────────────────────────────────────────────────── */
async function boot() {
  S.meta = await api("/api/meta");
  $("version").textContent = "v" + S.meta.version;
  $("railfoot").innerHTML =
    `Bound to localhost only.<br><span class="mono" style="font-size:10.5px">${esc(S.meta.data_dir)}</span>`;
  renderPresets();
  renderActiveStages();
  renderPhases();
  fillSettings(S.meta.settings);
  await loadPrograms();
  await loadTools();
  connect();
  show("scope");
}

/* ── programmes ─────────────────────────────────────────────────────────── */
async function loadPrograms() {
  S.programs = await api("/api/programs");
  const sel = $("programSelect");
  const previous = S.program?.id;
  sel.innerHTML = '<option value="">New programme…</option>' +
    S.programs.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("");
  if (previous && S.programs.find(p => p.id === previous)) sel.value = previous;
  else if (S.programs.length) sel.value = S.programs[0].id;
  selectProgram(sel.value);
}

$("programSelect").onchange = (e) => selectProgram(e.target.value);

function selectProgram(id) {
  S.program = S.programs.find(p => String(p.id) === String(id)) || null;
  const p = S.program;
  $("pName").value = p?.name || "";
  $("pPlatform").value = p?.platform || "";
  $("pHandle").value = p?.handle ?? (S.meta?.settings?.handle || "");
  if (!p && S.meta?.settings?.platform) $("pPlatform").value = S.meta.settings.platform;
  $("pInclude").value = (p?.scope?.include || []).join("\n");
  $("pExclude").value = (p?.scope?.exclude || []).join("\n");
  $("pBareChildren").checked = p ? p.scope.bare_includes_children !== false : true;
  $("pAllowPrivate").checked = !!p?.scope?.allow_private;
  $("pAllowMetadata").checked = !!p?.scope?.allow_metadata;
  $("pRps").value = p?.policy?.per_host_rps ?? 5;
  $("pGlobalRps").value = p?.policy?.global_rps ?? 20;
  const extra = Object.entries(p?.policy?.headers || {})
    .filter(([k]) => !k.startsWith("X-Bug-Bounty"))
    .map(([k, v]) => `${k}: ${v}`).join("\n");
  $("pHeaders").value = extra;
  $("scopeHash").textContent = p ? "scope " + p.scope_hash : "";
  updateHeaderPreview();
  updateBadges();
  if (p) { loadFindings(); loadAssets(); loadGallery(); }
  renderPhases();
}

$("pHandle").oninput = updateHeaderPreview;
function updateHeaderPreview() {
  const handle = $("pHandle").value.trim();
  $("headerPreview").innerHTML = handle
    ? `Every request will carry <code>X-Bug-Bounty: ${esc(handle)}</code> and
       <code>X-Bug-Bounty-Researcher: ${esc(handle)}</code>, over HTTP through the
       scope gate and over HTTPS via each tool's own header flag.`
    : `Set a handle and every request will carry <code>X-Bug-Bounty: &lt;handle&gt;</code>.
       Most programmes ask for this; it is what lets a blue team tell your
       testing from an attack.`;
}

function parseHeaders(text) {
  const out = {};
  (text || "").split("\n").forEach(line => {
    const i = line.indexOf(":");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return out;
}

$("saveProgram").onclick = async () => {
  const name = $("pName").value.trim();
  if (!name) return modal("<h3>Name required</h3><p>Give the programme a name.</p>");
  try {
    const res = await api("/api/programs", {
      method: "POST",
      body: {
        name, platform: $("pPlatform").value, handle: $("pHandle").value.trim(),
        include: $("pInclude").value, exclude: $("pExclude").value, seeds: "",
        allow_private: $("pAllowPrivate").checked,
        allow_metadata: $("pAllowMetadata").checked,
        bare_includes_children: $("pBareChildren").checked,
        headers: parseHeaders($("pHeaders").value),
        per_host_rps: Number($("pRps").value) || 5,
        global_rps: Number($("pGlobalRps").value) || 20,
      },
    });
    await loadPrograms();
    $("programSelect").value = res.program.id;
    selectProgram(res.program.id);
    if (res.rule_errors?.length) {
      modal(`<h3>Saved, with ${res.rule_errors.length} unusable rule(s)</h3>
        <p class="hint">These lines could not be parsed and were ignored:</p>
        <pre>${esc(res.rule_errors.map(e => `${e.line}  →  ${e.error}`).join("\n"))}</pre>
        <button class="btn" onclick="closeModal()">Close</button>`);
    }
  } catch (e) {
    modal(`<h3>Could not save</h3><p>${esc(e.message)}</p>
      <button class="btn" onclick="closeModal()">Close</button>`);
  }
};

$("deleteProgram").onclick = async () => {
  if (!S.program) return;
  modal(`<h3>Delete ${esc(S.program.name)}?</h3>
    <p class="hint">This removes the programme and every asset, run and finding
    recorded against it. It cannot be undone.</p>
    <div class="row"><button class="btn danger" id="confirmDel">Delete</button>
    <button class="btn ghost" onclick="closeModal()">Cancel</button></div>`);
  $("confirmDel").onclick = async () => {
    await api(`/api/programs/${S.program.id}`, { method: "DELETE" });
    closeModal();
    await loadPrograms();
  };
};

$("explainBtn").onclick = async () => {
  if (!S.program) return;
  const res = await api("/api/scope/explain", {
    method: "POST",
    body: { program_id: S.program.id, assets: $("explainIn").value },
  });
  $("explainOut").innerHTML = res.results.length ? `<table>
    <tr><th>Asset</th><th>Decision</th><th>Why</th></tr>
    ${res.results.map(r => `<tr>
      <td class="mono">${esc(r.asset)}</td>
      <td><span class="pill ${r.decision}">${r.decision}</span></td>
      <td style="color:var(--dim)">${esc(r.reason)}${r.rule ? " — " + esc(r.rule) : ""}</td>
    </tr>`).join("")}</table>` : "";
};

/* ── run ────────────────────────────────────────────────────────────────── */
function renderPresets() {
  $("presets").innerHTML = Object.entries(S.meta.presets).map(([key, p], i) => `
    <label class="check" style="align-items:flex-start;padding:10px 0;
      border-bottom:1px solid var(--border-soft)">
      <input type="radio" name="preset" value="${key}" ${i === 1 ? "checked" : ""}
        style="width:15px;height:15px;accent-color:var(--accent);margin-top:3px">
      <span><b>${esc(p.label)}</b> <span class="mono"
        style="color:var(--faint);font-size:11px">${p.stages.length} stages</span>
      <span class="d">${esc(p.blurb)}</span></span></label>`).join("");
}

function renderActiveStages() {
  $("activeStages").innerHTML = Object.entries(S.meta.active_stages).map(([key, a]) => `
    <label class="check"><input type="checkbox" class="activestage" value="${key}">
      <span><b>${esc(a.label)}</b><span class="d">${esc(a.warning)}</span></span></label>`).join("");
}

/* The chain as the phases a tester thinks in. The grouping comes from the
   server so the interface and the engine cannot disagree about what belongs
   to which step. */
function renderPhases() {
  const stages = S.meta.stages || {};
  $("phaseList").innerHTML = (S.meta.phases || []).map(ph => {
    const mine = ph.stages.filter(k => stages[k]);
    const states = mine.map(k => S.stages?.[k]).filter(Boolean);
    let cls = "";
    if (states.length && states.every(v => ["completed", "skipped"].includes(v))) cls = "done";
    if (states.includes("running")) cls = "running";
    if (states.includes("failed")) cls = "failed";

    const chips = mine.map(k => {
      const st = S.stages?.[k] || "";
      const meta = S.stageMeta?.[k] || {};
      const tool = stages[k].tool;
      const missing = tool && S.tools && S.tools.missing?.includes(tool);
      const count = meta.produced != null && st === "completed" ? ` ${meta.produced}` : "";
      return `<span class="chipstage ${st}" title="${esc(stages[k].description)}${
        missing ? ` — needs ${tool}` : ""}">${esc(stages[k].name)}${count}</span>`;
    }).join("");

    return `<div class="phase ${cls}">
      <div class="num">${ph.number}</div>
      <div class="body">
        <div class="t">${esc(ph.label)}</div>
        <div class="b">${esc(ph.blurb)}</div>
        <div class="steps">${chips}</div>
      </div>
      <div class="act">
        <button class="btn ghost sm runphase" data-stages="${esc(mine.join(","))}"
          data-label="${esc(ph.label)}">Run this step</button>
      </div>
    </div>`;
  }).join("");

  document.querySelectorAll(".runphase").forEach(btn => {
    btn.onclick = () => runStages(btn.dataset.stages.split(","), btn.dataset.label);
  });
}

async function runStages(stageKeys, label) {
  if (!S.program) return modal(`<h3>No programme selected</h3>
    <p>Create one on the Scope page first.</p>
    <button class="btn" onclick="closeModal()">Close</button>`);
  if (S.running) return modal(`<h3>A scan is already running</h3>
    <p class="hint">Stop it first, or wait for it to finish.</p>
    <button class="btn" onclick="closeModal()">Close</button>`);

  const active = stageKeys.filter(k => S.meta.active_stages[k]);
  modal(`<h3>Run "${esc(label)}" only?</h3>
    <p class="hint">This runs ${stageKeys.length} stage(s) against
      ${esc(S.program.name)}, reusing whatever earlier steps already produced.
      Useful when you have changed the scope or added hosts by hand and only
      need this part redone.</p>
    <pre>${esc(stageKeys.map(k => S.meta.stages[k]?.name || k).join("\n"))}</pre>
    ${active.length ? `<div class="note danger"><b>This includes active
      testing.</b> Payloads will be sent to in-scope parameters.</div>
      <label class="check"><input type="checkbox" id="ackStep">
      <span>I have authorisation to actively test this scope.</span></label>` : ""}
    <div class="row" style="margin-top:16px">
      <button class="btn" id="stepGo">Run</button>
      <button class="btn ghost" onclick="closeModal()">Cancel</button>
    </div>`);

  $("stepGo").onclick = async () => {
    if (active.length && !$("ackStep").checked) return;
    try {
      await api("/api/runs", { method: "POST", body: {
        program_id: S.program.id, preset: "standard",
        active_stages: active, acknowledge_active: true,
        only_stages: stageKeys,
      }});
      closeModal();
      $("runSetup").style.display = "none";
      $("runLive").style.display = "";
      $("log").innerHTML = "";
      S.counters = {}; S.stages = {};
      show("run");
    } catch (e) {
      modal(`<h3>Could not start</h3><p>${esc(e.message)}</p>
        <button class="btn" onclick="closeModal()">Close</button>`);
    }
  };
}

function selectedActive() {
  return [...document.querySelectorAll(".activestage:checked")].map(c => c.value);
}

$("preflightBtn").onclick = async () => {
  if (!S.program) return modal(`<h3>No programme selected</h3>
    <p>Create one on the Scope page first.</p>
    <button class="btn" onclick="closeModal()">Close</button>`);
  const preset = document.querySelector("input[name=preset]:checked")?.value || "standard";
  const active = selectedActive();
  const pre = await api("/api/preflight", {
    method: "POST",
    body: { program_id: S.program.id, preset, active_stages: active },
  });

  const warn = pre.warnings.map(w =>
    `<div class="note ${w.includes("Active testing") || w.includes("metadata") ? "danger" : "warn"}">${esc(w)}</div>`).join("");
  const stages = pre.stages.map(s => `<tr>
      <td>${esc(s.name)}${s.active ? ' <span class="pill high">active</span>' : ""}</td>
      <td style="color:var(--dim)">${esc(s.description)}</td>
      <td>${s.tool ? (s.installed
        ? `<span class="pill ok">${esc(s.tool)}</span>`
        : `<span class="pill medium">${esc(s.tool)} missing</span>`) : "—"}</td>
    </tr>`).join("");
  const ident = Object.entries(pre.identification || {});

  modal(`
    <h3>About to scan ${esc(pre.program)}</h3>
    <p class="hint">${esc(pre.preset_blurb)}</p>
    ${warn}
    <div class="kv" style="margin:14px 0">
      <span class="k">In scope</span><span class="v">${pre.scope.includes.map(esc).join(", ") || "—"}</span>
      <span class="k">Excluded</span><span class="v">${pre.scope.excludes.map(esc).join(", ") || "none"}</span>
      <span class="k">Seeds</span><span class="v">${pre.seeds.map(esc).join(", ") || "—"}</span>
      <span class="k">Rate</span><span class="v">${pre.rate.per_host_rps}/s per host,
        ${pre.rate.global_rps}/s combined, ${pre.rate.per_host_concurrency} concurrent</span>
      <span class="k">Identifies as</span><span class="v">${ident.length
        ? ident.map(([k, v]) => `${esc(k)}: ${esc(v)}`).join("<br>")
        : '<span style="color:var(--warn)">nothing configured</span>'}</span>
      <span class="k">Scope hash</span><span class="v">${esc(pre.scope.fingerprint)}</span>
    </div>
    <table><tr><th>Stage</th><th>What it does</th><th>Tool</th></tr>${stages}</table>
    ${pre.missing_tools.length ? `<div class="note warn">
      <b>${pre.missing_tools.length} tool(s) missing:</b>
      ${pre.missing_tools.map(esc).join(", ")}. Those stages will be skipped and
      said so in the log rather than failing the run.</div>` : ""}
    ${pre.active.length ? `<label class="check" style="margin-top:14px">
      <input type="checkbox" id="ackActive">
      <span><b>I have authorisation to actively test this scope.</b>
      <span class="d">Payloads will be sent to parameters on in-scope hosts.</span></span>
      </label>` : ""}
    <div class="row" style="margin-top:18px">
      <button class="btn" id="goBtn">Start scan</button>
      <button class="btn ghost" onclick="closeModal()">Cancel</button>
    </div>`);

  $("goBtn").onclick = async () => {
    if (pre.active.length && !$("ackActive").checked) {
      return modal($("modalbox").innerHTML.replace(
        '<div class="row" style="margin-top:18px">',
        '<div class="note danger">Tick the authorisation box to continue.</div><div class="row" style="margin-top:18px">'));
    }
    try {
      await api("/api/runs", {
        method: "POST",
        body: { program_id: S.program.id, preset, active_stages: active,
                acknowledge_active: true },
      });
      closeModal();
      $("runSetup").style.display = "none";
      $("runLive").style.display = "";
      $("log").innerHTML = "";
      S.counters = {}; S.stages = {};
      show("run");
    } catch (e) {
      modal(`<h3>Could not start</h3><p>${esc(e.message)}</p>
        <button class="btn" onclick="closeModal()">Close</button>`);
    }
  };
};

$("cancelBtn").onclick = async () => {
  await api("/api/runs/cancel", { method: "POST" });
};

document.querySelectorAll("[data-logfilter]").forEach(chip => {
  chip.onclick = () => {
    document.querySelectorAll("[data-logfilter]").forEach(c => c.classList.remove("on"));
    chip.classList.add("on");
    S.logFilter = chip.dataset.logfilter;
  };
});

async function loadRuns() {
  if (!S.program) return;
  const runs = await api(`/api/programs/${S.program.id}/runs`);
  $("runsList").innerHTML = runs.length ? `<table>
    <tr><th>#</th><th>Profile</th><th>Status</th><th>Stages</th><th>Started</th><th>Requests</th></tr>
    ${runs.map(r => {
      const stats = JSON.parse(r.request_stats_json || "{}");
      const done = r.stages.filter(s => s.status === "completed").length;
      return `<tr>
        <td class="mono">${r.id}</td>
        <td>${esc(r.preset)}</td>
        <td><span class="pill ${r.status === "completed" ? "ok" :
          r.status === "failed" ? "high" : "medium"}">${esc(r.status)}</span></td>
        <td class="mono">${done}/${r.stages.length}</td>
        <td style="color:var(--dim)">${r.started_at
          ? new Date(r.started_at * 1000).toLocaleString() : "—"}</td>
        <td class="mono">${stats.total_requests ?? "—"}${stats.total_blocked
          ? ` <span style="color:var(--warn)">(${stats.total_blocked} refused)</span>` : ""}</td>
      </tr>`;
    }).join("")}</table>` : '<div class="empty">No runs yet.</div>';
}

/* ── live stream ────────────────────────────────────────────────────────── */
function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => ws.send(JSON.stringify({ since: S.seq }));
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "status") return applyStatus(msg.status);
    if (msg.type !== "batch") return;
    msg.events.forEach(handleEvent);
    if (msg.dropped) {
      addLog(`… ${msg.dropped} line(s) dropped to keep the scan running`, "warn");
    }
  };
  ws.onclose = () => setTimeout(connect, 1500);
}

function applyStatus(status) {
  S.running = !!status.running;
  $("livedot").classList.toggle("live", S.running);
  $("runBadge").textContent = S.running ? "●" : "";
  if (S.running) {
    $("runSetup").style.display = "none";
    $("runLive").style.display = "";
    Object.entries(status.stage_states || {}).forEach(([k, v]) => { S.stages[k] = v; });
    renderStages();
  }
}

function handleEvent(ev) {
  S.seq = Math.max(S.seq, ev.seq);
  const d = ev.data || {};
  switch (ev.kind) {
    case "run_started":
      S.running = true;
      $("livedot").classList.add("live");
      $("runStatus").textContent = "running";
      $("runStatus").className = "pill ok";
      S.stages = {};
      (d.stages || []).forEach(s => { S.stages[s.key] = "pending"; S.stageNames = S.stageNames || {}; S.stageNames[s.key] = s.name; });
      renderStages();
      addLog(`Run ${d.run_id} started on ${d.program}`, "ok");
      break;
    case "stage":
      S.stages[d.key] = d.status;
      S.stageMeta = S.stageMeta || {};
      S.stageMeta[d.key] = d;
      renderStages();
      renderPhases();
      if (d.key === "screenshots" && d.status === "completed") loadGallery();
      break;
    case "counter":
      S.counters[d.name] = d.value;
      renderCounters();
      break;
    case "log":
      addLog(d.text, d.level || "info");
      break;
    case "tool":
      addLog(`  [${d.tool}] ${d.text}`, "tool");
      break;
    case "blocked":
      addLog(`gate refused ${d.method || "GET"} ${d.host} — ${d.reason}`, "warn");
      break;
    case "throttled":
      addLog(`${d.host} returned ${d.status}; rate cut to ${d.new_rate}/s and backing off ${d.backoff_s}s`, "warn");
      break;
    case "finding":
      addLog(`FINDING [${d.severity}] ${d.title} — ${d.target}`,
             d.severity === "critical" || d.severity === "high" ? "error" : "ok");
      updateBadges();
      break;
    case "run_finished":
      S.running = false;
      $("livedot").classList.remove("live");
      $("runStatus").textContent = d.status;
      $("runStatus").className = "pill " + (d.status === "completed" ? "ok" : "medium");
      addLog(`Run finished: ${d.status}. ${d.findings} finding(s), ${d.new_assets} new asset(s).`, "ok");
      $("runSetup").style.display = "";
      renderPhases();
      loadRuns(); loadFindings(); loadAssets(); loadGallery(); updateBadges();
      break;
  }
}

function renderStages() {
  const names = S.stageNames || {};
  const meta = S.stageMeta || {};
  $("stagestrip").innerHTML = Object.entries(S.stages).map(([key, status]) => {
    const m = meta[key] || {};
    const extra = m.produced != null && status === "completed"
      ? `<span class="n">${m.produced}</span>` : "";
    return `<div class="stage ${status}" title="${esc(m.message || "")}">
      <span class="ic"></span>${esc(names[key] || m.name || key)}${extra}</div>`;
  }).join("");
}

const COUNTER_LABELS = {
  roots: "Root domains", subdomains: "Subdomains", resolved: "Resolving",
  live_http: "Live HTTP", distinct_apps: "Distinct apps", open_ports: "Open ports",
  urls: "URLs", endpoint_shapes: "Endpoint shapes", parameters: "Parameters",
  js_files: "JS files", nuclei_findings: "Template hits", dast_findings: "Injection",
  xss_findings: "XSS candidates", screenshots: "Screenshots",
  takeover_candidates: "Takeover leads",
};

function renderCounters() {
  $("counters").innerHTML = Object.entries(S.counters).map(([k, v]) =>
    `<div class="counter"><div class="v">${Number(v).toLocaleString()}</div>
     <div class="k">${esc(COUNTER_LABELS[k] || k)}</div></div>`).join("");
}

function addLog(text, level = "info") {
  if (S.logFilter === "framework" && level === "tool") return;
  if (S.logFilter === "warn" && !["warn", "error"].includes(level)) return;
  const el = $("log");
  const stick = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
  const time = new Date().toLocaleTimeString([], { hour12: false });
  const div = document.createElement("div");
  div.className = "l-" + level;
  div.innerHTML = `<span class="t">${time}</span>${esc(text)}`;
  el.appendChild(div);
  while (el.childElementCount > 3000) el.removeChild(el.firstChild);
  if (stick) el.scrollTop = el.scrollHeight;
}

/* ── gallery ────────────────────────────────────────────────────────────── */
$("gSearch").oninput = debounce(loadGallery, 300);

async function loadGallery() {
  if (!S.program) return;
  const q = new URLSearchParams({ search: $("gSearch").value, limit: 400 });
  const res = await api(`/api/programs/${S.program.id}/gallery?${q}`);
  $("galleryCount").textContent = res.items.length
    ? `${res.items.length} of ${res.total} captured` : "";
  $("shotBadge").textContent = res.total || "";

  $("galleryGrid").innerHTML = res.items.length ? res.items.map(item => {
    const sev = item.status == null ? "info"
      : item.status < 300 ? "ok" : item.status < 400 ? "low"
      : item.status < 500 ? "medium" : "high";
    return `<a class="shot" href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">
      <img class="img" src="${esc(item.image)}" alt="" loading="lazy">
      <div class="meta">
        <div class="u">${esc(item.url)}</div>
        <div class="ti">${esc(item.title || "no title")}</div>
        <div class="tags">
          ${item.status != null ? `<span class="pill ${sev}">${item.status}</span>` : ""}
          ${(item.tech || []).slice(0, 3).map(t =>
            `<span class="pill info">${esc(t)}</span>`).join("")}
          ${item.server ? `<span class="pill info">${esc(item.server)}</span>` : ""}
        </div>
      </div></a>`;
  }).join("") : `<div class="empty" style="grid-column:1/-1">
      <div class="big">◱</div>No screenshots yet.
      <div style="margin-top:8px;font-size:12.5px">Run step 3 — "See what is
      alive" — and the distinct applications are captured automatically.</div>
    </div>`;
}

/* ── findings ───────────────────────────────────────────────────────────── */
["fSeverity", "fTriage"].forEach(id => $(id).onchange = loadFindings);
$("fSearch").oninput = debounce(loadFindings, 300);

async function loadFindings() {
  if (!S.program) return;
  const q = new URLSearchParams({
    severity: $("fSeverity").value, triage: $("fTriage").value,
    search: $("fSearch").value, limit: 300,
  });
  const res = await api(`/api/programs/${S.program.id}/findings?${q}`);
  const counts = res.counts;
  $("findingCounts").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter(s => counts[s]).map(s =>
      `<span class="pill ${s}">${counts[s]} ${s}</span>`).join(" ") || "";
  $("findBadge").textContent = (counts.critical + counts.high) || "";

  $("findingsList").innerHTML = res.items.length ? res.items.map(f => `
    <div style="border-bottom:1px solid var(--border-soft);padding:13px 0">
      <div class="row">
        <span class="pill ${f.severity}">${f.severity}</span>
        <b>${esc(f.title)}</b>
        ${f.instances > 1 ? `<span class="mono" style="color:var(--faint);font-size:11px">×${f.instances}</span>` : ""}
        ${f.confidence === "tentative" ? '<span class="pill medium">needs confirming</span>' : ""}
        <div class="right row">
          <select class="sm triage" data-id="${f.id}" style="width:auto;padding:4px 8px;font-size:12px">
            ${["new", "reviewed", "reported", "dismissed", "duplicate"].map(t =>
              `<option value="${t}" ${f.triage === t ? "selected" : ""}>${t}</option>`).join("")}
          </select>
        </div>
      </div>
      <div class="mono trunc" style="color:var(--dim);margin-top:5px">${esc(f.target)}</div>
      ${f.detail ? `<div style="color:var(--dim);font-size:12.5px;margin-top:6px">${esc(f.detail)}</div>` : ""}
      ${f.evidence ? `<details><summary>Evidence</summary><pre>${esc(f.evidence)}</pre></details>` : ""}
      ${f.repro ? `<details><summary>How to confirm it</summary><pre>${esc(f.repro)}</pre></details>` : ""}
      <div class="mono" style="color:var(--faint);font-size:11px;margin-top:6px">
        ${esc(f.tool)} · first seen run ${f.first_seen_run}</div>
    </div>`).join("") : '<div class="empty"><div class="big">◎</div>No findings yet.</div>';

  document.querySelectorAll(".triage").forEach(sel => {
    sel.onchange = async () => {
      await api("/api/findings/triage", {
        method: "POST",
        body: { finding_id: Number(sel.dataset.id), triage: sel.value },
      });
      loadFindings();
    };
  });
}

/* ── assets ─────────────────────────────────────────────────────────────── */
["aKind", "aDecision"].forEach(id => $(id).onchange = loadAssets);
$("aSearch").oninput = debounce(loadAssets, 300);

async function loadAssets() {
  if (!S.program) return;
  const q = new URLSearchParams({
    kind: $("aKind").value, decision: $("aDecision").value,
    search: $("aSearch").value, limit: 300,
  });
  const res = await api(`/api/programs/${S.program.id}/assets?${q}`);

  const kindSel = $("aKind");
  const current = kindSel.value;
  kindSel.innerHTML = '<option value="">All kinds</option>' +
    Object.entries(res.kinds).map(([k, c]) =>
      `<option value="${k}">${k} (${c})</option>`).join("");
  kindSel.value = current;
  $("assetTotal").textContent = `${res.items.length} shown of ${res.total}`;
  $("assetBadge").textContent = Object.values(res.kinds).reduce((a, b) => a + b, 0) || "";

  $("assetsList").innerHTML = res.items.length ? `<table>
    <tr><th>Asset</th><th>Kind</th><th>Scope</th><th>Detail</th></tr>
    ${res.items.map(a => {
      const d = a.data || {};
      const bits = [];
      if (d.status) bits.push(`<span class="pill ${d.status < 300 ? "ok" :
        d.status < 400 ? "low" : d.status < 500 ? "medium" : "high"}">${d.status}</span>`);
      if (d.title) bits.push(esc(d.title));
      if (d.tech?.length) bits.push(`<span style="color:var(--faint)">${esc(d.tech.slice(0, 4).join(", "))}</span>`);
      if (d.a?.length) bits.push(`<span class="mono" style="color:var(--faint)">${esc(d.a.slice(0, 2).join(", "))}</span>`);
      if (d.cname) bits.push(`<span class="mono" style="color:var(--faint)">→ ${esc(d.cname)}</span>`);
      if (d.instances) bits.push(`<span style="color:var(--faint)">${d.instances} URL(s)</span>`);
      if (d.classes?.length) bits.push(d.classes.map(c => `<span class="pill medium">${esc(c)}</span>`).join(" "));
      if (d.occurrences) bits.push(`<span style="color:var(--faint)">seen ${d.occurrences}×</span>`);
      return `<tr>
        <td class="mono trunc">${esc(a.key)}</td>
        <td style="color:var(--dim)">${esc(a.kind)}</td>
        <td><span class="pill ${a.scope_decision}">${a.scope_decision}</span></td>
        <td class="trunc">${bits.join(" ")}</td></tr>`;
    }).join("")}</table>` : '<div class="empty"><div class="big">◇</div>Nothing discovered yet.</div>';
}

/* ── diff ───────────────────────────────────────────────────────────────── */
async function loadDiff() {
  if (!S.program) return;
  const d = await api(`/api/programs/${S.program.id}/diff`);
  const group = (items) => {
    const by = {};
    items.forEach(i => (by[i.kind] = by[i.kind] || []).push(i.key));
    return by;
  };
  const newBy = group(d.new_assets || []);
  const goneBy = group(d.gone_assets || []);

  $("diffOut").innerHTML = `
    ${d.caveat ? `<div class="note warn">${esc(d.caveat)}
      ${d.unreliable?.length ? "<br>Affected: " + d.unreliable.map(esc).join(", ") : ""}</div>` : ""}
    <div class="kv" style="margin-bottom:16px">
      <span class="k">Run</span><span class="v">${d.run_id}</span>
      <span class="k">Compared with</span><span class="v">${d.baseline_run_id ?? "nothing — this is the first run"}</span>
    </div>
    ${(d.new_findings || []).length ? `<h3 style="font-size:13px;margin:16px 0 8px">
      New findings</h3>${d.new_findings.map(f =>
      `<div class="row" style="padding:5px 0"><span class="pill ${f.severity}">${f.severity}</span>
       <b>${esc(f.title)}</b> <span class="mono trunc" style="color:var(--dim)">${esc(f.target)}</span></div>`).join("")}` : ""}
    ${Object.keys(newBy).length ? `<h3 style="font-size:13px;margin:18px 0 8px">
      New assets</h3>${Object.entries(newBy).map(([kind, keys]) => `
      <details open><summary>${esc(kind)} — ${keys.length}</summary>
      <pre>${esc(keys.slice(0, 200).join("\n"))}${keys.length > 200 ? `\n… +${keys.length - 200} more` : ""}</pre>
      </details>`).join("")}` : '<div class="empty">Nothing new in this run.</div>'}
    ${Object.keys(goneBy).length ? `<h3 style="font-size:13px;margin:18px 0 8px">
      No longer seen</h3>${Object.entries(goneBy).map(([kind, keys]) => `
      <details><summary>${esc(kind)} — ${keys.length}</summary>
      <pre>${esc(keys.slice(0, 200).join("\n"))}</pre></details>`).join("")}` : ""}`;
}

/* ── tools ──────────────────────────────────────────────────────────────── */
async function loadTools() {
  S.tools = await api("/api/tools");
  const detail = S.tools.detail || {};
  const missingRequired = S.tools.missing_required || [];
  $("toolBadge").textContent = S.tools.missing.length
    ? `${S.tools.installed.length}/${S.tools.installed.length + S.tools.missing.length}` : "";

  $("toolsList").innerHTML = `
    ${missingRequired.length ? `<div class="note danger">
      <b>${missingRequired.length} required tool(s) missing:</b>
      ${missingRequired.map(esc).join(", ")}. Run <code>./install.sh</code>
      or copy the commands below.</div>` : `<div class="note">
      All required tools are present.</div>`}
    <table><tr><th>Tool</th><th>What it does</th><th>Status</th><th>Version</th></tr>
    ${Object.values(detail).sort((a, b) =>
      (a.installed === b.installed) ? a.key.localeCompare(b.key) : (a.installed ? 1 : -1))
      .map(t => `<tr>
        <td class="mono">${esc(t.key)}${t.optional === false
          ? ' <span class="pill high">required</span>' : ""}</td>
        <td style="color:var(--dim)">${esc(t.purpose || "")}
          ${t.notes ? `<div style="color:var(--faint);font-size:11.5px;margin-top:3px">${esc(t.notes)}</div>` : ""}</td>
        <td>${t.installed ? '<span class="pill ok">installed</span>'
          : '<span class="pill medium">missing</span>'}</td>
        <td class="mono" style="font-size:11px;color:var(--faint)">
          ${t.installed ? esc((t.version || "").slice(0, 40))
            : `<code>${esc(t.install || "")}</code>`}</td>
      </tr>`).join("")}</table>`;
}

$("refreshTools").onclick = loadTools;
$("copyInstall").onclick = () => {
  const detail = S.tools?.detail || {};
  const text = Object.values(detail).filter(t => !t.installed)
    .map(t => `# ${t.key} — ${t.purpose}\n${t.install}`).join("\n");
  navigator.clipboard?.writeText(text);
  modal(`<h3>Install commands copied</h3><pre>${esc(text || "Nothing missing.")}</pre>
    <button class="btn" onclick="closeModal()">Close</button>`);
};

/* ── settings ───────────────────────────────────────────────────────────── */
const KEY_SOURCES = [
  ["subfinder", "subfinder providers", "Written to subfinder's provider config. Widens passive enumeration considerably."],
  ["chaos", "Chaos (PDCP_API_KEY)", "ProjectDiscovery's dataset built from public programme scopes."],
  ["github", "GitHub token", "Public code search for hostnames and leaked keys. Read-only, public scope."],
  ["shodan", "Shodan", "Host and favicon pivoting."],
  ["securitytrails", "SecurityTrails", "Historical DNS."],
  ["virustotal", "VirusTotal", "Passive DNS."],
  ["censys", "Censys", "Certificate and host search."],
];

function fillSettings(s) {
  $("sUa").value = s.user_agent || "";
  $("sRps").value = s.per_host_rps ?? 5;
  $("sGlobalRps").value = s.global_rps ?? 20;
  $("sSeverity").value = s.nuclei_severity || "";
  $("sDepth").value = s.crawl_depth ?? 3;
  $("sPorts").value = s.top_ports ?? 1000;
  $("sTimeout").value = s.stage_timeout ?? 3600;
  $("sIntrusive").checked = s.exclude_intrusive !== false;
  $("apiKeys").innerHTML = KEY_SOURCES.map(([key, label, hint]) => `
    <label>${esc(label)}<span style="display:block;color:var(--faint);font-weight:400;
      font-size:11.5px;margin-top:2px">${esc(hint)}</span></label>
    <input type="text" class="apikey" data-key="${key}" placeholder="not set">`).join("");
}

$("saveSettings").onclick = async () => {
  await api("/api/settings", { method: "POST", body: {
    user_agent: $("sUa").value, per_host_rps: Number($("sRps").value),
    global_rps: Number($("sGlobalRps").value),
    nuclei_severity: $("sSeverity").value, crawl_depth: Number($("sDepth").value),
    top_ports: Number($("sPorts").value), stage_timeout: Number($("sTimeout").value),
    exclude_intrusive: $("sIntrusive").checked,
  }});
  modal(`<h3>Saved</h3><p class="hint">Applied to the next run.</p>
    <button class="btn" onclick="closeModal()">Close</button>`);
};

$("saveKeys").onclick = async () => {
  const keys = {};
  document.querySelectorAll(".apikey").forEach(i => {
    if (i.value.trim()) keys[i.dataset.key] = i.value.trim();
  });
  await api("/api/settings", { method: "POST", body: { api_keys: keys } });
  document.querySelectorAll(".apikey").forEach(i => { i.value = ""; i.placeholder = "saved"; });
  modal(`<h3>Keys saved</h3><p class="hint">Stored in your local config file.
    They are never sent back to this page.</p>
    <button class="btn" onclick="closeModal()">Close</button>`);
};

/* ── update ─────────────────────────────────────────────────────────────── */
$("checkUpdate").onclick = async () => {
  $("updateOut").innerHTML = '<div class="hint">Checking…</div>';
  const u = await api("/api/update/check");
  $("applyUpdate").style.display = u.update_available ? "" : "none";
  $("updateOut").innerHTML = `
    <div class="kv">
      <span class="k">Installed</span><span class="v">${esc(u.current)}</span>
      <span class="k">Latest</span><span class="v">${esc(u.latest || "unknown")}</span>
    </div>
    ${u.message ? `<div class="note warn">${esc(u.message)}</div>` : ""}
    ${u.update_available ? `<div class="note"><b>An update is available.</b>
      ${u.changes ? `<pre>${esc(u.changes)}</pre>` : ""}</div>`
      : (u.latest && !u.message ? '<div class="note">You are on the latest version.</div>' : "")}`;
};

$("applyUpdate").onclick = async () => {
  $("updateOut").innerHTML = '<div class="hint">Updating…</div>';
  const r = await api("/api/update/apply", { method: "POST" });
  $("updateOut").innerHTML = `<div class="note ${r.ok ? "" : "danger"}">
    ${r.ok ? "<b>Updated.</b> Restart bbhunter to load the new version."
           : "<b>Update failed.</b>"}</div><pre>${esc(r.output)}</pre>`;
};

/* ── misc ───────────────────────────────────────────────────────────────── */
function updateBadges() {
  if (!S.program) return;
  const stats = S.program.stats || {};
  const f = stats.findings || {};
  $("findBadge").textContent = ((f.critical || 0) + (f.high || 0)) || "";
  $("assetBadge").textContent = stats.total_assets || "";
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

window.closeModal = closeModal;
boot().catch(e => {
  document.body.innerHTML =
    `<div style="padding:40px;font-family:system-ui"><h2>bbhunter failed to start</h2>
     <pre>${esc(e.message)}</pre></div>`;
});
