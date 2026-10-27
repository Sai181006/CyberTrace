const $ = (selector) => document.querySelector(selector);
const entityTypes = ["ThreatActor", "Malware", "Technique", "Vulnerability", "IP", "Domain", "Organization"];
let csrfToken = "";
let entityMetadata = {};
let relationshipPatterns = [];
let currentRole = "";
let currentUsername = "";

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (!["GET", "HEAD"].includes(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const body = await response.json().catch(() => ({ error: "Invalid server response" }));
  if (response.status === 401 && path !== "/api/auth/login") showLogin();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}
function toast(message, error = false) { const box = $("#toast"); box.textContent = message; box.classList.toggle("error", error); box.classList.add("show"); setTimeout(() => box.classList.remove("show"), 2600); }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"})[char]); }
function title(properties) { return properties.name || properties.address || properties.cve_id || properties.source_id || "Entity"; }
function sourceLink(properties) {
  const url = String(properties.source_url || "");
  if (/^https:\/\/attack\.mitre\.org\//.test(url)) return ` · <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">MITRE source</a>`;
  if (/^https:\/\/(www\.)?cisa\.gov\//.test(url)) return ` · <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">CISA source</a>`;
  return "";
}

function showLogin() {
  csrfToken = "";
  currentRole = "";
  currentUsername = "";
  $("#login-screen").hidden = false;
  $(".tabs").hidden = true;
  $("main").hidden = true;
  $("#logout").hidden = true;
  $("#admin-users").replaceChildren();
  $("#admin-source-runs").replaceChildren();
  activateTab($("#tab-dashboard"));
}
function showApp(token, role, username) {
  csrfToken = token;
  currentRole = role || "viewer";
  currentUsername = username || "";
  $("#login-screen").hidden = true;
  $(".tabs").hidden = false;
  $("main").hidden = false;
  $("#logout").hidden = false;
  $("#tab-admin").hidden = currentRole !== "admin";
  $("#tab-manage").hidden = currentRole === "viewer";
  $("#investigation-save").hidden = currentRole === "viewer";
  activateTab($("#tab-dashboard"));
  loadDashboard();
  loadMetadata();
  loadSharedReports();
  if (currentRole === "admin") { loadUsers(); loadSourceRuns(); }
}
$("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    const data = await api("/api/auth/login", {method:"POST", body:JSON.stringify({username:$("#login-username").value.trim(), password:$("#login-password").value})});
    $("#login-password").value = "";
    showApp(data.csrf_token, data.role, data.username);
  } catch (error) { $("#login-error").textContent = error.message; }
});
$("#logout").addEventListener("click", async () => {
  try { await api("/api/auth/logout", {method:"POST"}); showLogin(); $("#login-password").focus(); }
  catch (error) { toast(error.message, true); }
});

function activateTab(button) {
  if (button.hidden) return;
  document.querySelectorAll(".tab,.panel").forEach(item => item.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(tab => tab.setAttribute("aria-selected", tab === button ? "true" : "false"));
  button.classList.add("active"); document.getElementById(button.dataset.panel).classList.add("active");
  const demoInput = {search:"#search-term",explorer:"#graph-id",investigate:"#actor-name",analytics:"#path-from-id"}[button.dataset.panel];
  if (demoInput) $(demoInput).focus();
}
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => activateTab(button)));
$(".tabs").addEventListener("keydown", event => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = [...document.querySelectorAll(".tab")].filter(tab => !tab.hidden);
  const index = tabs.indexOf(document.activeElement);
  if (index < 0) return;
  event.preventDefault();
  const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
  tabs[next].focus(); activateTab(tabs[next]);
});

entityTypes.forEach(type => {
  $("#search-type").insertAdjacentHTML("beforeend", `<option>${type}</option>`);
  $("#graph-type").insertAdjacentHTML("beforeend", `<option>${type}</option>`);
  $("#path-from-type").insertAdjacentHTML("beforeend", `<option>${type}</option>`);
  $("#path-to-type").insertAdjacentHTML("beforeend", `<option>${type}</option>`);
});
$("#search-type").value = "ThreatActor";
$("#graph-type").value = "ThreatActor";
$("#path-from-type").value = "ThreatActor";
$("#path-to-type").value = "Domain";

async function loadHealth() { try { await api("/api/health"); $("#connection").classList.add("online"); $("#connection").lastChild.textContent = " Neo4j connected"; } catch { $("#connection").lastChild.textContent = " Neo4j unavailable"; } }
async function loadDashboard() {
  try { const data = await api("/api/dashboard"); const values = {"Total Nodes":data.nodes,"Relationships":data.relationships,...data.labels}; $("#stats").innerHTML = Object.entries(values).map(([label,value]) => `<div class="stat"><strong>${value}</strong><span>${escapeHtml(label)}</span></div>`).join(""); $("#provenance").innerHTML = `<div class="stat-grid"><div class="stat"><strong>${data.provenance.real || 0}</strong><span>Sourced nodes</span></div><div class="stat"><strong>${data.provenance.synthetic || 0}</strong><span>Synthetic demo nodes</span></div></div>`; } catch (error) { toast(error.message, true); }
}
$("#refresh-dashboard").addEventListener("click", loadDashboard);

$("#search-form").addEventListener("submit", async event => {
  event.preventDefault();
  const query = new URLSearchParams({q:$("#search-term").value});
  if ($("#search-type").value) query.set("type", $("#search-type").value);
  const output = $("#search-results"); output.textContent = "Searching…";
  try {
    const {results} = await api(`/api/entities/search?${query}`);
    output.innerHTML = results.length ? results.map(row => {
      const idKey = entityMetadata[row.type]?.identifier;
      const stableId = idKey ? row.entity[idKey] : row.entity.source_id;
      const description = String(row.entity.description || "No description");
      const excerpt = description.length > 320 ? `${description.slice(0,320)}…` : description;
      return `<article class="result"><header><strong>${escapeHtml(title(row.entity))}</strong><span class="badge">${escapeHtml(row.type)}</span></header><p class="meta">ID: ${escapeHtml(stableId)} · Source: ${escapeHtml(row.entity.source)} · Synthetic: ${row.entity.is_synthetic ? "Yes" : "No"}${sourceLink(row.entity)}</p><p class="meta">${escapeHtml(excerpt)}</p><details><summary>Full details and provenance</summary><pre class="output">${escapeHtml(JSON.stringify(row.entity,null,2))}</pre></details><button type="button" class="secondary claim-history" data-type="${escapeHtml(row.type)}" data-id="${escapeHtml(stableId)}">Source history</button><pre class="output claim-output" hidden></pre></article>`;
    }).join("") : '<p class="meta">No matching entities.</p>';
  } catch(error) { output.textContent = error.message; toast(error.message, true); }
});
$("#search-results").addEventListener("click", async event => {
  const button = event.target.closest(".claim-history"); if (!button) return;
  const output = button.nextElementSibling; output.hidden = false; output.textContent = "Loading source history…";
  try {
    const data = await api(`/api/claims/nodes/${encodeURIComponent(button.dataset.type)}/${encodeURIComponent(button.dataset.id)}`);
    output.textContent = data.claims.length ? JSON.stringify(data.claims, null, 2) : "No archived source claim yet. The current record's provenance is shown above.";
  } catch(error) { output.textContent = error.message; }
});

function svgElement(name, attributes = {}) { const element = document.createElementNS("http://www.w3.org/2000/svg", name); Object.entries(attributes).forEach(([key,value]) => element.setAttribute(key,value)); return element; }
let graphOffset = 0;
let graphZoom = 1;
let graphView = "2d";
const graph3d = window.createCyberTraceGraph3D(
  $("#graph-3d"),
  neighbor => exploreNeighbor(neighbor),
  data => { $("#graph-details").textContent = JSON.stringify(data.center, null, 2); },
);
if (!graph3d) $("#graph-view-3d").disabled = true;
function graphPageSize() { return Number($("#graph-page-size").value); }
function applyGraphZoom() {
  const narrow = window.matchMedia("(max-width:720px)").matches;
  const width = narrow ? 400 : 900, height = narrow ? 500 : 520;
  const viewedWidth = width / graphZoom, viewedHeight = height / graphZoom;
  $("#graph").setAttribute("viewBox", `${(width - viewedWidth) / 2} ${(height - viewedHeight) / 2} ${viewedWidth} ${viewedHeight}`);
}
function exploreNeighbor(neighbor) {
  const idKey = entityMetadata[neighbor.type]?.identifier;
  if (!idKey || !neighbor.properties[idKey]) { toast("Stable ID unavailable for this entity.", true); return; }
  $("#graph-type").value = neighbor.type;
  $("#graph-id").value = neighbor.properties[idKey];
  graphOffset = 0;
  loadGraph();
}
function renderGraph(data) {
  const svg = $("#graph"); svg.replaceChildren();
  const list = $("#graph-connections"); list.replaceChildren();
  const narrow = window.matchMedia("(max-width:720px)").matches;
  applyGraphZoom();
  const cx = narrow ? 200 : 450, cy = 250;
  data.neighbors.forEach((neighbor, index) => {
    const relation = data.relationships[index];
    const outer = data.neighbors.length > 20 && index >= 12;
    const ringIndex = outer ? index - 12 : index;
    const ringCount = outer ? data.neighbors.length - 12 : Math.min(data.neighbors.length, 12);
    const radius = outer ? (narrow ? 165 : 225) : (narrow ? 92 : 145);
    const angle = Math.PI * 2 * ringIndex / Math.max(ringCount, 1) - Math.PI / 2;
    const x = cx + Math.cos(angle) * radius, y = cy + Math.sin(angle) * radius;
    svg.append(svgElement("line", {x1:cx,y1:cy,x2:x,y2:y,class:"edge"}));
    const edgeLabel = svgElement("text", {x:(cx+x)/2,y:(cy+y)/2,class:"edge-label"});
    edgeLabel.textContent = relation.type; svg.append(edgeLabel);
    const circle = svgElement("circle", {cx:x,cy:y,r:data.neighbors.length > 20 ? 14 : (narrow ? 25 : 29),class:"node neighbor"});
    circle.addEventListener("click", () => exploreNeighbor(neighbor)); svg.append(circle);
    if (data.neighbors.length <= 20) {
      const label = svgElement("text", {x,y:y+43,class:"node-label"});
      label.textContent = title(neighbor.properties).slice(0,narrow ? 13 : 18); svg.append(label);
    }
    const li = document.createElement("li");
    const details = document.createElement("button"); details.type = "button"; details.className = "secondary";
    details.textContent = `${neighbor.type}: ${title(neighbor.properties)} (${neighbor.properties.is_synthetic ? "Synthetic" : "Real"}) — ${relation.type} link (${relation.properties.is_synthetic ? "Synthetic" : "Real"})`;
    details.addEventListener("click", () => $("#graph-details").textContent = JSON.stringify({entity:neighbor.properties,relationship:relation.properties},null,2));
    const expand = document.createElement("button"); expand.type = "button"; expand.className = "secondary";
    expand.textContent = "Explore from here"; expand.addEventListener("click", () => exploreNeighbor(neighbor));
    li.append(details, expand); list.append(li);
  });
  const center = svgElement("circle", {cx,cy,r:narrow ? 38 : 46,class:"node center"});
  center.addEventListener("click", () => $("#graph-details").textContent = JSON.stringify(data.center,null,2)); svg.append(center);
  const centerLabel = svgElement("text", {x:cx,y:cy+65,class:"node-label"});
  centerLabel.textContent = title(data.center).slice(0,narrow ? 18 : 28); svg.append(centerLabel);
  $("#graph-details").textContent = `${data.center_type}: ${title(data.center)} · ${data.total} matching connections. Select a connection for provenance or explore from it.`;
  $("#graph-page").textContent = data.total ? `Showing ${data.offset + 1}–${data.offset + data.neighbors.length} of ${data.total}` : "No connections match these filters.";
  $("#graph-prev").disabled = data.offset === 0;
  $("#graph-next").disabled = data.offset + data.neighbors.length >= data.total;
  graph3d?.render(data);
}
async function loadGraph() {
  const type = $("#graph-type").value, id = $("#graph-id").value.trim();
  if (!id) return;
  const query = new URLSearchParams({limit:String(graphPageSize()),offset:String(graphOffset),provenance:$("#graph-provenance").value});
  if ($("#graph-relationship").value) query.set("relationship_type", $("#graph-relationship").value);
  if ($("#graph-neighbor-type").value) query.set("neighbor_type", $("#graph-neighbor-type").value);
  if ($("#graph-search").value.trim()) query.set("search", $("#graph-search").value.trim());
  if ($("#graph-confidence").value !== "") query.set("min_confidence", $("#graph-confidence").value);
  if ($("#graph-date").value) query.set("evidence_after", $("#graph-date").value);
  try { renderGraph(await api(`/api/graph/entity/${encodeURIComponent(type)}/${encodeURIComponent(id)}?${query}`)); }
  catch (error) { $("#graph-details").textContent = error.message; toast(error.message, true); }
}
$("#graph-form").addEventListener("submit", event => { event.preventDefault(); graphOffset = 0; loadGraph(); });
$(".graph-controls").addEventListener("keydown", event => {
  if (event.key !== "Enter") return;
  event.preventDefault(); graphOffset = 0; loadGraph();
});
$("#graph-relationship").addEventListener("change", () => { graphOffset = 0; loadGraph(); });
$("#graph-provenance").addEventListener("change", () => { graphOffset = 0; loadGraph(); });
$("#graph-apply").addEventListener("click", () => { graphOffset = 0; loadGraph(); });
$("#graph-page-size").addEventListener("change", () => { graphOffset = 0; loadGraph(); });
$("#graph-prev").addEventListener("click", () => { graphOffset = Math.max(0, graphOffset - graphPageSize()); loadGraph(); });
$("#graph-next").addEventListener("click", () => { graphOffset += graphPageSize(); loadGraph(); });
function setGraphView(view) {
  if (view === "3d" && !graph3d) return;
  graphView = view;
  $("#graph").toggleAttribute("hidden", view === "3d");
  $("#graph-3d").hidden = view !== "3d";
  $("#graph-3d-hint").hidden = view !== "3d";
  for (const option of ["2d", "3d"]) {
    const button = $(`#graph-view-${option}`);
    button.classList.toggle("active", option === view);
    button.setAttribute("aria-pressed", String(option === view));
  }
  if (view === "3d") graph3d.show();
  else applyGraphZoom();
}
$("#graph-view-2d").addEventListener("click", () => setGraphView("2d"));
$("#graph-view-3d").addEventListener("click", () => setGraphView("3d"));
$("#graph-zoom-in").addEventListener("click", () => {
  if (graphView === "3d") graph3d.zoomIn();
  else { graphZoom = Math.min(3, graphZoom * 1.25); applyGraphZoom(); }
});
$("#graph-zoom-out").addEventListener("click", () => {
  if (graphView === "3d") graph3d.zoomOut();
  else { graphZoom = Math.max(.65, graphZoom / 1.25); applyGraphZoom(); }
});
$("#graph-zoom-reset").addEventListener("click", () => {
  if (graphView === "3d") graph3d.reset();
  else { graphZoom = 1; applyGraphZoom(); }
});

async function loadMetadata() {
  try {
    const data = await api("/api/entity-types");
    entityMetadata = data.metadata;
    relationshipPatterns = data.relationship_patterns;
    const relationTypes = [...new Set(relationshipPatterns.map(pattern => pattern.type))].sort();
    $("#graph-relationship").innerHTML = '<option value="">All types</option>' + relationTypes.map(type => `<option>${escapeHtml(type)}</option>`).join("");
    $("#graph-neighbor-type").innerHTML = '<option value="">All types</option>' + data.types.map(type => `<option>${escapeHtml(type)}</option>`).join("");
    $("#entity-type").innerHTML = data.types.map(type => `<option>${escapeHtml(type)}</option>`).join("");
    $("#entity-type").value = "Malware";
    updateEntityHelp();
    $("#relationship-pattern").innerHTML = relationshipPatterns.map((pattern, index) => `<option value="${index}">${escapeHtml(pattern.from_type)} → ${escapeHtml(pattern.type)} → ${escapeHtml(pattern.to_type)}</option>`).join("");
    const demoPattern = relationshipPatterns.findIndex(pattern => pattern.from_type === "IP" && pattern.type === "RESOLVES_TO" && pattern.to_type === "Domain");
    if (demoPattern >= 0) $("#relationship-pattern").value = String(demoPattern);
    $("#relationship-output").textContent = `${relationshipPatterns.length} allowed relationship patterns available.`;
  } catch (error) { toast(error.message, true); }
}
function updateEntityHelp() {
  const spec = entityMetadata[$("#entity-type").value];
  if (!spec) return;
  $("#entity-id-label").textContent = `Stable ID (${spec.identifier})`;
  $("#entity-fields-help").textContent = `Allowed JSON fields: ${spec.mutable.join(", ")}. The stable ID is entered separately; source and synthetic status are assigned automatically.`;
}
$("#entity-type").addEventListener("change", updateEntityHelp);
function entityProperties() {
  let properties;
  try { properties = JSON.parse($("#entity-properties").value); }
  catch { throw new Error("Properties must be valid JSON."); }
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) throw new Error("Properties must be a JSON object.");
  const allowed = entityMetadata[$("#entity-type").value]?.mutable || [];
  const invalid = Object.keys(properties).filter(key => !allowed.includes(key));
  if (invalid.length) throw new Error(`Unsupported properties: ${invalid.join(", ")}`);
  return properties;
}
document.querySelectorAll("[data-entity-action]").forEach(button => button.addEventListener("click", async () => {
  const action = button.dataset.entityAction;
  const type = $("#entity-type").value;
  const id = $("#entity-id").value.trim();
  const output = $("#entity-output");
  if (!id) { output.textContent = "Enter a stable ID."; return; }
  const endpoint = `/api/entities/${encodeURIComponent(type)}/${encodeURIComponent(id)}`;
  try {
    let result;
    if (action === "read") {
      result = await api(endpoint);
      const editable = Object.fromEntries(Object.entries(result.entity).filter(([key]) => entityMetadata[type].mutable.includes(key)));
      $("#entity-properties").value = JSON.stringify(editable, null, 2);
    } else if (action === "create") {
      result = await api("/api/entities", {method:"POST", body:JSON.stringify({type, properties:{...entityProperties(), [entityMetadata[type].identifier]:id}})});
    } else {
      const current = (await api(endpoint)).entity;
      output.textContent = JSON.stringify({before_change:current}, null, 2);
      if (!current.is_synthetic) throw new Error("Real imported entities are read-only.");
      if (!window.confirm(`${action === "delete" ? "Delete" : "Update"} ${type} ${id}?\nSource: ${current.source}\nSynthetic: Yes`)) return;
      result = action === "update"
        ? await api(endpoint, {method:"PUT", body:JSON.stringify(entityProperties())})
        : await api(endpoint, {method:"DELETE"});
    }
    output.textContent = JSON.stringify(result, null, 2);
    toast(`${action} completed`);
    if (action !== "read") loadDashboard();
  } catch (error) { output.textContent = error.message; toast(error.message, true); }
}));

$("#relationship-create").addEventListener("click", async () => {
  const pattern = relationshipPatterns[Number($("#relationship-pattern").value)];
  const from_id = $("#relationship-from-id").value.trim();
  const to_id = $("#relationship-to-id").value.trim();
  const output = $("#relationship-output");
  if (!pattern || !from_id || !to_id) { output.textContent = "Choose a pattern and enter both endpoint IDs."; return; }
  try {
    const evidence = {};
    for (const [field, id] of [["first_seen","relationship-first-seen"],["last_seen","relationship-last-seen"]]) {
      if (document.getElementById(id).value) evidence[field] = new Date(document.getElementById(id).value).toISOString();
    }
    if ($("#relationship-confidence").value !== "") evidence.confidence = Number($("#relationship-confidence").value);
    if ($("#relationship-confidence-basis").value.trim()) evidence.confidence_basis = $("#relationship-confidence-basis").value.trim();
    if ($("#relationship-evidence-url").value.trim()) evidence.evidence_url = $("#relationship-evidence-url").value.trim();
    const result = await api("/api/relationships", {method:"POST", body:JSON.stringify({...pattern, from_id, to_id, ...evidence})});
    $("#relationship-id").value = result.relationship.relationship_id;
    output.textContent = JSON.stringify(result, null, 2);
    toast("Relationship created"); loadDashboard();
  } catch (error) { output.textContent = error.message; toast(error.message, true); }
});
$("#relationship-read").addEventListener("click", async () => {
  const id = $("#relationship-id").value.trim();
  if (!id) { $("#relationship-output").textContent = "Enter a relationship ID."; return; }
  try { $("#relationship-output").textContent = JSON.stringify(await api(`/api/relationships/${encodeURIComponent(id)}`), null, 2); }
  catch (error) { $("#relationship-output").textContent = error.message; toast(error.message, true); }
});
$("#relationship-delete").addEventListener("click", async () => {
  const id = $("#relationship-id").value.trim();
  const output = $("#relationship-output");
  if (!id) { output.textContent = "Enter a relationship ID."; return; }
  const endpoint = `/api/relationships/${encodeURIComponent(id)}`;
  try {
    const current = (await api(endpoint)).relationship;
    output.textContent = JSON.stringify({before_change:current}, null, 2);
    if (!current.properties.is_synthetic) throw new Error("Real imported relationships are read-only.");
    if (!window.confirm(`Delete ${current.type} relationship ${id}?\nSource: ${current.properties.source}\nSynthetic: Yes`)) return;
    output.textContent = JSON.stringify(await api(endpoint, {method:"DELETE"}), null, 2);
    toast("Relationship deleted"); loadDashboard();
  } catch (error) { output.textContent = error.message; toast(error.message, true); }
});

let currentPaths = [];
let sharedReports = [];
function exportInvestigation(report) {
  const steps = [
    ["Actor",report.path.actor],["USES relationship",report.path.uses],["Malware",report.path.malware],
    ["COMMUNICATES_WITH relationship",report.path.communication],["IP",report.path.ip],
    ["RESOLVES_TO relationship",report.path.resolution],["Domain",report.path.domain]
  ];
  const rows = steps.map(([label,properties]) => `<section><h2>${escapeHtml(label)}: ${escapeHtml(title(properties))}</h2><p><strong>Source:</strong> ${escapeHtml(properties.source || "Unknown")} · <strong>Synthetic:</strong> ${properties.is_synthetic ? "Yes" : "No"}${sourceLink(properties)}</p><pre>${escapeHtml(JSON.stringify(properties,null,2))}</pre></section>`).join("");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CyberTrace investigation report</title><style>body{font:16px/1.5 system-ui;max-width:850px;margin:2rem auto;padding:0 1rem;color:#15212a}section{border-top:1px solid #aaa;padding:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f6;padding:1rem}small{color:#52636d}</style></head><body><h1>CyberTrace investigation</h1><p><strong>Actor:</strong> ${escapeHtml(report.actor)} · <strong>Saved:</strong> ${escapeHtml(report.saved_at)}</p><p><strong>Note:</strong> ${escapeHtml(report.note || "None")}</p><p><strong>Interpretation:</strong> This is a graph snapshot. Each step has its own provenance. Synthetic relationships are demonstration scenarios, not confirmed incidents.</p>${rows}<small>Exported from CyberTrace. Verify current source data before using this report.</small></body></html>`;
  const url = URL.createObjectURL(new Blob([html], {type:"text/html"}));
  const link = document.createElement("a"); link.href = url; link.download = `cybertrace-investigation-${report.id}.html`;
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function renderSavedInvestigations() {
  const box = $("#saved-investigations"); box.replaceChildren();
  let legacy = [];
  try { legacy = JSON.parse(localStorage.getItem("cybertrace-investigations-v1") || "[]"); if (!Array.isArray(legacy)) legacy = []; }
  catch { legacy = []; }
  if (!sharedReports.length && !legacy.length) { box.textContent = "No shared reports yet."; return; }
  sharedReports.forEach(report => {
    const article = document.createElement("article"); article.className = "result";
    const heading = document.createElement("strong"); heading.textContent = `${report.title} · ${report.owner} · ${new Date(report.created_at).toLocaleString()}`;
    const note = document.createElement("p"); note.className = "meta"; note.textContent = report.note || "No note";
    const actions = document.createElement("div"); actions.className = "actions";
    const exportButton = document.createElement("button"); exportButton.type = "button"; exportButton.className = "secondary"; exportButton.textContent = "Export HTML report";
    exportButton.addEventListener("click", async () => {
      try {
        const {report:full} = await api(`/api/reports/${encodeURIComponent(report.id)}`);
        exportInvestigation({id:full.id,saved_at:full.created_at,actor:full.title,note:full.note,path:full.snapshot});
      } catch(error) { toast(error.message, true); }
    });
    actions.append(exportButton);
    if (report.owner === currentUsername || currentRole === "admin") {
      const removeButton = document.createElement("button"); removeButton.type = "button"; removeButton.className = "danger"; removeButton.textContent = "Remove";
      removeButton.addEventListener("click", async () => {
        if (!window.confirm(`Remove shared report ${report.title}?`)) return;
        try { await api(`/api/reports/${encodeURIComponent(report.id)}`, {method:"DELETE"}); await loadSharedReports(); }
        catch(error) { toast(error.message, true); }
      });
      actions.append(removeButton);
    }
    article.append(heading,note,actions); box.append(article);
  });
  legacy.forEach(report => {
    const article = document.createElement("article"); article.className = "result";
    const heading = document.createElement("strong"); heading.textContent = `${report.actor || "Investigation"} · legacy browser-only snapshot`;
    const note = document.createElement("p"); note.className = "meta"; note.textContent = "Saved before shared reports were added. This snapshot was not server-verified; export it for your records.";
    const exportButton = document.createElement("button"); exportButton.type = "button"; exportButton.className = "secondary"; exportButton.textContent = "Export local HTML";
    exportButton.addEventListener("click", () => exportInvestigation(report));
    article.append(heading,note,exportButton); box.append(article);
  });
}
async function loadSharedReports() {
  try { sharedReports = (await api("/api/reports")).reports; renderSavedInvestigations(); }
  catch(error) { $("#saved-investigations").textContent = error.message; }
}
function selectedPath() { return currentPaths[Number($("#investigation-choice").value)]; }
$("#investigation-save").addEventListener("click", async () => {
  const path = selectedPath(); if (!path) return;
  try {
    await api("/api/reports", {method:"POST", body:JSON.stringify({title:`${title(path.actor)} investigation`,note:$("#investigation-note").value.trim().slice(0,5000),snapshot_token:path._save_token})});
    await loadSharedReports(); toast("Investigation shared with teammates");
  } catch(error) { toast(error.message, true); }
});
$("#investigation-export").addEventListener("click", () => {
  const path = selectedPath(); if (!path) return;
  exportInvestigation({id:String(Date.now()),saved_at:new Date().toISOString(),actor:title(path.actor),note:$("#investigation-note").value.trim().slice(0,2000),path});
});
renderSavedInvestigations();
$("#investigation-form").addEventListener("submit", async event => {
  event.preventDefault();
  const query = new URLSearchParams({value:$("#actor-name").value,limit:"30"});
  try {
    const {results} = await api(`/api/investigations/actor-investigation?${query}`);
    currentPaths = results;
    $("#investigation-choice").disabled = !results.length;
    $("#investigation-save").disabled = !results.length;
    $("#investigation-export").disabled = !results.length;
    $("#investigation-choice").innerHTML = results.length ? results.map((row,index) => `<option value="${index}">${index + 1}. ${escapeHtml(title(row.malware))} → ${escapeHtml(title(row.domain))}</option>`).join("") : "<option>No complete path found</option>";
    const demoPath = results.findIndex(row => title(row.malware) === "Mimikatz" && title(row.domain) === "c2-demo-01.example.com");
    if (demoPath >= 0) $("#investigation-choice").value = String(demoPath);
    $("#investigation-results").innerHTML = results.length ? results.map(row => {
      const steps = [
        ["Actor", row.actor], ["USES link", row.uses],
        ["Malware", row.malware], ["COMMUNICATES_WITH link", row.communication],
        ["IP", row.ip], ["RESOLVES_TO link", row.resolution],
        ["Domain", row.domain]
      ];
      const details = steps.map(([label, properties]) => {
        const name = label.endsWith("link") ? label : `${label}: ${title(properties)}`;
        const source = properties.is_synthetic ? "Synthetic" : (properties.source || "Real source");
        return `<li>${escapeHtml(name)} · ${escapeHtml(source)}${sourceLink(properties)}<details><summary>Full provenance</summary><pre class="output">${escapeHtml(JSON.stringify(properties, null, 2))}</pre></details></li>`;
      }).join("");
      return `<article class="result"><header><strong>${escapeHtml(title(row.actor))}</strong><span class="badge">3 relationship path</span></header><ol>${details}</ol></article>`;
    }).join("") : '<p class="meta">No complete investigation path for that actor.</p>';
  } catch (error) { currentPaths = []; $("#investigation-save").disabled = true; $("#investigation-export").disabled = true; toast(error.message, true); }
});

$("#path-form").addEventListener("submit", async event => {
  event.preventDefault();
  const query = new URLSearchParams({from_type:$("#path-from-type").value,from_id:$("#path-from-id").value.trim(),to_type:$("#path-to-type").value,to_id:$("#path-to-id").value.trim(),max_hops:$("#path-hops").value});
  const output = $("#path-results"); output.textContent = "Finding path…";
  try {
    const data = await api(`/api/analytics/path?${query}`);
    if (!data.found) { output.textContent = "Both entities exist, but no path was found within the selected hop limit."; return; }
    output.innerHTML = `<p class="meta">Shortest path: ${data.hops} relationship${data.hops === 1 ? "" : "s"}</p>` +
      data.nodes.map((node, index) => {
        const edge = data.relationships[index];
        const provenance = node.properties.is_synthetic ? "Synthetic" : escapeHtml(node.properties.source || "Real source");
        return `<article class="result"><strong>${index + 1}. ${escapeHtml(title(node.properties))}</strong> <span class="badge">${escapeHtml(node.type)}</span><p class="meta">${provenance}${edge ? ` · Next relationship: ${escapeHtml(edge.type)} (${edge.properties.is_synthetic ? "synthetic" : "real"})` : ""}</p></article>`;
      }).join("");
  } catch (error) { output.textContent = error.message; toast(error.message, true); }
});

$("#pagerank-form").addEventListener("submit", async event => {
  event.preventDefault();
  const output = $("#pagerank-results"); output.textContent = "Calculating PageRank…";
  try {
    const query = new URLSearchParams({scope:$("#pagerank-scope").value,limit:"10"});
    const data = await api(`/api/analytics/pagerank?${query}`);
    output.innerHTML = `<p class="meta">${data.node_count} nodes · ${data.relationship_count} directed relationships · ${data.iterations} iterations${data.converged ? "" : " (iteration limit reached)"}</p>` +
      (data.results.length ? data.results.map((row, index) => `<article class="result"><header><strong>${index + 1}. ${escapeHtml(title(row.entity))}</strong><span class="badge">${escapeHtml(row.type)}</span></header><p class="meta">PageRank ${row.score.toFixed(6)} · ${row.entity.is_synthetic ? "Synthetic" : escapeHtml(row.entity.source || "Real source")}</p></article>`).join("") : '<p class="meta">No entities in this scope.</p>');
  } catch (error) { output.textContent = error.message; toast(error.message, true); }
});

$("#degree-form").addEventListener("submit", async event => {
  event.preventDefault();
  const output = $("#degree-results"); output.textContent = "Counting connections…";
  try {
    const query = new URLSearchParams({scope:$("#degree-scope").value,limit:"10"});
    const data = await api(`/api/analytics/degree?${query}`);
    output.innerHTML = `<p class="meta">${data.node_count} nodes · ${data.relationship_count} relationships in scope. Degree is an undirected connection count.</p>` +
      (data.results.length ? data.results.map((row,index) => `<article class="result"><header><strong>${index + 1}. ${escapeHtml(title(row.entity))}</strong><span class="badge">${escapeHtml(row.type)}</span></header><p class="meta">${row.degree} connections · ${row.entity.is_synthetic ? "Synthetic" : escapeHtml(row.entity.source || "Real source")}</p></article>`).join("") : '<p class="meta">No entities in this scope.</p>');
  } catch (error) { output.textContent = error.message; toast(error.message, true); }
});

let evaluationTasks = [];
let evaluationIndex = -1;
let evaluationStarted = 0;
$("#evaluation-start").addEventListener("click", async () => {
  try {
    const mode = $("#evaluation-mode").value;
    if (!evaluationTasks.length || evaluationIndex >= evaluationTasks.length - 1) {
      evaluationTasks = (await api(`/api/evaluation/tasks?mode=${encodeURIComponent(mode)}`)).tasks;
      evaluationIndex = -1;
    }
    evaluationIndex += 1;
    const task = evaluationTasks[evaluationIndex];
    if (!task) return;
    $("#evaluation-task").replaceChildren();
    const question = document.createElement("p"); question.textContent = `${evaluationIndex + 1} of ${evaluationTasks.length}: ${task.question}`;
    $("#evaluation-task").append(question);
    if (task.reference_context) {
      const reference = document.createElement("p"); reference.className = "notice"; reference.textContent = task.reference_context;
      $("#evaluation-task").append(reference);
    }
    $("#evaluation-feedback").textContent = "";
    $("#evaluation-answer").value = "";
    $("#evaluation-form").hidden = false;
    $("#evaluation-start").textContent = "Next task";
    evaluationStarted = performance.now();
  } catch(error) { toast(error.message, true); }
});
$("#evaluation-mode").addEventListener("change", () => { evaluationTasks = []; evaluationIndex = -1; $("#evaluation-form").hidden = true; $("#evaluation-start").textContent = "Start task"; });
$("#evaluation-form").addEventListener("submit", async event => {
  event.preventDefault();
  const task = evaluationTasks[evaluationIndex]; if (!task) return;
  try {
    const duration_seconds = Math.min(3600, (performance.now() - evaluationStarted) / 1000);
    const data = await api("/api/evaluation/responses", {method:"POST", body:JSON.stringify({task_id:task.id,mode:$("#evaluation-mode").value,answer:$("#evaluation-answer").value,duration_seconds})});
    $("#evaluation-feedback").textContent = `${data.result.correct ? "Correct" : "Not correct"}. ${data.explanation} Time: ${duration_seconds.toFixed(1)} seconds.`;
    $("#evaluation-form").hidden = true;
    loadEvaluationSummary();
  } catch(error) { toast(error.message, true); }
});
async function loadEvaluationSummary() {
  try {
    const data = await api("/api/evaluation/summary");
    $("#evaluation-summary").textContent = data.summary.length ? data.summary.map(row => `${row.mode}: ${row.responses} responses · ${Math.round(row.accuracy * 100)}% correct · ${row.avg_seconds}s average`).join(" | ") : "No study responses yet.";
  } catch(error) { $("#evaluation-summary").textContent = error.message; }
}
$("#evaluation-summary-button").addEventListener("click", loadEvaluationSummary);

async function loadUsers() {
  try {
    const users = (await api("/api/admin/users")).users;
    const box = $("#admin-users"); box.replaceChildren();
    users.forEach(user => {
      const row = document.createElement("article"); row.className = "result admin-user";
      const name = document.createElement("strong"); name.textContent = `${user.username} · ${user.disabled ? "disabled" : "active"}`;
      const role = document.createElement("select");
      ["viewer", "analyst", "admin"].forEach(value => { const option = document.createElement("option"); option.value = value; option.textContent = value; role.append(option); });
      role.value = user.role;
      const save = document.createElement("button"); save.type = "button"; save.className = "secondary"; save.textContent = "Set role";
      save.addEventListener("click", async () => {
        try { await api(`/api/admin/users/${encodeURIComponent(user.username)}`, {method:"PATCH",body:JSON.stringify({role:role.value})}); loadUsers(); }
        catch(error) { toast(error.message, true); }
      });
      const toggle = document.createElement("button"); toggle.type = "button"; toggle.className = "secondary"; toggle.textContent = user.disabled ? "Enable" : "Disable";
      toggle.addEventListener("click", async () => {
        try { await api(`/api/admin/users/${encodeURIComponent(user.username)}`, {method:"PATCH",body:JSON.stringify({disabled:!user.disabled})}); loadUsers(); }
        catch(error) { toast(error.message, true); }
      });
      role.disabled = user.protected; save.disabled = user.protected; toggle.disabled = user.protected;
      row.append(name, role, save, toggle); box.append(row);
    });
  } catch(error) { $("#admin-users").textContent = error.message; }
}
$("#admin-user-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await api("/api/admin/users", {method:"POST",body:JSON.stringify({username:$("#admin-username").value.trim(),password:$("#admin-password").value,role:$("#admin-role").value})});
    $("#admin-password").value = ""; toast("User created"); loadUsers();
  } catch(error) { toast(error.message, true); }
});
async function loadSourceRuns() {
  try {
    const runs = (await api("/api/admin/source-runs")).runs;
    $("#admin-source-runs").innerHTML = runs.length ? runs.map(run => `<article class="result"><strong>${escapeHtml(run.source)} · ${escapeHtml(run.status)}</strong><p class="meta">Version ${escapeHtml(run.version)} · ${escapeHtml(run.completed_at)} · ${run.nodes} nodes · ${run.relationships} links</p><p class="meta">${escapeHtml(run.message)}</p></article>`).join("") : "No source sync runs yet.";
  } catch(error) { $("#admin-source-runs").textContent = error.message; }
}
$("#admin-refresh-sources").addEventListener("click", loadSourceRuns);

async function initialize() {
  loadHealth();
  try {
    const state = await api("/api/auth/session");
    if (state.authenticated) showApp(state.csrf_token, state.role, state.username);
    else showLogin();
  } catch (error) { showLogin(); $("#login-error").textContent = error.message; }
}
initialize();
