const $ = (selector) => document.querySelector(selector);
const entityTypes = ["ThreatActor", "Malware", "Technique", "Vulnerability", "IP", "Domain", "Organization"];
let csrfToken = "";
let entityMetadata = {};
let relationshipPatterns = [];

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

function showLogin() {
  csrfToken = "";
  $("#login-screen").hidden = false;
  $(".tabs").hidden = true;
  $("main").hidden = true;
  $("#logout").hidden = true;
}
function showApp(token) {
  csrfToken = token;
  $("#login-screen").hidden = true;
  $(".tabs").hidden = false;
  $("main").hidden = false;
  $("#logout").hidden = false;
  loadDashboard();
  loadMetadata();
}
$("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    const data = await api("/api/auth/login", {method:"POST", body:JSON.stringify({username:$("#login-username").value.trim(), password:$("#login-password").value})});
    $("#login-password").value = "";
    showApp(data.csrf_token);
  } catch (error) { $("#login-error").textContent = error.message; }
});
$("#logout").addEventListener("click", async () => {
  try { await api("/api/auth/logout", {method:"POST"}); showLogin(); $("#login-password").focus(); }
  catch (error) { toast(error.message, true); }
});

function activateTab(button) {
  document.querySelectorAll(".tab,.panel").forEach(item => item.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(tab => tab.setAttribute("aria-selected", tab === button ? "true" : "false"));
  button.classList.add("active"); document.getElementById(button.dataset.panel).classList.add("active");
}
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => activateTab(button)));
$(".tabs").addEventListener("keydown", event => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = [...document.querySelectorAll(".tab")];
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
$("#path-to-type").value = "Domain";

async function loadHealth() { try { await api("/api/health"); $("#connection").classList.add("online"); $("#connection").lastChild.textContent = " Neo4j connected"; } catch { $("#connection").lastChild.textContent = " Neo4j unavailable"; } }
async function loadDashboard() {
  try { const data = await api("/api/dashboard"); const values = {"Total Nodes":data.nodes,"Relationships":data.relationships,...data.labels}; $("#stats").innerHTML = Object.entries(values).map(([label,value]) => `<div class="stat"><strong>${value}</strong><span>${escapeHtml(label)}</span></div>`).join(""); $("#provenance").innerHTML = `<div class="stat-grid"><div class="stat"><strong>${data.provenance.real || 0}</strong><span>Real ATT&amp;CK nodes</span></div><div class="stat"><strong>${data.provenance.synthetic || 0}</strong><span>Synthetic demo nodes</span></div></div>`; } catch (error) { toast(error.message, true); }
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
      return `<article class="result"><header><strong>${escapeHtml(title(row.entity))}</strong><span class="badge">${escapeHtml(row.type)}</span></header><p class="meta">ID: ${escapeHtml(stableId)} · Source: ${escapeHtml(row.entity.source)} · Synthetic: ${row.entity.is_synthetic ? "Yes" : "No"}</p><p class="meta">${escapeHtml(excerpt)}</p><details><summary>Full details and provenance</summary><pre class="output">${escapeHtml(JSON.stringify(row.entity,null,2))}</pre></details></article>`;
    }).join("") : '<p class="meta">No matching entities.</p>';
  } catch(error) { output.textContent = error.message; toast(error.message, true); }
});

function svgElement(name, attributes = {}) { const element = document.createElementNS("http://www.w3.org/2000/svg", name); Object.entries(attributes).forEach(([key,value]) => element.setAttribute(key,value)); return element; }
function renderGraph(data) { const svg = $("#graph"); svg.innerHTML = ""; const cx=450, cy=260, radius=185; const neighbors=data.neighbors.slice(0,12); const list=$("#graph-connections"); list.innerHTML=""; neighbors.forEach((neighbor,index) => { const angle=(Math.PI*2*index)/Math.max(neighbors.length,1)-Math.PI/2; const x=cx+Math.cos(angle)*radius, y=cy+Math.sin(angle)*radius; svg.append(svgElement("line",{x1:cx,y1:cy,x2:x,y2:y,class:"edge"})); const relation=data.relationships.find(item=>[item.start,item.end].includes(data.center_id)&&[item.start,item.end].includes(neighbor.id)); if(relation){ const edgeLabel=svgElement("text",{x:(cx+x)/2,y:(cy+y)/2,class:"edge-label"}); edgeLabel.textContent=relation.type; svg.append(edgeLabel); } const circle=svgElement("circle",{cx:x,cy:y,r:29,class:"node neighbor"}); circle.addEventListener("click",()=>$("#graph-details").textContent=JSON.stringify(neighbor.properties,null,2)); svg.append(circle); const label=svgElement("text",{x,y:y+43,class:"node-label"}); label.textContent=title(neighbor.properties).slice(0,18); svg.append(label); const li=document.createElement("li"); const detail=document.createElement("button"); detail.type="button"; detail.className="secondary"; detail.textContent=`${neighbor.type}: ${title(neighbor.properties)} — ${relation?.type || "RELATED"} — ${neighbor.properties.is_synthetic ? "Synthetic" : "Real"}`; detail.addEventListener("click",()=>$("#graph-details").textContent=JSON.stringify(neighbor.properties,null,2)); li.append(detail); list.append(li); }); const center=svgElement("circle",{cx,cy,r:46,class:"node center"}); center.addEventListener("click",()=>$("#graph-details").textContent=JSON.stringify(data.center,null,2)); svg.append(center); const label=svgElement("text",{x:cx,y:cy+65,class:"node-label"}); label.textContent=title(data.center).slice(0,28); svg.append(label); $("#graph-details").textContent=`${data.center_type}: ${title(data.center)} · showing ${neighbors.length} of ${data.neighbors.length} neighbors · ${data.relationships.length} relationships`; if(data.neighbors.length>neighbors.length){ const li=document.createElement("li");li.textContent=`${data.neighbors.length-neighbors.length} more neighbors not shown; use search or a narrower query.`;list.append(li); }
}
$("#graph-form").addEventListener("submit", async event => { event.preventDefault(); try { renderGraph(await api(`/api/graph/entity/${encodeURIComponent($("#graph-type").value)}/${encodeURIComponent($("#graph-id").value)}`)); } catch(error) { toast(error.message, true); } });

async function loadMetadata() {
  try {
    const data = await api("/api/entity-types");
    entityMetadata = data.metadata;
    relationshipPatterns = data.relationship_patterns;
    $("#entity-type").innerHTML = data.types.map(type => `<option>${escapeHtml(type)}</option>`).join("");
    $("#entity-type").value = "Malware";
    updateEntityHelp();
    $("#relationship-pattern").innerHTML = relationshipPatterns.map((pattern, index) => `<option value="${index}">${escapeHtml(pattern.from_type)} → ${escapeHtml(pattern.type)} → ${escapeHtml(pattern.to_type)}</option>`).join("");
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
    const result = await api("/api/relationships", {method:"POST", body:JSON.stringify({...pattern, from_id, to_id})});
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

$("#investigation-form").addEventListener("submit", async event => { event.preventDefault(); const query=new URLSearchParams({value:$("#actor-name").value,limit:"30"}); try { const {results}=await api(`/api/investigations/actor-investigation?${query}`); $("#investigation-results").innerHTML=results.length ? results.map(row=>`<article class="result"><header><strong>${escapeHtml(title(row.actor))}</strong><span class="badge">3 relationship path</span></header><p>${escapeHtml(title(row.malware))} → ${escapeHtml(row.ip.address)} → ${escapeHtml(row.domain.name)}</p><p class="meta">Actor source: ${escapeHtml(row.actor.source)} · Infrastructure synthetic: ${row.ip.is_synthetic ? "Yes" : "No"}</p></article>`).join("") : '<p class="meta">No complete investigation path for that actor.</p>'; } catch(error) { toast(error.message,true); } });

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

async function initialize() {
  loadHealth();
  try {
    const state = await api("/api/auth/session");
    if (state.authenticated) showApp(state.csrf_token);
    else showLogin();
  } catch (error) { showLogin(); $("#login-error").textContent = error.message; }
}
initialize();
