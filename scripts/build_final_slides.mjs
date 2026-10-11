import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const runtimeNodeModules = process.env.RUNTIME_NODE_MODULES;
const skillDir = process.env.PRESENTATIONS_SKILL_DIR;
const pythonExecutable = process.env.RUNTIME_PYTHON;
if (!runtimeNodeModules || !skillDir || !pythonExecutable) {
  throw new Error("Set RUNTIME_NODE_MODULES, PRESENTATIONS_SKILL_DIR, and RUNTIME_PYTHON to the slide-building dependencies before rebuilding the deck.");
}
const artifactModule = path.join(runtimeNodeModules,"@oai","artifact-tool","dist","artifact_tool.mjs");
const { Presentation, PresentationFile } = await import(pathToFileURL(artifactModule).href);

const workspaceDir = path.resolve(".");
const buildDir = path.join(workspaceDir, ".runtime", "slides-build");
const outputDir = path.join(workspaceDir, "output", "slides");
const finalPath = path.join(outputDir, "CyberTrace_Final_Demo.pptx");

const deck = Presentation.create({slideSize:{width:1280,height:720}});
const C = {ink:"#102B3F",muted:"#516576",accent:"#087F87",pale:"#F6FAFB"};

function text(slide, name, value, x, y, width, height, size, color=C.ink, bold=false) {
  const shape = slide.shapes.add({
    geometry:"textbox", name, position:{left:x,top:y,width,height},
    fill:"none", line:{style:"solid",fill:"none",width:0},
  });
  shape.text = value;
  shape.text.style = {fontFamily:"Aptos",fontSize:size,color,bold};
  return shape;
}
function slide(title, number, notes) {
  const page = deck.slides.add();
  page.background.fill = C.pale;
  text(page,`title-${number}`,title,72,54,1110,82,39,C.ink,true);
  text(page,`footer-${number}`,`CyberTrace  |  BCSE302P  |  ${number}`,72,661,820,28,15,C.muted);
  page.speakerNotes.text = notes;
  return page;
}
function lines(page, rows, y=178, gap=74, size=27) {
  rows.forEach((row,index)=>text(page,`line-${index}`,row,80,y+index*gap,1095,gap-8,size,C.ink,false));
}

{
  const page = deck.slides.add();
  page.background.fill=C.pale;
  text(page,"cover-title","CyberTrace",72,177,1120,120,66,C.ink,true);
  text(page,"cover-subtitle","Neo4j threat intelligence graph",78,316,1080,65,33,C.accent);
  text(page,"cover-context","BCSE302P Database Systems Lab  |  Final review",78,426,1080,48,24,C.muted);
  page.speakerNotes.text="Introduce CyberTrace as a local graph database lab application. The demonstration uses a pinned MITRE ATT&CK subset and labelled synthetic scenario data. Source: CyberTrace docs/final-report.md.";
}
{
  const page=slide("Data and provenance",2,"Show the source manifest and explain the separation. ATT&CK Enterprise v19.2 release: https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2. MITRE terms: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. Synthetic data is generated locally with seed 302.");
  text(page,"large-real","105 real",80,190,500,75,48,C.accent,true);
  text(page,"real-caption","ATT&CK groups, software, techniques",82,276,520,100,26);
  text(page,"large-synth","54 synthetic",690,190,500,75,48,C.accent,true);
  text(page,"synth-caption","Safe infrastructure and lab scenarios",692,276,500,100,26);
  text(page,"provenance-rule","Each node and relationship records its source and synthetic status.",80,451,1100,110,29,C.ink);
}
{
  const page=slide("Graph model",3,"Explain seven labels, six relationship type names and nine allowed label patterns. The sixth relationship name AFFECTS occurs only in synthetic scenarios. Seven uniqueness constraints and six explicit search indexes are verified by scripts/verify_database.py.");
  text(page,"labels-heading","Seven node labels",80,176,510,50,30,C.accent,true);
  text(page,"labels","ThreatActor, Malware, Technique,\nVulnerability, IP, Domain, Organization",80,245,510,220,27);
  text(page,"rels-heading","Six relationship types",660,176,535,50,30,C.accent,true);
  text(page,"rels","USES, TARGETS, EXPLOITS,\nCOMMUNICATES_WITH, RESOLVES_TO, AFFECTS",660,245,535,220,27);
  text(page,"schema-foot","Stable IDs: 7 uniqueness constraints  |  Search: 6 explicit indexes",80,524,1110,78,25,C.muted);
}
{
  const page=slide("Application workflow",4,"Live demonstration order: sign in, dashboard, search APT28, graph explorer with G0007, synthetic CRUD, multi-hop investigation, path and PageRank, sign out. Real records are read-only. User manual: docs/user-manual.md.");
  lines(page,["Sign in and inspect live graph totals","Search APT28 and inspect source fields","Explore G0007 and its labelled connections","Manage a disposable synthetic record","Investigate an actor to domain chain"],167,84,27);
}
{
  const page=slide("Graph analytics",5,"Shortest path is bounded to six hops and treats links as traversable in either direction while returning stored direction. PageRank follows directed links with damping 0.85. Real-only scope excludes synthetic nodes and links. These are graph topology tools, not threat scoring. Implementation: backend/analytics.py.");
  text(page,"path-heading","Shortest path",80,176,500,55,32,C.accent,true);
  text(page,"path-copy","Up to 6 hops\nMissing endpoint differs from no path\nEvery step carries provenance",80,247,505,260,27);
  text(page,"rank-heading","PageRank",670,176,500,55,32,C.accent,true);
  text(page,"rank-copy","Directed rank flow\nReal-only or all-data scope\nProminence is not threat severity",670,247,510,260,27);
}
{
  const page=slide("Verification and limits",6,"Run python -m scripts.verify_final. Observed on 11 October 2026: 27 automated tests passed, 159 nodes, 1116 relationships, 10 named investigations, CRUD, real-data guard, shortest path, PageRank. Limitations: selected ATT&CK subset, synthetic scenario links, local-only authentication and development server. Evidence: docs/final-verification.md.");
  text(page,"evidence","27 tests passed",80,167,1040,70,44,C.accent,true);
  text(page,"metrics","159 nodes  |  1,116 relationships  |  10 investigations",80,270,1110,105,31);
  text(page,"limits-heading","Interpretation limits",80,427,1080,52,29,C.ink,true);
  text(page,"limits","Selected ATT&CK subset; synthetic scenarios; local lab security model",80,492,1110,100,25,C.muted);
}

await fs.mkdir(buildDir,{recursive:true});
await fs.mkdir(outputDir,{recursive:true});
for(let i=0;i<deck.slides.items.length;i++){
  const png=await deck.export({slide:deck.slides.items[i],format:"png",scale:1});
  await fs.writeFile(path.join(buildDir,`slide-${String(i+1).padStart(2,"0")}.png`),new Uint8Array(await png.arrayBuffer()));
}
const draftPath=path.join(buildDir,"CyberTrace_Final_Demo_draft.pptx");
await (await PresentationFile.exportPptx(deck)).save(draftPath);
const {finalizePresentation}=await import(pathToFileURL(path.join(skillDir,"container_tools","artifact_tool_utils.mjs")).href);
const result=await finalizePresentation({
  workspaceDir,candidatePath:draftPath,finalPath,
  pythonExecutable,
  integrityValidatorPath:path.join(skillDir,"container_tools","inspect_presentation_package_integrity.py"),
  layoutValidatorPath:path.join(skillDir,"container_tools","inspect_presentation_layout_geometry.py"),
  layoutArgs:["--expected-slide-size-emu","12192000,6858000","--validate-heading-fit"],
  fontPolicy:{basis:"design",families:["Aptos"]},
  verifyArtifactToolImport:true,
  receiptPath:path.join(buildDir,"validation-27-tests.json"),
});
console.log(JSON.stringify({draftPath,finalPath,result},null,2));
