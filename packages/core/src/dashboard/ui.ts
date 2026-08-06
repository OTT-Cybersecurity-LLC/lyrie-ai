/**
 * dashboard/ui.ts — self-contained static HTML for the public
 * Agentic-Attack-Compression radar. No build step, no external assets, no
 * CDN: a single string served by the dashboard server. It polls
 * `/api/compression/feed` and draws a lightweight canvas radar keyed on
 * attack phase + channel, plus threat-level counters.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export function renderRadarHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Lyrie — Agentic Attack Compression Radar</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#05070d; color:#c9d4e5; }
  header { padding:16px 20px; border-bottom:1px solid #16202f; }
  h1 { font-size:16px; margin:0; letter-spacing:0.04em; }
  .sub { color:#5f7085; font-size:12px; margin-top:4px; }
  main { display:grid; grid-template-columns: 360px 1fr; gap:20px; padding:20px; }
  canvas { background:radial-gradient(circle at center, #0a1524 0%, #05070d 70%); border:1px solid #16202f; border-radius:8px; }
  .panel { border:1px solid #16202f; border-radius:8px; padding:14px; }
  .panel h2 { font-size:12px; color:#7d8ea6; margin:0 0 10px; text-transform:uppercase; letter-spacing:0.08em; }
  .row { display:flex; justify-content:space-between; padding:3px 0; font-size:13px; }
  .lvl-Critical { color:#ff5d5d; } .lvl-High { color:#ff9f43; }
  .lvl-Medium { color:#ffd93d; } .lvl-Low { color:#5ad1a0; } .lvl-None { color:#5f7085; }
  .stamp { color:#5f7085; font-size:11px; margin-top:8px; }
</style>
</head>
<body>
<header>
  <h1>◐ LYRIE · AGENTIC ATTACK COMPRESSION RADAR</h1>
  <div class="sub">Anonymized, aggregated signal feed · automation ↔ autonomy spectrum · OTT Cybersecurity LLC</div>
</header>
<main>
  <div>
    <canvas id="radar" width="320" height="320"></canvas>
    <div class="stamp" id="stamp">connecting…</div>
  </div>
  <div>
    <div class="panel">
      <h2>Threat levels (window)</h2>
      <div id="levels"></div>
    </div>
    <div class="panel" style="margin-top:16px;">
      <h2>Channels</h2>
      <div id="channels"></div>
    </div>
    <div class="panel" style="margin-top:16px;">
      <h2>Attack phases</h2>
      <div id="phases"></div>
    </div>
  </div>
</main>
<script>
const PHASE_ORDER = ["Recon","InitialAccess","Execution","Persistence","LateralMovement","Exfiltration","PromptInjection","SelfPropagation"];
const CH_NAMES = {1:"Automation",2:"Augmentation",3:"Autonomy"};
const cv = document.getElementById("radar"), ctx = cv.getContext("2d");
const cx = cv.width/2, cy = cv.height/2, R = 130;

function drawRadar(byPhase){
  ctx.clearRect(0,0,cv.width,cv.height);
  ctx.strokeStyle = "#16202f";
  for (let r=1;r<=4;r++){ ctx.beginPath(); ctx.arc(cx,cy,R*r/4,0,Math.PI*2); ctx.stroke(); }
  const n = PHASE_ORDER.length;
  const max = Math.max(1, ...PHASE_ORDER.map(p => byPhase[p]||0));
  ctx.strokeStyle = "#2a3a52";
  const pts = [];
  for (let i=0;i<n;i++){
    const ang = (i/n)*Math.PI*2 - Math.PI/2;
    ctx.beginPath(); ctx.moveTo(cx,cy);
    ctx.lineTo(cx+Math.cos(ang)*R, cy+Math.sin(ang)*R); ctx.stroke();
    const v = (byPhase[PHASE_ORDER[i]]||0)/max;
    pts.push([cx+Math.cos(ang)*R*v, cy+Math.sin(ang)*R*v]);
    ctx.fillStyle = "#5f7085"; ctx.font = "9px monospace";
    ctx.fillText(PHASE_ORDER[i].slice(0,6), cx+Math.cos(ang)*(R+10)-14, cy+Math.sin(ang)*(R+10));
  }
  ctx.beginPath();
  pts.forEach((p,i)=> i? ctx.lineTo(p[0],p[1]) : ctx.moveTo(p[0],p[1]));
  ctx.closePath();
  ctx.fillStyle = "rgba(90,209,160,0.18)"; ctx.strokeStyle = "#5ad1a0";
  ctx.fill(); ctx.stroke();
}
function rows(el, obj, cls){
  el.innerHTML = Object.entries(obj).map(([k,v])=>
    '<div class="row '+(cls?cls+k:'')+'"><span>'+(CH_NAMES[k]||k)+'</span><span>'+v+'</span></div>').join("");
}
async function tick(){
  try {
    const r = await fetch("/api/compression/feed"); const d = await r.json();
    drawRadar(d.aggregate.byPhase||{});
    rows(document.getElementById("levels"), d.aggregate.byThreatLevel||{}, "lvl-");
    rows(document.getElementById("channels"), d.aggregate.byChannel||{});
    rows(document.getElementById("phases"), d.aggregate.byPhase||{});
    document.getElementById("stamp").textContent =
      d.aggregate.total+" signals · updated "+new Date(d.generatedAtMs).toISOString();
  } catch(e){ document.getElementById("stamp").textContent = "feed unavailable"; }
}
tick(); setInterval(tick, 5000);
</script>
</body>
</html>`;
}
