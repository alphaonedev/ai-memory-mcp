/* Dashboard renderer for index.html (#7313, #7587, #7588, #7634, #7684).
   No state value reaches the DOM as markup except through the helper block below, which is the only code that
   names the token store, the Trusted Types policy or innerHTML:
   - markup`...` is a template tag: every ${...} that is not markup is HTML-escaped once, so a state value can
     never become markup; a plain call markup("...") throws;
   - cat(list, sep) joins markup and escaped values;
   - nf(value, digits) prints a finite number or the fixed placeholder;
   - put(host, markup) is the single sink. The policy `dash` (one createPolicy, no allow-duplicates) escapes
     any plain string it is given and passes only a token the closure-private WeakMap holds. The Content-Security-Policy
     (public/_headers) adds require-trusted-types-for 'script' and trusted-types dash, so a Chromium browser
     rejects every other string-to-HTML sink. Browsers without Trusted Types get the same escaping plus
     script-src 'self'. The page carries no inline script or handler. */
const PLACEHOLDER = "\u2014";
const { markup, cat, put } = (() => {
  // Trust is a closure-private brand, not a type (#7684): markup() returns a frozen, prototype-less, property-less
  // token and its text lives only in this WeakMap, keyed by the token. Nothing outside this block can read, add to or
  // forge an entry (no constructor, no property, no prototype carries trust), and the WeakMap methods are captured here
  // so a later patch of WeakMap.prototype changes nothing.
  const trusted = new WeakMap();
  const has = trusted.has.bind(trusted), get = trusted.get.bind(trusted), set = trusted.set.bind(trusted);
  const escText = v => String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const mint = text => { const token = Object.freeze(Object.create(null)); set(token, text); return token; };
  const part = v => has(v) ? get(v) : escText(v);
  const markup = (strings, ...values) => {
    if(!Array.isArray(strings) || !Array.isArray(strings.raw)) throw new TypeError("markup is a template tag, not a function");
    let out = strings[0];
    for(let i = 0; i < values.length; i++) out += part(values[i]) + strings[i + 1];
    return mint(out);
  };
  const cat = (list, sep) => mint(list.map(part).join(sep == null ? "" : escText(sep)));
  const put = (() => {
    const rules = { createHTML: (s, h) => has(h) ? get(h) : escText(s) };
    const dash = window.trustedTypes ? window.trustedTypes.createPolicy("dash", rules) : rules;
    return function put(host, h){
      if(!has(h)) throw new TypeError("put() takes markup, not a string");
      host.innerHTML = dash.createHTML("", h);
    };
  })();
  return { markup, cat, put };
})();
function num(v){
  const x = typeof v === "number" ? v : (typeof v === "string" && v.trim() !== "" ? Number(v) : NaN);
  return Number.isFinite(x) ? x : null;
}
function nf(v, d){
  const x = num(v);
  if(x === null) return PLACEHOLDER;
  return d === undefined ? String(x) : x.toFixed(d);
}
const FLOWATTR = markup`stroke-dasharray="10 8" class="flow"`;
const STALEATTR = markup` class="c-warn"`;
// #7687: every number written into an SVG attribute or path goes through sn()/pd(), which require Number.isFinite.
// A value that is not a finite number throws BADNUM and omit() drops just that element: nothing is drawn and nothing
// is logged (a text placeholder is used outside SVG, see nf()).
const BADNUM = {};
function sn(v, d){
  const x = num(v);
  if(x === null || !Number.isFinite(x)) throw BADNUM;
  return d === undefined ? String(x) : x.toFixed(d);
}
function omit(build){
  try{ return build(); }
  catch(e){ if(e === BADNUM) return cat([]); throw e; }
}
// path data from [letter, n, n, ...] commands; the strings "0" and "1" are arc flags and are written as given
function pd(cmds){
  return cmds.map(c=>c[0]+c.slice(1).map(n=>typeof n==="string"&&/^[01]$/.test(n)?n:sn(n,1)).join(" ")).join(" ");
}
// #7689: dynamic widths and offsets travel as data-w / data-left and are applied through the CSSOM
// (style.setProperty), which style-src does not govern; a value that is not a finite number sets nothing.
function dyn(root){
  root.querySelectorAll("[data-w],[data-left]").forEach(e=>{
    const w=num(e.dataset.w), l=num(e.dataset.left);
    if(w!==null) e.style.setProperty("width", w+"%");
    if(l!==null) e.style.setProperty("left", l+"%");
  });
}

const LABEL={done:"green",run:"running",stale:"stale",pend:"pending",fail:"fail"};
const el=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)put(e,h);return e;};
const fmt=v=>{ if(v==null)return null; const x=num(v); if(x===null)return PLACEHOLDER; if(x>=1e6)return (x/1e6).toFixed(x>=1e7?0:1)+"M"; if(x>=1e3)return (x/1e3).toFixed(x>=1e4?0:1)+"k"; return (Math.round(x*10)/10).toString(); };

/* ---------- animated count-up KPIs ---------- */
const kpiAnim={};
function renderKpis(list){
  const host=document.getElementById("kpis");
  if(host.childElementCount!==list.length){ host.textContent=""; list.forEach((k,i)=>{
    const c=el("div","kpi "+(k.state||"pend"));
    put(c, markup`<div class="lab">${k.label}</div><div class="val ${k.value==null?'pend':''}" id="kv${nf(i)}">—</div><div class="sub">${k.sub||""}</div>`);
    host.appendChild(c);
  });}
  list.forEach((k,i)=>{
    const box=document.getElementById("kpis").children[i];
    box.className="kpi "+(k.state||"pend");
    box.querySelector(".lab").textContent=k.label; box.querySelector(".sub").textContent=k.sub||"";
    const vEl=document.getElementById("kv"+i);
    if(k.value==null){ vEl.className="val pend"; vEl.textContent="—"; kpiAnim[i]=null; return; }
    vEl.className="val";
    const tgt=k.value, from=(kpiAnim[i]==null?0:kpiAnim[i]); kpiAnim[i]=tgt;
    const of=k.of!=null?markup` <span class="of">/ ${fmt(k.of)}</span>`:""; const su=k.suffix?markup`<span class="su">${k.suffix}</span>`:"";
    const t0=performance.now(),dur=700;
    (function step(now){ const p=Math.min(1,(now-t0)/dur), e=1-Math.pow(1-p,3), cur=from+(tgt-from)*e;
      put(vEl, markup`${fmt(cur)}${su}${of}`); if(p<1)requestAnimationFrame(step); })(t0);
  });
}

/* ---------- live swarm canvas ---------- */
let swarmState=null;
const swCanvas=document.getElementById("swarm");
const SCOL={working:'--good',idle:'--run',recovered:'--viol',error:'--bad'};
function safeUrl(u){return /^https:\/\//.test(String(u||''))?String(u):'#';}
function swarmFabric(sw){
  sw=sw||{}; const D=window.__D||{}; const legs=((D.comms||{}).legs)||[];
  const model=sw.model||"GLM-5.3-Flash";
  for(const id of ["swarmModelSec","swarmModelCap","swarmModelHero"]){const e=document.getElementById(id); if(e) e.textContent=model;}
  const host=document.getElementById("swarm"); if(!host) return;
  const leg=(pfx)=>legs.find(l=>(l.name||"").startsWith(pfx))||{};
  const rate=(l)=>l.rate!=null?l.rate:null;
  const live=!!sw.live&&window.__RUN===true, working=sw.working||0, total=sw.total||0;
  const mods=(sw.modules&&sw.modules.length)?sw.modules:[{id:"f2",agents:total,working:working,calls:null,writes:null,active:live&&working>0},{id:"f1",agents:0,working:0,calls:null,writes:null,active:false}];
  const f2=mods.find(m=>m.id==="f2")||mods[0], f1=mods.find(m=>m.id==="f1")||{id:"f1",agents:0,working:0,calls:0,writes:0,active:false};
  const embedLeg=leg("ai-memory → OpenRouter (embed)"), loopLeg=leg("Agent → ai-memory daemon (loopback"), xLeg=leg("Agent → ai-memory daemon (cross-host"), pgLeg=leg("Daemon → PostgreSQL");
  const fit=(t,m)=>{t=String(t==null?'':t); return t.length>m?t.slice(0,m-1)+'…':t;};
  // box() and flow() take plain text and escape it exactly once
  // every box is sized so that `maxc` characters of 10px monospace (~6.2px/char) fit with padding; lines are clipped to maxc
  const box=(x,y,w,h,title,sub,on,accent)=>{const maxc=Math.floor((w-24)/6.2); return cat([
    omit(()=>markup`<rect x="${sn(x)}" y="${sn(y)}" width="${sn(w)}" height="${sn(h)}" rx="14" fill="var(--raise)" stroke="${on?accent:'var(--line)'}" stroke-width="${sn(on?2.5:1)}"/>`),
    omit(()=>markup`<text x="${sn(x+w/2)}" y="${sn(y+24)}" text-anchor="middle" class="svt">${fit(title,Math.floor((w-24)/8))}</text>`),
    cat(sub.filter(t=>t!=null&&String(t).trim()!=='').map((t,i)=>omit(()=>markup`<text x="${sn(x+w/2)}" y="${sn(y+44+i*15)}" text-anchor="middle" class="svm svs">${fit(t,maxc)}</text>`)))]);};
  const flow=(x1,y1,x2,y2,label,on,col,above=true)=>{const mx=(x1+x2)/2,my=(y1+y2)/2; return cat([
    omit(()=>markup`<line x1="${sn(x1)}" y1="${sn(y1)}" x2="${sn(x2)}" y2="${sn(y2)}" stroke="${on?col:'var(--dim)'}" stroke-width="${sn(on?3:1.5)}" ${on?FLOWATTR:''} marker-end="url(#ah)" marker-start="url(#at)"/>`),
    omit(()=>markup`<rect x="${sn(mx-((label.length*6.2)/2)-6)}" y="${sn(above?my-22:my+6)}" width="${sn(label.length*6.2+12)}" height="16" rx="6" fill="var(--bg)" opacity=".85"/>`),
    omit(()=>markup`<text x="${sn(mx)}" y="${sn(above?my-10:my+18)}" text-anchor="middle" class="svm" fill="${on?col:'var(--soft)'}">${label}</text>`)]);};
  const pair=(v,u)=>v==null?'—':(v+' '+u);
  const W=1240,H=640;
  const OR={x:30,y:40,w:290,h:96}, AG={x:30,y:330,w:290,h:170}, AM2={x:470,y:70,w:300,h:118}, AM1={x:470,y:400,w:300,h:118}, DT2={x:900,y:70,w:320,h:118}, DT1={x:900,y:400,w:320,h:118};
  const parts=[omit(()=>markup`<svg viewBox="0 0 ${sn(W)} ${sn(H)}" width="100%" preserveAspectRatio="xMidYMid meet" class="swarmsvg">
  <defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--soft)"/></marker>
  <marker id="at" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M10,0 L0,5 L10,10 z" fill="var(--soft)"/></marker></defs>`)];
  parts.push(box(OR.x,OR.y,OR.w,OR.h,"OpenRouter",[model+" decide calls","gemini-embedding-2 embeds · gemini-3.7-flash LLM",embedLeg.live&&embedLeg.live.usd_per_hour!=null?"$"+embedLeg.live.usd_per_hour+"/h live spend":null],live,"var(--p3,#c8a2ff)"));
  parts.push(box(AG.x,AG.y,AG.w,AG.h,"AI agents (NHIs)",[total+" "+model+" agents",working+" working · "+(total-working)+" idle",fit(sw.run||'',40),"Ed25519-signed writes · own namespace"],live&&working>0,"var(--good)"));
  parts.push(box(AM2.x,AM2.y,AM2.w,AM2.h,"ai-memory · f2 (Linux)",["TLS 1.3 + pinned mTLS + API key",f2.agents+" agents · "+f2.working+" working",f2.calls!=null?Number(f2.calls).toLocaleString()+" calls this run":null],f2.active,"var(--acc)"));
  parts.push(box(AM1.x,AM1.y,AM1.w,AM1.h,"ai-memory · f1 (macOS)",["TLS 1.3 + pinned mTLS + API key",f1.agents+" agents · "+f1.working+" working",f1.calls!=null?Number(f1.calls).toLocaleString()+" calls this run":null],f1.active,"var(--acc)"));
  parts.push(box(DT2.x,DT2.y,DT2.w,DT2.h,"data tier · f2",["PostgreSQL 18.6 · Apache AGE 1.8.0","pgvector 0.8.6 · TLS verify-full · "+pair(rate(pgLeg),'tx/s'),f2.writes!=null?f2.writes+" signed rows this run":null],f2.active,"var(--p2,#ffb86b)"));
  parts.push(box(DT1.x,DT1.y,DT1.w,DT1.h,"data tier · f1",["PostgreSQL 18.6 · Apache AGE 1.8.0","pgvector 0.8.6 · TLS verify-full",f1.writes!=null?f1.writes+" signed rows this run":null],f1.active,"var(--p2,#ffb86b)"));
  // flows anchored on box EDGES (never crossing a box)
  parts.push(flow(AG.x+AG.w/2, AG.y, OR.x+OR.w/2, OR.y+OR.h, "decide (prompt → tool call)", live&&working>0, "var(--p3,#c8a2ff)", false));
  parts.push(flow(AG.x+AG.w, AG.y+50, AM2.x, AM2.y+AM2.h-10, "mTLS · "+pair(rate(loopLeg),'/s'), f2.active, "var(--good)"));
  parts.push(flow(AG.x+AG.w, AG.y+120, AM1.x, AM1.y+AM1.h/2, "mTLS cross-host · "+pair(rate(xLeg),'/s'), f1.active, "var(--good)", false));
  parts.push(flow(AM2.x+AM2.w, AM2.y+AM2.h/2, DT2.x, DT2.y+DT2.h/2, "TLS verify-full", f2.active, "var(--p2,#ffb86b)"));
  parts.push(flow(AM1.x+AM1.w, AM1.y+AM1.h/2, DT1.x, DT1.y+DT1.h/2, "TLS verify-full", f1.active, "var(--p2,#ffb86b)"));
  parts.push(flow(AM2.x, AM2.y+18, OR.x+OR.w, OR.y+OR.h/2, "embed / LLM · "+pair(embedLeg.ms,'ms'), f2.active, "var(--p3,#c8a2ff)"));
  parts.push(omit(()=>markup`<line x1="${sn(AM2.x+AM2.w/2)}" y1="${sn(AM2.y+AM2.h)}" x2="${sn(AM1.x+AM1.w/2)}" y2="${sn(AM1.y)}" stroke="var(--dim)" stroke-dasharray="3 5"/>`));
  parts.push(omit(()=>markup`<text x="${sn(AM2.x+AM2.w/2+10)}" y="${sn((AM2.y+AM2.h+AM1.y)/2+4)}" class="svm svs">federation (mTLS) · not wired this run</text>`));
  parts.push(omit(()=>markup`<text x="${sn(W/2)}" y="${sn(H-14)}" text-anchor="middle" class="svm svs svfoot">every link encrypted · ${window.__RUN===true?'animated links = data moving now':'no animation: no run is active'} · ${sw.run||'no run active'} · as of ${String(sw.asOf||'').replace('T',' ')}</text>`));
  parts.push(markup`</svg>`);
  put(host, cat(parts));
}

/* ---------- streaming throughput area ---------- */
function areaChart(mount, series, yk, ylab){
  const host=document.getElementById(mount);
  if(!series||series.length<2){put(host, markup`<div class="await">no data<br>· empty series in this state ·</div>`);return;}
  const W=440,H=200,PL=44,PR=10,PT=14,PB=24, pts=series.slice(-60);
  const ys=pts.map(p=>p[yk]); const ymax=Math.max(...ys)*1.15||1;
  const X=i=>PL+i/(pts.length-1)*(W-PL-PR), Y=v=>H-PB-(v/ymax)*(H-PT-PB);
  const last=pts[pts.length-1][yk];
  const kids=[
    markup`<defs><linearGradient id="tpg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--acc)" stop-opacity="0.35"/><stop offset="1" stop-color="var(--acc)" stop-opacity="0"/></linearGradient></defs>`,
    omit(()=>markup`<line x1="${sn(PL)}" y1="${sn(H-PB)}" x2="${sn(W-PR)}" y2="${sn(H-PB)}" stroke="var(--grid)"/>`),
    omit(()=>markup`<path d="${pd([["M",X(0),H-PB],...pts.map((p,i)=>["L",X(i),Y(p[yk])]),["L",X(pts.length-1),H-PB],["Z"]])}" fill="url(#tpg)"/>`),
    omit(()=>markup`<path d="${pd(pts.map((p,i)=>[i?"L":"M",X(i),Y(p[yk])]))}" fill="none" stroke="var(--acc)" stroke-width="2"/>`),
    omit(()=>markup`<circle cx="${sn(X(pts.length-1),1)}" cy="${sn(Y(last),1)}" r="3.5" fill="var(--acc)"/>`),
    omit(()=>markup`<text x="${sn(W-PR)}" y="${sn(PT)}" text-anchor="end" fill="var(--ink)" font-size="15" font-family="var(--disp)" font-weight="700">${fmt(last)}</text>`),
    omit(()=>markup`<text x="${sn(W-PR)}" y="${sn(PT+13)}" text-anchor="end" fill="var(--soft)" font-size="9">${ylab}</text>`)];
  put(host, omit(()=>markup`<svg viewBox="0 0 ${sn(W)} ${sn(H)}" width="100%">${cat(kids)}</svg>`));
}

/* ---------- line chart (capacity knee / scaling) ---------- */
function lineChart(mount, pts, xk, yk, xlab, ylab, markKnee){
  const host=document.getElementById(mount);
  if(!pts||!pts.length){put(host, markup`<div class="await">awaiting measurement</div>`);return;}
  const W=440,H=200,PL=44,PR=12,PT=14,PB=30;
  const xs=pts.map(p=>p[xk]),ys=pts.map(p=>p[yk]); const xmin=Math.min(...xs),xmax=Math.max(...xs),ymax=Math.max(...ys)*1.1||1;
  const X=v=>PL+(v-xmin)/((xmax-xmin)||1)*(W-PL-PR), Y=v=>H-PB-(v/ymax)*(H-PT-PB);
  const dots=cat(pts.map(p=>omit(()=>markup`<circle cx="${sn(X(p[xk]),1)}" cy="${sn(Y(p[yk]),1)}" r="2.5" fill="var(--acc)"/>`)));
  let knee=cat([]);
  if(markKnee&&pts.length>2){let ki=pts.length-1;for(let i=1;i<pts.length;i++){if(pts[i][yk]<pts[i-1][yk]*1.03){ki=i-1;break;}}
    const p=pts[ki];knee=cat([
      omit(()=>markup`<line x1="${sn(X(p[xk]))}" y1="${sn(PT)}" x2="${sn(X(p[xk]))}" y2="${sn(H-PB)}" stroke="var(--good)" stroke-dasharray="3 3" opacity=".7"/>`),
      omit(()=>markup`<text x="${sn(X(p[xk])+4)}" y="${sn(PT+11)}" fill="var(--good)" font-size="10">knee ≈ ${p[xk]} agents</text>`)]);}
  const kids=[
    omit(()=>markup`<line x1="${sn(PL)}" y1="${sn(H-PB)}" x2="${sn(W-PR)}" y2="${sn(H-PB)}" stroke="var(--grid)"/>`),
    omit(()=>markup`<line x1="${sn(PL)}" y1="${sn(PT)}" x2="${sn(PL)}" y2="${sn(H-PB)}" stroke="var(--grid)"/>`),
    knee,
    omit(()=>markup`<path d="${pd(pts.map((p,i)=>[i?"L":"M",X(p[xk]),Y(p[yk])]))}" fill="none" stroke="var(--acc)" stroke-width="2"/>`),
    dots,
    omit(()=>markup`<text x="${sn(W/2)}" y="${sn(H-5)}" fill="var(--soft)" font-size="10" text-anchor="middle">${xlab}</text>`),
    omit(()=>markup`<text x="10" y="${sn(H/2)}" fill="var(--soft)" font-size="10" transform="rotate(-90 10 ${sn(H/2)})" text-anchor="middle">${ylab}</text>`)];
  put(host, omit(()=>markup`<svg viewBox="0 0 ${sn(W)} ${sn(H)}" width="100%">${cat(kids)}</svg>`));
}
function donut(mount, cov){
  const host=document.getElementById(mount);
  if(!cov||!cov.total){put(host, markup`<div class="await">awaiting Phase 1</div>`);return;}
  const pct=cov.covered/cov.total,r=54,c=2*Math.PI*r;
  const kids=[
    omit(()=>markup`<circle r="${sn(r)}" fill="none" stroke="var(--line)" stroke-width="14"/>`),
    omit(()=>markup`<circle r="${sn(r)}" fill="none" stroke="var(--good)" stroke-width="14" stroke-linecap="round" stroke-dasharray="${sn(c)}" stroke-dashoffset="${sn(c*(1-pct),1)}" transform="rotate(-90)"/>`),
    markup`<text y="-1" text-anchor="middle" font-size="24" fill="var(--ink)" font-family="var(--disp)" font-weight="700">${nf(Math.round(pct*100))}%</text>`,
    markup`<text y="17" text-anchor="middle" font-size="10" fill="var(--soft)">${cov.covered}/${cov.total} tools</text>`];
  put(host, markup`<svg viewBox="0 0 160 132" width="100%"><g transform="translate(80,66)">${cat(kids)}</g></svg>`);
}
function latency(mount, L){
  const host=document.getElementById(mount);
  if(!L){put(host, markup`<div class="await">awaiting measurement</div>`);return;}
  const rows=[["p50",L.p50],["p95",L.p95],["p99",L.p99]];const max=Math.max(L.budget,L.p99)*1.1;
  const body=cat(rows.map(([k,v])=>{
    const w=Math.min(100,v/max*100),bw=L.budget/max*100,ok=v<=L.budget;
    return markup`<div class="latrow"><div class="lathead"><span>${k}</span><span class="${ok?'c-good':'c-bad'}">${v} ms</span></div>
      <div class="lattrack"><div class="latbud" data-left="${nf(bw)}"></div><div class="latfill ${ok?'bg-good':'bg-bad'}" data-w="${nf(w)}"></div></div></div>`;
  }));
  put(host, markup`<div class="latwrap">${body}<div class="latnote">▏ budget ${L.budget} ms (PERFORMANCE.md)</div></div>`);
  dyn(host);
}

function security(mount, s){
  const host=document.getElementById(mount);
  if(!s||s.injected==null){put(host, markup`<div class="await">awaiting red-team injection<br>· bad-memory infection test ·</div>`);return;}
  const clean=s.infections===0;
  put(host, markup`<div class="shield">
    <div class="shieldbig ${clean?'c-good':'c-bad'}">${clean?'0':s.infections}</div>
    <div class="shieldrows">
      <div class="shrow"><span>infections that spread</span><b class="${clean?'c-good':'c-bad'}">${s.infections}${clean?' ✓':''}</b></div>
      <div class="shrow"><span>poisoned memories injected</span><b>${s.injected}</b></div>
      <div class="shrow"><span>convicted / quarantined</span><b>${s.blocked}</b></div>
      <div class="shrow"><span>groupthink cascades</span><b class="${(s.cascades||0)===0?'c-good':'c-bad'}">${s.cascades||0}</b></div>
    </div></div>`);
}
function continuity(mount, cyc){
  const host=document.getElementById(mount);
  if(!cyc||!cyc.length){put(host, markup`<div class="await">awaiting hard kill cycles<br>· resume-from-cold test ·</div>`);return;}
  const ok=cyc.filter(c=>c.retained).length;
  const cells=cat(cyc.map(c=>markup`<div class="cyccell"><div class="n">cycle ${c.cycle}</div><div class="ck">${c.retained?'✓':'✕'}</div><div class="ms">${c.resume_ms!=null?c.resume_ms+'ms':''}</div></div>`));
  put(host, markup`<div class="contsum">${nf(ok)}/${nf(cyc.length)} cold restarts recovered mission + resumed exactly where it left off</div>
  <div class="cyc">${cells}</div>`);
}
function campaignsPanel(g){
  const host=document.getElementById("campaignsPanel"); if(!host) return;
  if(!g||!g.campaigns){put(host, markup`<p class="cap">campaign data not measurable this pass</p>`);return;}
  const fl=fs=>cat((fs||[]).map(f=>markup`<a href="${safeUrl(f.url)}" title="${f.title}">#${f.number}${f.state==="OPEN"?"":" (closed)"}</a>`), " ");
  const out=[markup`<p class="mb10"><b class="${g.closed>=g.total?"c-good":"c-warn"}">${g.gate}</b> &middot; cells ticked ${nf(g.cells_done)}/${nf(g.cells_total)}</p>`];
  g.campaigns.forEach(r=>{const s=r.summary||{};
    out.push(markup`<h4 class="cmph">Campaign ${r.letter} &mdash; <a href="${safeUrl(r.url)}">#${r.n}</a> ${r.title}</h4>`);
    out.push(markup`<p class="cap mb6">state <b>${r.state}</b> &middot; cells ${nf(s.cells_done)}/${nf(s.cells_total)} &middot; findings open ${nf(s.findings_open)} / closed ${nf(s.findings_closed)}${(r.findings||[]).length?markup` &middot; campaign-level findings: ${fl(r.findings)}`:""}</p>`);
    const cellRows=cat((r.cells||[]).map(c=>markup`<tr><td><code>${c.id}</code></td><td>${c.text}</td><td>${c.backend}</td><td class="stcell ${c.state==="done"?"c-good":"c-warn"}">${c.state}</td><td>${fl(c.findings)}</td></tr>`));
    out.push(markup`<table class="agents"><thead><tr><th>cell</th><th>test</th><th>backend</th><th>state</th><th>findings</th></tr></thead><tbody>${cellRows}</tbody></table>`);});
  put(host, cat(out));
}
function board(dims){
  const b=document.getElementById("board"); b.textContent="";
  dims.forEach(x=>{const cls=x.s==="done"?"done":x.s==="run"?"run":x.s==="stale"?"stale":x.s==="fail"?"fail":"";
    const card=el("div","dim "+cls);
    put(card, markup`<div class="dimhead"><h3>${x.n}</h3><span class="st ${x.s}">${LABEL[x.s]||x.s}</span></div><div class="d">${x.d||""}</div><div class="m">${x.m||""}</div>`);
    b.appendChild(card);});
}
function feed(evs){
  const f=document.getElementById("feed");f.textContent="";
  evs.slice().sort((a,b)=>(b.t||"").localeCompare(a.t||"")).slice(0,40).forEach(e=>{
    const row=el("div","ev");const tm=(e.t||"").replace("T"," ").replace("Z","").slice(5,16);
    put(row, markup`<time>${tm}</time><span class="k ${e.k||'info'}">${(e.k||'info').toUpperCase()}</span><span>${e.x||""}</span>`);
    f.appendChild(row);});
}

/* ---------- hardware architecture monitor ---------- */
function hwBar(used,total){const p=total?Math.min(100,used/total*100):0;const col=p>85?'bg-bad':p>70?'bg-warn':'bg-good';
  return markup`<div class="hbar"><div class="hbarfill ${col}" data-w="${nf(p,0)}"></div></div>`;}
function hardwareMonitor(hw){
  const host=document.getElementById("hwmon"),tag=document.getElementById("hwtag");
  if(!hw||!hw.nodes||!hw.nodes.length){put(host, markup`<div class="await">awaiting node telemetry</div>`);tag.textContent="—";return;}
  const up=hw.nodes.filter(n=>n.status==='up').length;
  tag.textContent=up+"/"+hw.nodes.length+" up"; tag.className="envtag "+(up===hw.nodes.length?"ok":"warn");
  const nodes=cat(hw.nodes.map(n=>{
    const led=n.status==='up'?'bg-good':n.status==='pressure'?'bg-warn':'bg-bad';
    return markup`<div class="hwnode">
      <div class="hwtop"><span class="hwled ${led}"></span><b>${n.id}</b><span class="hwos">${n.os}</span><span class="hwrole">${n.role}</span></div>
      ${n.gpu?markup`<div class="hwgpu">⚡ ${n.gpu}</div>`:markup`<div class="hwgpu off">CPU-only · no GPU/NPU</div>`}
      <div class="hwmetric"><span class="hwk">RAM</span>${hwBar(n.ram_used,n.ram_total)}<span class="hwv">${nf(n.ram_used)}/${nf(n.ram_total)} GB</span></div>
      <div class="hwmetric"><span class="hwk">Disk</span>${hwBar(n.disk_total-n.disk_free,n.disk_total)}<span class="hwv">${nf(n.disk_free)} GB free</span></div>
      <div class="hwfoot"><span class="hwchip">✓ ${n.datatier}</span><span class="hwmem">${(n.memories||0).toLocaleString()} mem</span></div>
    </div>`;
  }));
  const link=hw.link?markup`<div class="hwlink">🔒 ${hw.link.proto}${hw.link.status?' · '+hw.link.status:''}</div>`:"";
  put(host, markup`<div class="hwnodes">${nodes}</div>${link}`);
  dyn(host);
}
/* ---------- DigitalOcean cloud monitor ---------- */
function cloudMonitor(cloud){
  const host=document.getElementById("domon"),tag=document.getElementById("dotag");
  if(!cloud){put(host, markup`<div class="await">DigitalOcean monitor — awaiting cloud phase</div>`);tag.textContent="—";return;}
  const drops=cloud.droplets||[],lim=cloud.droplet_limit||15;
  tag.textContent=cloud.status||"armed"; tag.className="envtag "+(drops.length?"ok":"warn");
  const configs=cat((cloud.configs||[]).map(c=>markup`<div class="docfg ${c.status}"><span class="docn">${c.name}</span><span class="docd">${c.desc}</span><span class="docs">${c.status}</span></div>`));
  const droplets=drops.length?markup`<div class="dodroplets">${cat(drops.map(d=>markup`<div class="dodrop ${d.status||'up'}" title="${d.name||''}"></div>`))}</div>`
                             :markup`<div class="doidle">no droplets provisioned — DO phase runs after hardware testing</div>`;
  put(host, markup`<div class="dostats">
      <div class="dostat"><div class="dov">$${nf(cloud.credit_usd-(cloud.used_usd||0),2)}</div><div class="dol">credit of $${nf(cloud.credit_usd)}</div></div>
      <div class="dostat"><div class="dov">${nf(drops.length)}/${nf(lim)}</div><div class="dol">droplets active</div></div>
      <div class="dostat"><div class="dov">${cloud.region||'—'}</div><div class="dol">region</div></div>
    </div>
    <div class="doconfigs">${configs}</div>${droplets}`);
}

/* ---------- encrypted communication pathways ---------- */
function comms(c){
  const host=document.getElementById("commspanel");
  if(!c||!c.legs||!c.legs.length){put(host, markup`<div class="await">awaiting pathway measurement</div>`);return;}
  const max=Math.max(1,...c.legs.map(l=>l.ms||0))*1.15;
  const rowsHtml=cat(c.legs.map(l=>{
    const has=l.ms!=null,w=has?Math.max(3,l.ms/max*100):0;
    const note=l.note?markup`<span class="cnote">${l.note}</span>`:'';
    const rateHtml=l.rate!=null?markup`<div class="crate ${l.rate>0?'c-good':'c-soft'}">${l.rate>0?'● ':'○ '}${l.rate}${String(l.name).indexOf('OpenRouter')>=0?' $/h':' /s'} live</div>`:'';
    const reqHtml=l.req!=null?markup`<div class="creq">${Number(l.req).toLocaleString()} total</div>`:'';
    return markup`<div class="crow">
      <div class="cinfo"><span class="cname">${l.name}</span><span class="cenc">🔒 ${l.enc}</span>${note}</div>
      <div class="ctrack"><div class="cbar ${has?'bg-good':'bg-dim'}" data-w="${nf(w,0)}"></div></div>
      <div class="cval ${has?'c-ink':'c-dim'}">${has?l.ms+' ms':'not wired'}${rateHtml}${reqHtml}</div></div>`;
  }));
  put(host, markup`<div class="comms">${rowsHtml}</div>`);
  dyn(host);
}

/* ---------- issue lifecycle (uncovered -> fixed -> re-verified) ---------- */
const ISTAGES=["opened","fixing","code-review","sec-review","merged","recompiled","redeployed","re-tested","verified"];
function issues(list){
  const host=document.getElementById("issuespanel");
  if(!list||!list.length){put(host, markup`<div class="await">no issues uncovered yet · capture → fix → re-verify pipeline armed</div>`);return;}
  const items=cat(list.map(it=>{
    const si=ISTAGES.indexOf(it.stage);
    const pipe=cat(ISTAGES.map((s,i)=>markup`<span class="pstage ${i<si?'done':i===si?'cur':''}"><em>${s}</em></span>`));
    const done=it.stage==="verified";
    const note=it.note?markup`<div class="inote">${it.note}</div>`:'';
    return markup`<div class="issue">
      <div class="ihead"><a href="https://github.com/alphaonedev/ai-memory-mcp/issues/${encodeURIComponent(String(it.num))}" target="_blank" rel="noopener">#${it.num}</a>
        <span class="ititle">${it.title}</span><span class="istage ${done?'ok':''}">${it.stage}</span></div>
      <div class="pipe">${pipe}</div>${note}</div>`;
  }));
  put(host, markup`<div class="issues">${items}</div>`);
}

/* ---------- configuration under test (TOML, syntax-highlighted) ---------- */

function agentsPanel(list, asOf, stale){
  const host=document.getElementById("agentsPanel"); if(!host) return;
  if(!list||!list.length){ host.textContent="no agent data in this state file"; return; }
  // "gone" must NOT render like "idle": idle says the lane could wake up, gone says a human has
  // to relaunch it. Falling through to the soft colour would have hidden exactly that difference.
  const col={building:"c-good",active:"c-good",idle:"c-soft",stopped:"c-bad",unreachable:"c-bad",gone:"c-bad"};
  // "idle" with no duration cannot tell a lane between tasks from a lane that has stopped, and an
  // owned-but-stalled item hides inside the owned count. quiet_min = minutes since that lane last
  // wrote a file. Branch age was measured and REJECTED as the signal: lanes work in worktrees, so a
  // working lane can show a two-day-old branch.
  const quiet=m=>{
    if(m===null||m===undefined) return markup`<span class="c-soft">not measured</span>`;
    const c = m>=120 ? "c-bad" : (m>=45 ? "c-warn" : "c-soft");
    const t = m<1 ? "just now" : (m<60 ? m+"m ago" : Math.floor(m/60)+"h "+(m%60)+"m ago");
    return markup`<span class="${c}">${t}</span>`;
  };
  const rows=cat(list.map(a=>markup`<tr><td>${a.node}</td><td><code>${a.agent}</code></td><td>${a.model}</td><td>${a.sector}</td><td class="stcell ${col[a.state]||"c-soft"}">${a.state}</td><td>${quiet(a.quiet_min)}</td></tr>`));
  put(host, markup`<table class="agents"><thead><tr><th>node</th><th>agent</th><th>model</th><th>sector of work</th><th>state</th><th>last wrote</th></tr></thead><tbody>${rows}</tbody></table><div class="ringsub mt6">node, state and last-wrote measured live; sector maintained by the conductor, <b${stale?STALEATTR:''}>${asOf?("as of "+asOf+(stale?" — STALE (older than 7 days)":"")):"no dated evidence"}</b>. "last wrote" is the newest file mtime under that lane's scratch directory &mdash; a lane doing work writes logs. It is not available for f1, which is a separate host.</div>`);
}
function tomlLine(line){
  if(/^\s*#/.test(line)) return markup`<span class='c'>${line}</span>`;
  const parts=[]; let rest=line;
  let m=rest.match(/^(\s*)(\[[^\]]+\])/);
  if(m){ parts.push(m[1], markup`<span class='h'>${m[2]}</span>`); rest=rest.slice(m[0].length); }
  else { m=rest.match(/^(\s*)([A-Za-z0-9_]+)(\s*=\s*)/); if(m){ parts.push(m[1], markup`<span class='k'>${m[2]}</span>`, m[3]); rest=rest.slice(m[0].length); } }
  const re=/("[^"]*")|(\s#.*$)/g; let last=0, hit;
  while((hit=re.exec(rest))){
    parts.push(rest.slice(last,hit.index));
    parts.push(hit[1]?markup`<span class='s'>${hit[1]}</span>`:markup`<span class='c'>${hit[2]}</span>`);
    last=re.lastIndex;
  }
  parts.push(rest.slice(last));
  return cat(parts);
}
function configPanel(cfg){
  const host=document.getElementById("cfgpre");
  if(!cfg){host.textContent="—";return;}
  put(host, cat(String(cfg).split("\n").map(tomlLine),"\n"));
}

/* ---------- north-star pillar gauges (derived from measured dimensions) ---------- */
const PILLARS=[
  {name:"Data integrity", keys:["feature coverage","regression","experiential"]},
  {name:"Security", keys:["cert posture","cross-host","red-team"]},
  {name:"Performance", keys:["capacity","scaling"]},
  {name:"Reliability", keys:["ci @","a2a choreographies","continuity","do config"]}
];
function renderPillars(dims){
  const host=document.getElementById("pillars");
  const cells=PILLARS.map(p=>{const mine=dims.filter(d=>p.keys.some(k=>d.n.toLowerCase().includes(k)));
    const green=mine.filter(d=>d.s==="done").length,tot=mine.length||1;return {name:p.name,green,tot,frac:green/tot};});
  if(host.childElementCount!==cells.length){host.textContent=""; cells.forEach((c,i)=>{
    const b=el("div","pgauge"); put(b, markup`<div class="pname">${c.name}</div><svg width="100" height="58" viewBox="0 0 100 58" id="pg${nf(i)}"></svg><div class="psub" id="pgs${nf(i)}"></div>`);
    host.appendChild(b);});}
  cells.forEach((c,i)=>{const pct=Math.round(c.frac*100),r=38,cx=50,cy=50,circ=Math.PI*r,off=circ*(1-c.frac);
    const color=c.frac>=1?"var(--good)":c.frac>0?"var(--run)":"var(--dim)";
    const arcD=()=>pd([["M",cx-r,cy],["A",r,r,0,"0","1",cx+r,cy]]);
    put(document.getElementById("pg"+i), cat([
      omit(()=>markup`<path d="${arcD()}" fill="none" stroke="var(--line)" stroke-width="8" stroke-linecap="round"/>`),
      omit(()=>markup`<path d="${arcD()}" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${sn(circ,1)}" stroke-dashoffset="${sn(off,1)}"/>`),
      omit(()=>markup`<text x="${sn(cx)}" y="${sn(cy-7)}" text-anchor="middle" font-size="19" font-weight="700" fill="var(--ink)" font-family="var(--disp)">${nf(pct)}%</text>`)]));
    document.getElementById("pgs"+i).textContent=c.green+" / "+c.tot+" validated";});
}
/* ---------- federation topology ---------- */
function federation(f){
  const host=document.getElementById("fedchart"); f=f||{};
  if(!f.legs){put(host, markup`<div class="await">no data<br>· no federation measurement in this state ·</div>`);return;}
  // the THREE encrypted legs of ai-memory data-in-transit (status from state, defaults operational)
  const legs=f.legs||[
    {enc:"mTLS",             label:"agent → daemon",     status:"operational", up:true},
    {enc:"verify-full TLS",  label:"daemon → PostgreSQL",status:"operational", up:true},
    {enc:"mTLS federation",  label:"node ↔ node",        status:"9/9 A2A",     up:true}
  ];
  const W=460,H=224;
  const N={
    agents:{x:58,y:112,label:"Agents",sub:"GLM swarm"},
    daemon:{x:212,y:74,label:"ai-memory",sub:"f2 daemon"},
    pg:{x:402,y:74,label:"PG · AGE",sub:"pgvector"},
    peer:{x:212,y:170,label:"ai-memory",sub:"f1 peer"}
  };
  // leg i -> [from,to] mapping onto the topology
  const MAP=[["agents","daemon"],["daemon","pg"],["daemon","peer"]];
  const links=[],pulses=[],badges=[];
  MAP.forEach((pair,i)=>{
    const L=legs[i]||{}; const p=N[pair[0]],q=N[pair[1]]; const up=L.up!==false;
    const c=up?'var(--good)':'var(--bad)'; const mx=(p.x+q.x)/2, my=(p.y+q.y)/2;
    links.push(omit(()=>markup`<line x1="${sn(p.x)}" y1="${sn(p.y)}" x2="${sn(q.x)}" y2="${sn(q.y)}" stroke="${c}" stroke-width="2" opacity=".6"/>`));
    if(up&&window.__RUN===true) pulses.push(omit(()=>markup`<circle r="3" fill="${c}"><animateMotion dur="${sn(1.4+i*0.35,2)}s" repeatCount="indefinite" path="${pd([["M",p.x,p.y],["L",q.x,q.y]])}"/></circle>`));
    const off=(pair[1]==='pg')?-16:(pair[1]==='peer')?0:-15;
    badges.push(cat([
      omit(()=>markup`<g transform="translate(${sn(mx,0)},${sn(my,0)})"><rect x="-12" y="-11" width="24" height="22" rx="6" fill="var(--panel)" stroke="${c}"/><text y="4" text-anchor="middle" font-size="11">🔒</text></g>`),
      omit(()=>markup`<text x="${sn(mx,0)}" y="${sn(my+off-11,0)}" text-anchor="middle" font-size="8.5" fill="${c}" font-family="var(--mono)" font-weight="600">${L.enc||''}</text>`),
      omit(()=>markup`<text x="${sn(mx,0)}" y="${sn(my+16,0)}" text-anchor="middle" font-size="8" fill="var(--soft)" font-family="var(--mono)">${L.status||''}</text>`)]));
  });
  const nodes=cat(Object.values(N).map(nd=>omit(()=>markup`<g transform="translate(${sn(nd.x)},${sn(nd.y)})">
    <circle r="25" fill="none" stroke="var(--good)" stroke-width="1.5" opacity="${window.__RUN===true?'.28':'0'}"><animate attributeName="r" from="25" to="33" dur="2.6s" repeatCount="indefinite"/><animate attributeName="opacity" from=".28" to="0" dur="2.6s" repeatCount="indefinite"/></circle>
    <circle r="25" fill="var(--panel2)" stroke="var(--good)" stroke-width="2"/>
    <text y="-2" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--ink)" font-family="var(--disp)">${nd.label}</text>
    <text y="9" text-anchor="middle" font-size="7.5" fill="var(--soft)" font-family="var(--mono)">${nd.sub}</text></g>`)));
  const opCount=legs.filter(l=>l.up!==false).length;
  const legend=omit(()=>markup`<text x="10" y="${sn(H-7)}" font-size="9" fill="var(--good)" font-family="var(--mono)">🔒 ${nf(opCount)}/3 encrypted legs operational · all data in transit encrypted</text>`);
  put(host, omit(()=>markup`<svg viewBox="0 0 ${sn(W)} ${sn(H)}" width="100%">${cat(links)}${cat(pulses)}${cat(badges)}${nodes}${legend}</svg>`));
}
/* ---------- A2A message flow ---------- */
function a2aflow(a){
  const host=document.getElementById("a2apanel");
  if(!a||a.total==null){put(host, markup`<div class="await">no data<br>· no A2A measurement in this state ·</div>`);return;}
  const types=Object.entries(a.types||{}),max=Math.max(1,...types.map(([k,v])=>v||0));
  const bars=cat(types.map(([k,v])=>markup`<div class="a2arow">
      <div class="a2ahead"><span>${k}</span><span class="c-ink">${fmt(v)}</span></div>
      <div class="a2atrack"><div class="a2afill" data-w="${nf(v/max*100,0)}"></div></div></div>`));
  put(host, markup`<div class="a2atop">
     <span class="a2arate">${fmt(a.rate)}</span>
     <span class="a2asub">msg/s · ${fmt(a.total)} total</span></div>${bars}`);
  dyn(host);
}
/* ---------- startup / boot latency ---------- */
const BOOT_BG=['bg-good','bg-run','bg-viol','bg-warn'], BOOT_FG=['c-good','c-run','c-viol','c-warn'];
function bootPanel(b){
  const host=document.getElementById("bootpanel");
  if(!b||b.mcp_ready_ms==null){put(host, markup`<div class="await">awaiting boot measurement</div>`);return;}
  const phases=b.phases||[],tot=phases.reduce((s,p)=>s+p.ms,0)||b.mcp_ready_ms;
  const segs=cat(phases.map((p,i)=>markup`<i class="${BOOT_BG[i%BOOT_BG.length]}" data-w="${nf(p.ms/tot*100,1)}"></i>`));
  const rows=cat(phases.map((p,i)=>markup`<div class="bootrow"><span class="${BOOT_FG[i%BOOT_FG.length]}">■</span><span class="bootname">${p.name}</span><b>${p.ms} ms</b></div>`));
  put(host, markup`<div class="boot">
    <div class="bootbig"><span class="n">${b.mcp_ready_ms}</span><span class="u">ms to MCP-ready</span>
      <span class="lb">cold ${b.cold_ms!=null?b.cold_ms+'ms':'—'}<br>warm ${b.warm_ms!=null?b.warm_ms+'ms':'—'}</span></div>
    <div class="bootbar">${segs}</div>
    ${rows}
    <div class="bootrow"><span class="bootnote">${b.note||'backfill runs in background — never blocks init (#3329)'}</span></div></div>`);
  dyn(host);
}
/* ---------- operation latency ---------- */
function opLatency(ops){
  const host=document.getElementById("oplatpanel");
  if(!ops||!ops.length){put(host, markup`<div class="await">awaiting bench<br>· store · recall · search · embed · rerank · sign ·</div>`);return;}
  const max=Math.max(...ops.map(o=>o.p99))*1.1||1;
  const rows=cat(ops.map(o=>markup`<div class="row"><span class="nm">${o.op}</span>
     <span class="track"><i class="p99" data-w="${nf(o.p99/max*100,0)}"></i><i class="p95" data-w="${nf(o.p95/max*100,0)}"></i><i class="p50" data-w="${nf(o.p50/max*100,0)}"></i></span>
     <span class="vv">${o.p50}/${o.p95}/${o.p99}</span></div>`));
  put(host, markup`<div class="oplat">${rows}<div class="oplegend">ms · p50 / p95 / p99 · green p50 · blue p95 · amber p99</div></div>`);
  dyn(host);
}


function aiUsage(mount, u){
  const host=document.getElementById(mount); if(!host) return;
  if(!u){put(host, markup`<div class="await">awaiting usage snapshots</div>`);return;}
  const rows=cat((u.runs||[]).slice().sort((a,b)=>(b.ts||"").localeCompare(a.ts||"")).slice(0,8).map(r=>markup`<div class="row airow"><span>${r.run}</span><span>${r.duration_s!=null?r.duration_s+'s':''}</span><span class="${r.cost_usd==null?'c-soft':'c-ink'}">${r.cost_usd==null?'n/a':'$'+nf(r.cost_usd,3)}</span></div>`));
  put(host, markup`<div class="aihead">today <b class="c-ink">$${nf(u.usage_today_usd||0,2)}</b> · week $${nf(u.usage_week_usd||0,2)} · lifetime $${nf(u.usage_total_usd||0,2)} of ${u.credits_total_usd} credits · as of ${String(u.asOf||'').replace('T',' ')}</div>${rows}<div class="aifoot">${u.note||''}</div>`);
}

/* ---------- top-level render ---------- */
function renderAll(D){
  D=D||{}; window.__D=D; const dims=D.dimensions||[];
  window.__RUN=(D.run_active===true);
  const _t=(id,v)=>{const e=document.getElementById(id); if(e) e.textContent=v;};
  _t("titlemode", window.__RUN?"Live":"Last run");
  _t("swarmPre", window.__RUN?"Live":"Last run");
  _t("swarmAnim", window.__RUN?"animated links = data moving now":"no animation: no run is active");
  _t("swarmLegend", window.__RUN?"green box / animated link = data moving now":"no run is active: nothing is moving");
  _t("tpcap", window.__RUN?"ai-memory operations / second — live stream":"ai-memory operations / second — last recorded series");
  _t("feedTitle", window.__RUN?"Live event feed":("Event feed — newest event "+(D.newest_event||"unknown")+", from the last run"));
  const R=D.roles||{}; _t("rolesline", R.line?("roles: "+R.line):"roles: not in state"); _t("fixflow", R.fix_flow||"roles: not in state");
  const rb=document.getElementById("runbanner");
  if(rb){ if(window.__RUN){rb.style.display="none";} else { rb.style.display="block";
    rb.textContent="No campaign run is active. Last run ended "+(D.last_run_ended||"on an unknown date")+"; the figures below are from that run."; } }
  document.getElementById("tip").textContent=D.tip||"—";
  document.getElementById("phase").textContent=D.phase||"—";
  const _S=(f)=>{try{f()}catch(e){if(window.console)console.error('panel render error:',e)}};
  _S(()=>renderKpis(D.kpis||[]));
  _S(()=>renderPillars(dims));
  _S(()=>federation(D.federation)); _S(()=>a2aflow(D.a2a));
  _S(()=>bootPanel(D.boot)); _S(()=>opLatency(D.oplatency));
  _S(()=>hardwareMonitor(D.hardware)); _S(()=>cloudMonitor(D.cloud));
  _S(()=>comms(D.comms)); _S(()=>issues(D.issues));
  _S(()=>agentsPanel(D.agents, D.agentsAsOf, D.agentsStale===true));
  _S(()=>campaignsPanel(D.ga_campaigns));
  _S(()=>configPanel(D.config));
  const ns=D.swarm||{};
  _S(()=>{const j=JSON.stringify(ns);if(j!==swarmState){swarmState=j;swarmFabric(ns);}});
  _S(()=>areaChart("tpchart", D.throughputSeries, "ops", "ops/s"));
  _S(()=>lineChart("capchart", D.capacity, "agents","ops","concurrent NHIs","ops/s", true));
  _S(()=>lineChart("wpchart", D.writePath, "agents","ops","concurrent NHIs (signed store)","ops/s", true));
  _S(()=>lineChart("scalechart", D.scaling, "modules","agents","modules (federation)","sustained agents", false));
  _S(()=>donut("covchart", D.coverage));
  _S(()=>latency("latchart", D.latency));
  _S(()=>aiUsage("aiusage", D.aiUsage));
  _S(()=>security("secpanel", D.security));
  _S(()=>continuity("cycpanel", D.continuity));
  _S(()=>board(dims)); _S(()=>feed(D.events||[]));
  // a non-list `dimensions` is a malformed state: skip the ring (placeholder stays); poll() catches the throw, sets stateBad and the badge reads offline
  if(!Array.isArray(dims)) throw new TypeError("state.dimensions is not a list");
  // 2026-09-18: the ring shows the V&V VALIDATED share (items measured green / items in scope), not the
  // count of fully-green dimensions - a dimension only turns green when its LAST item lands, so the
  // dimension count sat at 1/6 while 160/195 items were validated. The dimension count is the subtitle.
  // 2026-09-19: the ring shows LIVE burn-down, not the V&V share. The V&V ledgers were last
  // produced 2026-09-04 and their denominator predates eleven issues admitted since, including
  // four standards — so a V&V headline reads as current while measuring a surface that no longer
  // exists. Burn-down is recomputed every pass from the queue and GitHub, so it is true today.
  // (rule w: an instrument blind to the state it must report.)
  const kp=l=>(D.kpis||[]).find(k=>k.label===l);
  // 2026-09-29 (tmux-22): the ring looked up "landed on rehearsal", a KPI renamed to "fixed on a branch",
  // so it counted 0 landed and showed closed-only (57%). It now shows the MEASURED "GA readiness" KPI
  // (closed + fixed on release awaiting the tag, over the whole scope) with the stage gates beneath;
  // the fallback uses the current KPI names.
  const ga=kp("GA readiness"), gates=kp("GA stage gates");
  const closed=kp("blockers closed"), landed=kp("fixed on a branch")||kp("landed on rehearsal");
  const burnDone=(closed?closed.value:0)+(landed?landed.value:0);
  const burnTotal=closed&&closed.of?closed.of:1;
  const vnum=ga?ga.value/100:(burnTotal?burnDone/burnTotal:0);
  // 2026-10-07: three-segment ring (shipped on release / fixed on carrier + ticked / remaining) over one denominator,
  // from state.ga; falls back to the single-arc ring when an older state.json has no ga block.
  const G=D.ga;
  const r=41,c=2*Math.PI*r;
  const ringBase=omit(()=>markup`<circle cx="47" cy="47" r="${sn(r)}" fill="none" stroke="var(--line)" stroke-width="8"/>`);
  if(G&&G.denom){
    const sh=G.shipped/G.denom, fx=(G.fixed+G.ticked)/G.denom;
    const arc=(from,len,col)=>len<=0?cat([]):omit(()=>markup`<circle cx="47" cy="47" r="${sn(r)}" fill="none" stroke="${col}" stroke-width="8" stroke-dasharray="${sn(Math.max(0,c*len-1),1)} ${sn(c,1)}" stroke-dashoffset="${sn(-c*from,1)}" transform="rotate(-90 47 47)"/>`);
    document.getElementById("ringpct").textContent=nf(G.ready_pct,1)+"%";
    document.getElementById("ringcnt").textContent="GA readiness · on release "+nf(G.release_pct,1)+"% · shipped "+nf(G.shipped)+" · carrier "+nf(G.fixed)+" · remaining "+nf(G.remaining)+(gates?" · gates "+nf(gates.value)+"/"+nf(gates.of):"");
    put(document.getElementById("ringsvg"), cat([ringBase, arc(0,sh,"var(--good)"), arc(sh,fx,"var(--run)")]));
    return;
  }
  document.getElementById("ringpct").textContent=(ga?nf(ga.value,1):Math.round(vnum*100))+"%";
  document.getElementById("ringcnt").textContent="GA readiness · "+burnDone+"/"+burnTotal+" resolved"+(gates?" · gates "+nf(gates.value)+"/"+nf(gates.of):"");
  const off=c*(1-vnum);
  put(document.getElementById("ringsvg"), cat([ringBase,
    omit(()=>markup`<circle cx="47" cy="47" r="${sn(r)}" fill="none" stroke="var(--good)" stroke-width="8" stroke-linecap="round" stroke-dasharray="${sn(c,1)}" stroke-dashoffset="${sn(off,1)}" transform="rotate(-90 47 47)"/>`)]));
}

/* ---------- live poll ---------- */
let lastGood=0, lastUpdated=null;
function setLive(state){
  const b=document.getElementById("livebadge"),t=document.getElementById("livetext");
  b.className="live"+(state==="stale"?" stale":state==="err"?" err":"");
  if(state==="err"){t.textContent="offline — retrying";return;}
  const stamp=lastUpdated?new Date(lastUpdated).getTime():0;
  if(!Number.isFinite(stamp)){b.className="live stale";t.textContent="stale · state time unknown";return;}
  const ago=lastUpdated?Math.max(0,Date.now()-stamp):0;
  const m=Math.floor(ago/60000),h=Math.floor(m/60);
  const rel=h>0?h+"h "+(m%60)+"m ago":m>0?m+"m ago":Math.floor(ago/1000)+"s ago";
  const old=ago>30*60000; b.className="live"+(old?" stale":"");
  t.textContent=(old?"stale · ":"connected · ")+"state generated "+rel;
}
// stateBad: the last state.json arrived but could not be used (unparsable body, or renderAll rejected its shape,
// e.g. a non-list `dimensions`). The badge then reads offline at once, not after the 15 s network grace, and the
// 1 s tick does not repaint it "connected" from lastGood alone. A network failure keeps the 15 s grace.
let stateBad=false;
async function poll(){
  let res;
  try{
    res=await fetch("/state.json?t="+Date.now(),{cache:"no-store"});
    if(!res.ok)throw new Error("http "+res.status);
  }catch(e){ if(Date.now()-lastGood>15000)setLive("err"); return; }
  try{
    const D=await res.json(); lastUpdated=D.lastUpdated||null;
    renderAll(D); stateBad=false; lastGood=Date.now(); setLive("live");
  }catch(e){ stateBad=true; setLive("err"); }
}
function tick(){ if(lastGood||stateBad)setLive(stateBad||Date.now()-lastGood>15000?"err":"live"); }
[["northstar","northstar-state.json"],["security","security-state.json"],["mcp","mcp-tools-state.json"],["swarm","swarm-tools-state.json"],["datatier","datatier-state.json"],["federation","federation-state.json"]].forEach(([k,f])=>fetch("/"+f+"?t="+Date.now(),{cache:"no-store"}).then(r=>r.json()).then(d=>{const e=document.getElementById("nav-"+k);if(e){const p=d.pct!=null?d.pct:Math.round((d.validated+d.failclosed)/d.total*100);e.textContent=nf(p)+"%";e.style.color=p>=100?"var(--good)":"var(--warn)";}}).catch(()=>{}));
poll(); setInterval(poll,3000);
setInterval(tick,1000);
function toggleCardFS(card){
  // Fullscreen API when available (Esc exits natively); otherwise a fixed overlay with Esc/click-to-close.
  const canFS=!!(card.requestFullscreen||card.webkitRequestFullscreen);
  if(canFS){
    try{ if(document.fullscreenElement===card){ document.exitFullscreen(); } else { (card.requestFullscreen||card.webkitRequestFullscreen).call(card); } return; }catch(_){}
  }
  const on=card.classList.toggle("maximized");
  document.body.style.overflow=on?"hidden":"";
}
function toggleFS(){ toggleCardFS(document.getElementById("swarmwrap")); }
const isFabricBtn=b=>b.id==="swarmfs";
function installCardFS(){
  document.querySelectorAll(".card").forEach(card=>{
    if(card.querySelector(":scope > h4 .fsbtn, :scope > .fsbtn")) return;
    const b=document.createElement("button"); b.className="fsbtn"; b.title="expand this card to full screen (Esc to close)"; b.textContent="⛶";
    b.addEventListener("click",(ev)=>{ev.stopPropagation(); toggleCardFS(card);});
    const h=card.querySelector(":scope > h4"); if(h){ h.appendChild(b); } else { b.classList.add("fsabs"); card.style.position=card.style.position||"relative"; card.prepend(b); }
  });
  const fabricBtn=document.getElementById("swarmfs");
  if(fabricBtn) fabricBtn.addEventListener("click",toggleFS);
  document.querySelectorAll(".card .fsbtn").forEach(b=>{ if(isFabricBtn(b)){ b.textContent="⛶ full screen"; } });
  document.addEventListener("keydown",e=>{ if(e.key==="Escape"){ document.querySelectorAll(".card.maximized").forEach(c=>c.classList.remove("maximized")); document.body.style.overflow=""; } });
  document.addEventListener("fullscreenchange",()=>{ const b=document.querySelectorAll(".card .fsbtn"); b.forEach(x=>x.textContent=(document.fullscreenElement&&x.closest(".card")===document.fullscreenElement)?"⤡ exit":(isFabricBtn(x)?"⛶ full screen":"⛶")); });
}
installCardFS();
