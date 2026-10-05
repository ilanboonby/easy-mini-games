"use strict";
/* Moteur d'aventure textuelle partagé par tous les jeux de Port-443.
   Un jeu = un objet enregistré dans GAMES (voir games/*.js). */

/* ============ Utilitaires ============ */
function modpow(b, e, m) {
  b = BigInt(b) % BigInt(m); e = BigInt(e); m = BigInt(m);
  let r = 1n;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return Number(r);
}
const gcd = (a, b) => b ? gcd(b, a % b) : a;
const isPrime = n => { if (n < 2) return false; for (let i = 2; i * i <= n; i++) if (n % i === 0) return false; return true; };
const norm = s => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/['’\-]/g, " ").replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim();
const ART = new Set(["le", "la", "les", "l", "un", "une", "des", "du", "de", "d", "mon", "ma", "mes", "ce", "cette", "ces", "en", "et"]);
const SEP = new Set(["sur", "avec", "a", "au", "aux", "vers", "dans", "pour", "contre", "depuis", "par"]);
const b64u = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => { try { return decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/")))); } catch (e) { return null; } };

function sha256(str) {
  const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  const bytes = Array.from(new TextEncoder().encode(str));
  const bits = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  const hi = Math.floor(bits / 2 ** 32), lo = bits >>> 0;
  bytes.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255, (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let i = 0; i < bytes.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = (bytes[i + 4 * t] << 24) | (bytes[i + 4 * t + 1] << 16) | (bytes[i + 4 * t + 2] << 8) | bytes[i + 4 * t + 3];
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[t] + w[t]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    const v = [a, b, c, d, e, f, g, h];
    H = H.map((x, j) => (x + v[j]) | 0);
  }
  return H.map(v => (v >>> 0).toString(16).padStart(8, "0")).join("");
}

/* ============ État ============ */
const GAMES = {};
let G = null, S = null;
const f = () => S.f;
const SAVE_PREFIX = "p443:";
function fresh() { return { room: G.start, inv: [], f: {}, notes: [], a: null, hobj: "", hl: 0, figs: [] }; }
function readSave(id) { try { const v = JSON.parse(localStorage.getItem(SAVE_PREFIX + id) || "null"); return v && v.room ? v : null; } catch (e) { return null; } }
function save() { try { localStorage.setItem(SAVE_PREFIX + G.id, JSON.stringify(S)); } catch (e) { /* sans sauvegarde */ } }
function wipe() { try { localStorage.removeItem(SAVE_PREFIX + G.id); } catch (e) { /* idem */ } }

/* ============ Sortie ============ */
const logEl = document.getElementById("log");
function fmt(t) {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`(.+?)`/g, (m, c) => `<code class="cmd" tabindex="0" role="button">${c}</code>`);
}
function out(t, cls) {
  const p = document.createElement("p"); p.className = cls || "";
  p.innerHTML = fmt(t); logEl.append(p); logEl.scrollTop = logEl.scrollHeight;
}
const say = (who, t) => out(`**${who}** : « ${t} »`, "npc");
// bloc de code (requêtes, jetons...) sans interprétation du balisage
function code(t) {
  const p = document.createElement("p"); p.className = "codeblock"; p.textContent = t;
  logEl.append(p); logEl.scrollTop = logEl.scrollHeight;
}
function note(id) {
  if (S.notes.includes(id)) return;
  S.notes.push(id);
  out(`✎ Nouvelle entrée dans ton carnet : **${G.notes[id][0]}**  (\`carnet\` pour relire)`, "note");
}

/* ============ Schémas SVG ============ */
const T = (x, y, t, c, a) => `<text x="${x}" y="${y}" text-anchor="${a || "middle"}" class="f-t ${c || ""}">${t}</text>`;
const R = (x, y, w, h, c) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="6" class="f-box ${c || ""}"/>`;
const AR = (x1, y1, x2, y2, c, both) => `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="f-ln ${c || ""}" marker-end="url(#fa)"${both ? ' marker-start="url(#fa)"' : ""}/>`;
const LN = (x1, y1, x2, y2, c) => `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="f-ln ${c || ""}"/>`;
const LOCK = (x, y, c) => `<g class="f-lock ${c}"><path d="M${x + 4},${y} v-6 a8,8 0 0 1 16,0 v6"/><rect x="${x}" y="${y}" width="24" height="18" rx="3"/></g>`;
const KEY = (x, y, c) => `<g class="f-key ${c}"><circle cx="${x}" cy="${y}" r="6"/><path d="M${x + 6},${y} h20 m-5,0 v6 m-6,-6 v5"/></g>`;
const SVG = (h, label, body) => `<svg viewBox="0 0 420 ${h}" role="img" aria-label="${label}">${body}</svg>`;

function fig(name, arg) {
  const d = G.figs[name](arg);
  const el = document.createElement("figure"); el.className = "fig";
  el.innerHTML = d.svg + `<figcaption>${d.cap.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</figcaption>`;
  logEl.append(el); logEl.scrollTop = logEl.scrollHeight;
  if (!S.figs.includes(name)) S.figs.push(name);
}
function schemaCmd(txt) {
  const have = S.figs || [];
  if (!txt) {
    out(have.length ? "Schémas débloqués : " + have.map(n => "`schema " + n + "`").join(" · ") : "Aucun schéma débloqué pour l'instant : ils apparaissent quand tu réussis une étape.", "sys"); return;
  }
  const name = Object.keys(G.figs).find(n => n.startsWith(txt) || txt.startsWith(n) || ((G.figAlias || {})[n] || []).some(a => a.startsWith(txt) || txt.startsWith(a)));
  if (!name || !have.includes(name)) { out("Ce schéma n'est pas (encore) débloqué. `schema` liste ceux que tu as.", "err"); return; }
  if (G.refig) G.refig(name); else fig(name);
}

/* ============ Entités ============ */
function inScope() {
  const ids = G.rooms[S.room].ents.filter(id => !S.inv.includes(id) && (!G.ents[id].vis || G.ents[id].vis()));
  return [...S.inv, ...ids];
}
function match(r, ids, filter) {
  if (!r) return { none: true };
  const rt = r.split(" ");
  let best = [], bestScore = 0;
  for (const id of ids) {
    const e = G.ents[id]; if (!e || (filter && !filter(e))) continue;
    let sc = 0;
    for (const n of e.names) {
      const nt = norm(n).split(" ");
      if (!rt.every(t => nt.some(u => u.startsWith(t)))) continue;
      sc = Math.max(sc, norm(n) === r ? 3 : rt.length === nt.length ? 2 : 1);
    }
    if (sc > bestScore) { best = [id]; bestScore = sc; } else if (sc === bestScore && sc > 0) best.push(id);
  }
  if (!best.length) return { none: true };
  if (best.length > 1) return { ambig: best };
  return { id: best[0] };
}
function resolve(r, filter) {
  const m = match(r, inScope(), filter);
  if (m.id) return m.id;
  if (m.ambig) out(`Précise : ${m.ambig.map(i => G.ents[i].names[0]).join(" ou ")} ?`, "err");
  else out(r ? `Tu ne vois pas « ${r} » ici.` : "De quoi parles-tu ?", "err");
  return null;
}
const give = id => { if (!S.inv.includes(id)) S.inv.push(id); };
const drop = id => { S.inv = S.inv.filter(x => x !== id); };

/* ============ Lieux ============ */
function describe() {
  const r = G.rooms[S.room];
  out(r.name, "title");
  out(r.desc());
  const seen = r.ents.filter(id => !S.inv.includes(id) && (!G.ents[id].vis || G.ents[id].vis()) && G.ents[id].label).map(id => G.ents[id].label);
  if (seen.length) out("Tu vois : " + seen.join(", ") + ".", "sys");
  out("Sorties : " + Object.entries(r.exits).map(([d, t]) => `${d} (${G.rooms[t].short || G.rooms[t].name})`).join(", ") + ".", "sys");
  renderBar();
}
const DIRS = { n: "nord", nord: "nord", s: "sud", sud: "sud", e: "est", est: "est", o: "ouest", ouest: "ouest", w: "ouest", h: "haut", haut: "haut", b: "bas", bas: "bas" };
function move(target) {
  const r = G.rooms[S.room];
  let dest = null;
  if (DIRS[target]) dest = r.exits[DIRS[target]];
  else for (const id of Object.values(r.exits)) if (G.rooms[id].alias.some(a => norm(a) === target || (norm(a).startsWith(target) && target.length >= 3))) dest = id;
  if (!dest) { out(target ? "Tu ne peux pas aller par là." : "Où ça ? (nord, sud, est, ouest)", "err"); return; }
  if (G.gate && G.gate(dest)) return;
  S.room = dest; describe();
}

/* ============ Indices ============ */
function hint() {
  const k = G.objective();
  if (S.hobj !== k) { S.hobj = k; S.hl = 0; }
  const h = G.hints[k]();
  out("Indice : " + h[Math.min(S.hl, 1)], "sys");
  if (S.hl === 0 && h[1]) out("Tape `indice` encore pour une indication plus précise.", "sys");
  S.hl++;
}

/* ============ Calculatrice de poche ============ */
function calc(expr) {
  const e = expr.replace(/,/g, ".").trim();
  let m;
  if ((m = e.match(/^(\d+)\s*\^\s*(\d+)\s*mod(?:ulo)?\s*(\d+)$/))) {
    if (+m[3] === 0) { out("Modulo zéro : impossible.", "err"); return; }
    out(`Le boulier cliquette : ${m[1]}^${m[2]} mod ${m[3]} = **${modpow(m[1], m[2], m[3])}**`, "ok");
  } else if ((m = e.match(/^(\d+)\s*\^\s*(\d+)$/)) && +m[2] <= 60) {
    out(`Le boulier cliquette : ${m[1]}^${m[2]} = **${BigInt(m[1]) ** BigInt(m[2])}**`, "ok");
  } else if (/^[\d\s+\-*/().%]+$|^[\d\s+\-*/().]+\s*mod\s*\d+$/i.test(e)) {
    let v; try { v = Function('"use strict"; return (' + e.replace(/\bmod\b/gi, "%") + ")")(); } catch (x) { v = NaN; }
    out(Number.isFinite(v) ? `Le boulier cliquette : **${Math.round(v * 1e6) / 1e6}**` : "Le boulier ne comprend pas cette opération.", Number.isFinite(v) ? "ok" : "err");
  } else out("Le boulier connaît : `calc 5^6 mod 23`, ou une opération comme `calc 3*7 mod 20`.", "err");
}

/* ============ Verbes ============ */
const BASE_VERBS = {
  look: ["regarder", "voir", "l", "observer", "r"], examine: ["examiner", "ex", "x", "inspecter", "lire", "etudier", "verifier"],
  go: ["aller", "va", "go", "marcher", "entrer", "monter", "descendre"], take: ["prendre", "ramasser", "attraper", "saisir"],
  use: ["utiliser", "appliquer", "sceller", "signer", "fermer", "combiner"], talk: ["parler", "discuter", "saluer"],
  give: ["donner", "remettre", "tendre", "offrir", "livrer"], say: ["dire", "repondre", "annoncer", "enoncer"],
  inv: ["inventaire", "inv", "i"], notes: ["carnet", "notes", "codex"], hint: ["indice", "aide moi"], help: ["aide", "help", "commandes", "?"],
  debrief: ["analogies", "debrief", "bilan", "explications"], schema: ["schema", "schemas", "image", "images", "dessin"],
  restart: ["recommencer", "reset"],
};
let VERB_OF = {};
function buildVerbs() {
  VERB_OF = {};
  const all = {};
  for (const [k, arr] of Object.entries(BASE_VERBS)) all[k] = arr.slice();
  for (const [k, v] of Object.entries(G.verbs || {})) all[k] = (all[k] || []).concat(v.words || []);
  for (const [k, arr] of Object.entries(all)) arr.forEach(v => VERB_OF[v] = k);
}
function splitArgs(rest) {
  const i = rest.findIndex(t => SEP.has(t));
  if (i > 0) return [rest.slice(0, i).join(" "), rest.slice(i + 1).join(" ")];
  return [rest.filter(t => !SEP.has(t)).join(" "), ""];
}

const DEF = {
  look(c) { if (!c.rest.length) describe(); else { const id = resolve(c.target); if (id) out(G.ents[id].desc()); } },
  examine(c) {
    if (/^verifier/.test(c.verb) && !c.rest.length) { out("Vérifier quoi ? (`examiner ‹objet›`)", "err"); return; }
    const id = resolve(c.target); if (!id) return;
    if (G.ents[id].onExamine) G.ents[id].onExamine();
    out(G.ents[id].desc());
  },
  go(c) { move(c.target); },
  take(c) {
    const id = resolve(c.target); if (!id) return;
    if (S.inv.includes(id)) out("Tu l'as déjà.", "sys");
    else if (G.ents[id].take) { give(id); out(`Tu prends ${G.ents[id].label}.`, "ok"); }
    else out("Tu ne peux pas emporter ça.", "sys");
  },
  use(c) {
    const [at, bt] = splitArgs(c.rest);
    const a = resolve(at); if (!a) return;
    if (!bt) { out("Utiliser sur quoi ? (`utiliser ‹objet› sur ‹objet›`)", "err"); return; }
    const b = resolve(bt); if (!b) return;
    if (a === b) { out("Ça ne donne rien.", "sys"); return; }
    if (G.use && G.use([a, b].sort().join("+"), a, b) !== false) return;
    out("Ces deux objets n'ont rien à faire ensemble.", "sys");
  },
  talk(c) { const id = resolve(c.target, e => e.npc); if (id) G.talk(id); },
  give(c) {
    if (!c.rest.length) { out("Donner quoi à qui ? (`donner ‹objet› a ‹personne›`)", "err"); return; }
    const [at, bt] = splitArgs(c.rest);
    const item = resolve(at, e => !e.npc); if (!item) return;
    if (!S.inv.includes(item)) { out("Tu ne l'as pas sur toi.", "err"); return; }
    const who = resolve(bt, e => e.npc); if (!who) return;
    if (G.give && G.give(item, who) !== false) return;
    say(G.ents[who].names[0], "Merci, mais je n'en ai pas besoin.");
  },
  say(c) { if (G.say) G.say(c.rest.join(" "), c); else out(c.rest.length ? "Personne ne réagit." : "Dire quoi ?", "sys"); },
  inv() { out(S.inv.length ? "Tu portes : " + S.inv.map(id => G.ents[id].label).join(", ") + "." : "Tu ne portes rien.", "sys"); },
  notes() {
    if (!S.notes.length) { out("Ton carnet est vide : il se remplit à mesure que tu comprends.", "sys"); return; }
    out(`Carnet (${S.notes.length}/${Object.keys(G.notes).length})`, "title");
    S.notes.forEach(id => out(`**${G.notes[id][0]}**\n${G.notes[id][1]}`, "note"));
  },
  hint() { hint(); },
  help() {
    out("Commandes utiles", "title");
    out("`regarder` · `examiner ‹objet›` · `aller ‹direction›` (ou n, s, e, o) · `prendre ‹objet›`\n`utiliser ‹objet› sur ‹objet›` · `parler ‹personne›` · `donner ‹objet› a ‹personne›` · `dire ‹mot›`\n`calc ‹expression›` (calculatrice de poche, ex. calc 5^6 mod 23)\n`inventaire` · `carnet` · `schema` (schémas débloqués) · `indice` · `analogies` (en fin de partie) · `recommencer`" + (G.help ? "\n" + G.help : ""), "sys");
    out("Astuce : les commandes en orange sont cliquables.", "sys");
  },
  debrief() { if (G.isEnd()) G.debrief(); else out("Termine d'abord l'aventure : ce bilan dévoile toutes les astuces du jeu.", "sys"); },
  schema(c) { schemaCmd(c.target); },
  restart(c) {
    if (c.rest[0] === "oui") { wipe(); S = fresh(); if (G.setup) G.setup(); logEl.replaceChildren(); begin(); }
    else out("Cela efface toute ta progression dans ce jeu. Pour confirmer : `recommencer oui`", "err");
  },
};

function exec(raw) {
  const clean = raw.trim(); if (!clean) return;
  out("> " + clean, "you");
  const mc = clean.toLowerCase().match(/^(?:calc|calculer|boulier)\s+(.+)$/);
  if (mc) { calc(mc[1]); save(); return; }
  const toks = norm(clean).split(" ").filter(Boolean);
  let verb = toks[0], rest = toks.slice(1), vlen = 1;
  if (toks.length >= 2 && VERB_OF[toks[0] + " " + toks[1]]) { verb = toks[0] + " " + toks[1]; rest = toks.slice(2); vlen = 2; }
  if (DIRS[verb] && !rest.length) { move(verb); save(); return; }
  rest = rest.filter(t => !ART.has(t));
  const k = VERB_OF[verb];
  if (!k) { out("Je ne comprends pas. Tape `aide` pour la liste des commandes.", "err"); return; }
  const target = rest.filter((t, i) => !SEP.has(t) || i > 0).join(" ").replace(/^(a|au|aux|vers|sur|dans) /, "");
  const ctx = { k, verb, rest, target, raw: clean, rawArg: clean.split(/\s+/).slice(vlen).join(" ") };
  const h = (G.verbs && G.verbs[k] && G.verbs[k].run) || DEF[k];
  const room = S.room;
  h(ctx);
  save(); if (room !== S.room) return; renderBar();
}

/* ============ Interface ============ */
const input = document.getElementById("cmd");
const history = []; let hpos = 0;
function run(c) { history.push(c); hpos = history.length; exec(c); }
function renderBar() {
  const bar = document.getElementById("bar"); bar.replaceChildren();
  if (!G) return;
  const add = (label, cmd, cls) => { const b = document.createElement("button"); b.type = "button"; b.textContent = label; if (cls) b.className = cls; b.addEventListener("click", () => run(cmd)); bar.append(b); };
  Object.entries(G.rooms[S.room].exits).forEach(([d, id]) => add(`${d[0].toUpperCase() + d.slice(1)} · ${G.rooms[id].short || G.rooms[id].name}`, "aller " + d, "go"));
  add("Regarder", "regarder"); add("Inventaire", "inventaire"); add("Carnet", "carnet"); add("Indice", "indice"); add("Aide", "aide");
}
document.getElementById("form").addEventListener("submit", e => { e.preventDefault(); const v = input.value; input.value = ""; if (v.trim() && G) run(v); });
input.addEventListener("keydown", e => {
  if (e.key === "ArrowUp" && history.length) { hpos = Math.max(0, hpos - 1); input.value = history[hpos]; e.preventDefault(); }
  if (e.key === "ArrowDown") { hpos = Math.min(history.length, hpos + 1); input.value = history[hpos] || ""; e.preventDefault(); }
});
logEl.addEventListener("click", e => {
  const c = e.target.closest && e.target.closest("code.cmd"); if (!c) return;
  const t = c.textContent;
  if (t.includes("‹")) { input.value = t.replace(/\s*‹.*$/, "") + " "; input.focus(); } else run(t);
});
logEl.addEventListener("keydown", e => { if ((e.key === "Enter" || e.key === " ") && e.target.classList && e.target.classList.contains("cmd")) { e.preventDefault(); e.target.click(); } });

function begin() {
  G.intro();
  describe();
  out("Commence par `" + G.firstCommand + "`.", "sys");
}

/* ============ Menu et lancement ============ */
const hubEl = document.getElementById("hub"), gameEl = document.getElementById("game"), backBtn = document.getElementById("back");
const headTitle = document.getElementById("headtitle"), headSub = document.getElementById("headsub");
function openGame(id) {
  G = GAMES[id]; S = readSave(id) || null;
  buildVerbs();
  hubEl.hidden = true; gameEl.hidden = false; backBtn.hidden = false;
  headTitle.textContent = G.title.toUpperCase(); headSub.textContent = G.subtitle;
  document.title = G.pageTitle || G.title;
  logEl.replaceChildren();
  if (S) { out("Partie reprise. (`recommencer` pour tout effacer.)", "sys"); describe(); }
  else { S = fresh(); if (G.setup) G.setup(); begin(); }
  save(); input.focus();
}
function showHub() {
  G = null; gameEl.hidden = true; hubEl.hidden = false; backBtn.hidden = true;
  headTitle.textContent = "PORT-443 QUEST"; headSub.textContent = Object.keys(GAMES).length + " aventures pour comprendre la cybersécurité";
  document.title = "Port-443 Quest";
  const cards = document.getElementById("cards"); cards.replaceChildren();
  cards.className = "";
  const THEMES = ["Cryptographie", "Réseau", "Applications web", "Identité et accès", "Logiciel et données", "Cryptographie avancée", "Détection et réponse", "Cloud et mobile", "Systèmes", "Vie privée et IA", "Organisation et gouvernance", "Cas concrets"];
  const THEME_OF = { tls: 0, rsa: 0, hash: 0, cryptomisuse: 0, vpn: 1, dns: 1, firewall: 1, wifi: 1, mailauth: 1, dos: 1, bgp: 1, web: 2, cors: 2, api: 2, session: 2, upload: 2, ssrf: 2, clickjack: 2, oauth: 3, kerberos: 3, mfa: 3, rbac: 3, secrets: 3, supply: 4, diskenc: 4, ransom: 4, pqc: 5, chain: 5, zkp: 5, sidechan: 5, ecc: 5, shamir: 5, mpc: 5, logs: 6, incident: 6, social: 6, nids: 6, forensics: 6, cloud: 7, mobile: 7, privesc: 8, memcorrupt: 8, containers: 8, privacy: 9, ai: 9, threat: 10, vuln: 10, redteam: 10, bcp: 10, compliance: 10, heartbleed: 11, log4shell: 11, solarwinds: 11 };
  const games = Object.values(GAMES).sort((a, b) => a.order - b.order);
  THEMES.forEach((name, ti) => {
    const inTheme = games.filter(g => (THEME_OF[g.id] ?? 0) === ti);
    if (!inTheme.length) return;
    const h = document.createElement("p"); h.className = "theme"; h.textContent = name; cards.append(h);
    const grid = document.createElement("div"); grid.className = "cards"; cards.append(grid);
    inTheme.forEach(g => {
      const sv = readSave(g.id);
      const total = Object.keys(g.notes).length;
      const done = sv && sv.f && sv.f.end;
      const b = document.createElement("button"); b.type = "button"; b.dataset.id = g.id; b.className = "gcard" + (done ? " done" : "");
      b.innerHTML = `<b></b><small></small><span class="meta"></span>`;
      b.querySelector("b").textContent = g.title;
      b.querySelector("small").textContent = g.blurb;
      b.querySelector(".meta").textContent = done ? `Terminé · carnet ${sv.notes.length}/${total}` : sv ? `En cours · carnet ${sv.notes.length}/${total}` : `Concept : ${g.concept}`;
      b.addEventListener("click", () => openGame(g.id));
      grid.append(b);
    });
  });
}
backBtn.addEventListener("click", showHub);
document.body.insertAdjacentHTML("beforeend", '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs><marker id="fa" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="f-mk"/></marker></defs></svg>');
