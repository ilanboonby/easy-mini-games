"use strict";
/* Le Bureau de Poste : SPF (évaluation réelle, limite de 10 recherches), DKIM (signature RSA jouet sur la forme canonisée),
   DMARC (alignement, politiques, pourcentage, rapports), transferts et listes, déploiement progressif. */
(function () {
  const F = () => f();
  const DOM = "guilde.port443", NEWS = "news." + DOM, TYPO = "gui1de.port443", MALD = "mal-relais.port443";
  const RCPT = "membres@marchands.port443";
  const T0 = 1760000000, DAY = 86400, LIM = 10;
  const IP = { ada: "203.0.113.10", campagne: "198.51.100.7", facture: "192.0.2.50", transfert: "203.0.113.150", liste: "203.0.113.160", mallory: "198.18.0.66" };
  const org = d => d.split(".").slice(-2).join(".");
  const cut = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  const dateOf = t => new Date(t * 1000).toISOString().slice(0, 10);
  const nowT = () => T0 + F().day * DAY;

  /* ---------- Clés RSA jouets (DKIM) ---------- */
  const SEEDS = { own1: 40000000, own2: 41000000, prov: 42000000, listes: 43000000, mal: 44000000, typo: 45000000 };
  const nextPrime = n => { while (!isPrime(n)) n++; return n; };
  function invMod(a, m) { let [r0, r1, s0, s1] = [a, m, 1n, 0n]; while (r1) { const q = r0 / r1;[r0, r1] = [r1, r0 - q * r1];[s0, s1] = [s1, s0 - q * s1]; } return ((s0 % m) + m) % m; }
  const KEYS = {};
  function keyOf(name) {
    if (KEYS[name]) return KEYS[name];
    const seed = SEEDS[name];
    let p = nextPrime(seed); while ((p - 1) % 65537 === 0) p = nextPrime(p + 1);
    let q = nextPrime(seed + 7000003); while ((q - 1) % 65537 === 0) q = nextPrime(q + 1);
    const N = BigInt(p) * BigInt(q), phi = BigInt(p - 1) * BigInt(q - 1);
    return (KEYS[name] = { N, E: 65537n, D: invMod(65537n, phi) });
  }
  const pubTxt = name => `v=DKIM1; k=rsa-toy; n=${keyOf(name).N}; e=65537`;
  const H = s => BigInt(parseInt(sha256(s).slice(0, 11), 16));
  const OWNKEY = { s1: "own1", s2: "own2" };

  /* ---------- DNS fictif ---------- */
  const A = { [DOM]: ["203.0.113.5"], ["mail." + DOM]: ["203.0.113.10"], "relais.sondage.port443": ["203.0.113.200"], "mx.crm.port443": ["192.0.2.200"] };
  const MX = { [DOM]: ["mail." + DOM], "crm.port443": ["mx.crm.port443"] };
  const INIT_SPF = "v=spf1 mx include:_spf.envoi.port443 include:_spf.sondage.port443 include:_spf.agenda.port443 include:_spf.crm.port443 ?all";
  let EXT = null;
  const ext = () => EXT || (EXT = {
    "_spf.envoi.port443": ["v=spf1 include:s1._spf.envoi.port443 include:s2._spf.envoi.port443 ~all"],
    "s1._spf.envoi.port443": ["v=spf1 ip4:198.51.100.0/25 -all"],
    "s2._spf.envoi.port443": ["v=spf1 ip4:198.51.100.128/25 -all"],
    "_spf.sondage.port443": ["v=spf1 a:relais.sondage.port443 ip4:203.0.113.201 -all"],
    "_spf.agenda.port443": ["v=spf1 include:d1._spf.agenda.port443 include:d2._spf.agenda.port443 -all"],
    "d1._spf.agenda.port443": ["v=spf1 ip4:203.0.113.210 -all"],
    "d2._spf.agenda.port443": ["v=spf1 ip4:203.0.113.211 -all"],
    "_spf.crm.port443": ["v=spf1 mx:crm.port443 -all"],
    "_spf.facture.port443": ["v=spf1 ip4:192.0.2.48/28 -all"],
    "bounce.envoi.port443": ["v=spf1 ip4:198.51.100.0/24 -all"],
    "prov._domainkey.envoi.port443": [pubTxt("prov")],
    "listes.port443": ["v=spf1 ip4:203.0.113.160 -all"],
    "_dmarc.listes.port443": ["v=DMARC1; p=none"],
    "l1._domainkey.listes.port443": [pubTxt("listes")],
    [MALD]: ["v=spf1 ip4:198.18.0.66 -all"],
    ["m1._domainkey." + MALD]: [pubTxt("mal")],
    [TYPO]: ["v=spf1 ip4:198.18.0.66 -all"],
    ["_dmarc." + TYPO]: ["v=DMARC1; p=reject"],
    ["t1._domainkey." + TYPO]: [pubTxt("typo")],
  });
  function txt(name) {
    name = name.toLowerCase();
    const x = F();
    if (name === DOM) return [x.zone.spf];
    if (name === "_dmarc." + DOM) return x.zone.dmarc ? [x.zone.dmarc] : [];
    const m = /^([a-z0-9-]+)\._domainkey\.guilde\.port443$/.exec(name);
    if (m) {
      if (m[1] === "envoi1") return x.zone.envoi ? [pubTxt("prov")] : [];
      const v = x.zone.keys[m[1]];
      if (v === "pub" && OWNKEY[m[1]]) return [pubTxt(OWNKEY[m[1]])];
      if (v === "revoked") return ["v=DKIM1; p="];
      return [];
    }
    return ext()[name] || [];
  }
  function parseTags(s) { const o = {}; s.split(";").forEach(p => { const i = p.indexOf("="); if (i > 0) o[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim(); }); return o; }
  function parseDmarc(s) {
    const parts = s.split(";").map(p => p.trim()).filter(Boolean);
    if (!/^v\s*=\s*DMARC1$/i.test(parts[0] || "")) return { ok: false, err: "un enregistrement DMARC commence par « v=DMARC1; »." };
    const t = parseTags(s), p = (t.p || "").toLowerCase();
    if (!["none", "quarantine", "reject"].includes(p)) return { ok: false, err: "il faut une politique : p=none, p=quarantine ou p=reject." };
    let pct = 100;
    if (t.pct !== undefined) { if (!/^\d+$/.test(t.pct) || +t.pct > 100) return { ok: false, err: "pct doit être un entier de 0 à 100." }; pct = +t.pct; }
    const md = v => (v || "r").toLowerCase();
    const aspf = md(t.aspf), adkim = md(t.adkim);
    if (!/^[rs]$/.test(aspf) || !/^[rs]$/.test(adkim)) return { ok: false, err: "aspf et adkim valent r (relaxé) ou s (strict)." };
    return { ok: true, p, pct, aspf, adkim, rua: t.rua ? t.rua.replace(/^mailto:/i, "") : "" };
  }
  function dmarcFor(fd) {
    const names = org(fd) === fd ? [fd] : [fd, org(fd)];
    for (const d of names) { const r = txt("_dmarc." + d).find(s => /^v=DMARC1/i.test(s)); if (r) return { at: d, rec: r, pr: parseDmarc(r) }; }
    return null;
  }

  /* ---------- SPF : évaluation réelle ---------- */
  const ip2n = s => s.split(".").reduce((a, b) => a * 256 + (+b), 0);
  function inCidr(ip, spec) {
    const [b, l] = spec.split("/"), bits = l === undefined ? 32 : +l;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(b) || !(bits >= 0 && bits <= 32)) return false;
    const sz = 2 ** (32 - bits);
    return Math.floor(ip2n(ip) / sz) === Math.floor(ip2n(b) / sz);
  }
  function spfEval(ip, dom) {
    const tr = []; let look = 0;
    const add = (d, term, eff, k) => tr.push({ d, term, eff, k, t: term + (eff ? " : " + eff : ""), n: look });
    function chk(dm, d) {
      const recs = txt(dm).filter(s => /^v=spf1(\s|$)/i.test(s));
      if (!recs.length) { add(d, dm, "aucun enregistrement SPF", "err"); return "none"; }
      add(d, dm, "enregistrement lu", "info");
      for (const term of recs[0].trim().split(/\s+/).slice(1)) {
        const m = /^([+\-~?]?)([a-z0-9]+)(?::(.+))?$/i.exec(term);
        if (!m) { add(d, term, "syntaxe non reconnue", "err"); return "permerror"; }
        const q = m[1] || "+", mech = m[2].toLowerCase(), arg = m[3];
        const res = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" }[q];
        if (mech === "all") { add(d, term, "tout le reste → " + res, "hit"); return res; }
        if (mech === "ip4") {
          const ok = !!arg && inCidr(ip, arg);
          add(d, term, ok ? "contient " + ip + " → " + res : "ne contient pas " + ip, ok ? "hit" : "no");
          if (ok) return res; continue;
        }
        if (mech === "a" || mech === "mx" || mech === "include") {
          look++;
          if (look > LIM) { add(d, term, "recherche " + look + " : limite de 10 dépassée", "err"); return "permerror"; }
          const host = arg || dm;
          if (mech === "include") {
            add(d, term, "recherche " + look + "/10", "inc");
            const r = chk(host, d + 1);
            if (r === "pass") { add(d, term, "l'inclusion passe → " + res, "hit"); return res; }
            if (r === "none" || r === "permerror") return "permerror";
            continue;
          }
          const ips = mech === "a" ? (A[host] || []) : (MX[host] || []).flatMap(h => A[h] || []);
          const ok = ips.includes(ip);
          add(d, term, "recherche " + look + "/10 : " + (ips.join(", ") || "rien") + (ok ? " → " + res : ""), ok ? "hit" : "no");
          if (ok) return res; continue;
        }
        add(d, term, "mécanisme non géré par le jeu", "err"); return "permerror";
      }
      add(d, "(fin)", "aucune correspondance → neutral", "no");
      return "neutral";
    }
    const res = chk(dom, 0);
    return { res, tr, look, ip, dom };
  }
  const spfWhy = sp => { const e = sp.tr.find(r => r.k === "hit"); if (e) return e.t; const er = sp.tr.find(r => r.k === "err"); return er ? er.t : "aucun mécanisme ne correspond"; };

  /* ---------- DKIM : canonisation, signature, vérification ---------- */
  const cwsp = s => String(s).replace(/\s+/g, " ").trim();
  const canonBody = lines => lines.map(l => l.replace(/[ \t]+/g, " ").replace(/ +$/, "")).join("\r\n").replace(/(\r\n)+$/, "") + "\r\n";
  const bodyHash = lines => sha256(canonBody(lines));
  const hdrStr = (m, names) => names.map(n => n + ":" + cwsp(m.h[n] || "")).join("\n");
  const sigData = (m, sg) => hdrStr(m, sg.h) + "\ndkim-signature:v=1;d=" + sg.d + ";s=" + sg.s + ";h=" + sg.h.join(":") + ";bh=" + sg.bh + ";t=" + sg.t + (sg.x ? ";x=" + sg.x : "");
  function signMsg(m, d, s, kn, h, t, ttl) {
    const K = keyOf(kn);
    const sg = { d, s, h: h.slice(), bh: bodyHash(m.body), t, x: ttl > 0 ? t + ttl * DAY : 0 };
    sg.b = modpow(H(sigData(m, sg)), K.D, K.N);
    return sg;
  }
  function verifyDkim(m, sg) {
    const r = { d: sg.d, s: sg.s };
    const rec = txt(sg.s + "._domainkey." + sg.d);
    if (!rec.length) return Object.assign(r, { res: "permerror", why: "aucune clé publique à " + sg.s + "._domainkey." + sg.d });
    const t = parseTags(rec[0]);
    if (!/^\d+$/.test(t.n || "")) return Object.assign(r, { res: "fail", why: "clé révoquée (p= vide) : plus personne ne peut valider ce sélecteur" });
    if (!sg.h.includes("from")) return Object.assign(r, { res: "permerror", why: "l'en-tête From n'est pas signé (obligatoire)" });
    if (sg.x && sg.x < nowT()) return Object.assign(r, { res: "fail", why: "signature expirée (x=" + dateOf(sg.x) + ", on est le " + dateOf(nowT()) + ")" });
    if (bodyHash(m.body) !== sg.bh) return Object.assign(r, { res: "fail", why: "empreinte du corps différente (bh) : le corps a été modifié" });
    const N = BigInt(t.n), E = BigInt(t.e || 65537);
    if (BigInt(modpow(sg.b, E, N)) !== H(sigData(m, sg)) % N) return Object.assign(r, { res: "fail", why: "signature invalide : un en-tête signé a changé" });
    return Object.assign(r, { res: "pass", why: "corps et en-têtes signés intacts, clé lue dans le DNS" });
  }

  /* ---------- Courriers du jeu ---------- */
  const fromDom = m => /<[^@>]+@([^>]+)>/.exec(m.h.from)[1];
  const fromAddr = m => /<([^>]+)>/.exec(m.h.from)[1];
  function ownSigs(m, t) { const s = F().sign; if (!s.on || !s.sel) return []; return [signMsg(m, DOM, s.sel, OWNKEY[s.sel], s.h, t, s.ttl)]; }
  const ADA_BODY = ["Chers membres,", "la réunion de la Guilde aura lieu", "jeudi à 18 h, salle des archives.", "Maître Ada"];
  function mk(id) {
    const x = F(), t = nowT();
    const base = (ip, helo, mf, from, subject, body) => ({ id, ip, helo, mf, h: { from, to: RCPT, subject, date: dateOf(t) }, body: body.slice(), sigs: [] });
    let m;
    switch (id) {
      case "ada": m = base(IP.ada, "mail." + DOM, "direction@" + DOM, "Maître Ada <direction@" + DOM + ">", "Convocation : réunion de jeudi", ADA_BODY); m.sigs = ownSigs(m, t); m.label = "Courrier légitime de Maître Ada (serveur de la Guilde)"; break;
      case "mallory": m = base(IP.mallory, "poste-pirate.port443", "direction@" + DOM, "Maître Ada <direction@" + DOM + ">", "URGENT : virement à régler aujourd'hui", ["Bonjour,", "règle aujourd'hui la facture de 4 800 pièces", "sur le compte PORT 0000 1234 (fictif).", "Réponds vite et reste discret. Ada"]); m.label = "Usurpation directe par Mallory (tout est faux)"; break;
      case "malin": m = base(IP.mallory, "poste-pirate.port443", "mallory@" + MALD, "Maître Ada <direction@" + DOM + ">", "URGENT : virement à régler aujourd'hui", ["Bonjour,", "règle aujourd'hui la facture de 4 800 pièces", "sur le compte PORT 0000 1234 (fictif).", "Réponds vite et reste discret. Ada"]); m.sigs = [signMsg(m, MALD, "m1", "mal", ["from", "to", "subject", "date"], t, 0)]; m.label = "Mallory, plus maligne : enveloppe et signature de SON domaine, « De » usurpé"; break;
      case "typo": m = base(IP.mallory, "poste-pirate.port443", "direction@" + TYPO, "Maître Ada <direction@" + TYPO + ">", "Convocation : réunion de jeudi", ["Chers membres,", "la réunion est déplacée : confirmez", "vos coordonnées bancaires ici.", "Maître Ada"]); m.sigs = [signMsg(m, TYPO, "t1", "typo", ["from", "to", "subject", "date"], t, 0)]; m.label = "Domaine voisin de Mallory (gui1de.port443, avec un « 1 »)"; break;
      case "campagne": m = base(IP.campagne, "s1.envoi.port443", "bounce-4821@bounce.envoi.port443", "Info Guilde <info@" + NEWS + ">", "La lettre d'automne de la Guilde", ["Chers membres,", "voici la lettre d'automne :", "ateliers, concours, nouveautés."]);
        m.sigs = x.zone.envoi ? [signMsg(m, DOM, "envoi1", "prov", ["from", "to", "subject", "date"], t, 0)] : [signMsg(m, "envoi.port443", "prov", "prov", ["from", "to", "subject", "date"], t, 0)]; m.label = "Lettre d'information envoyée par le prestataire de campagnes"; break;
      case "facture": m = base(IP.facture, "relais.facture-cloud.port443", "facturation@" + DOM, "Facturation <facturation@" + DOM + ">", "Votre facture d'octobre", ["Bonjour,", "votre facture d'octobre est disponible", "dans votre espace membre."]); m.label = "Facture envoyée par le prestataire de facturation"; break;
      case "transfert": m = base(IP.ada, "mail." + DOM, "direction@" + DOM, "Maître Ada <direction@" + DOM + ">", "Convocation : réunion de jeudi", ADA_BODY); m.sigs = ownSigs(m, t); m.ip = IP.transfert; m.helo = "redirection.alice.port443"; m.label = "Courrier d'Ada transféré par la redirection automatique d'Alice"; break;
      case "liste": {
        m = base(IP.ada, "mail." + DOM, "direction@" + DOM, "Maître Ada <direction@" + DOM + ">", "Convocation : réunion de jeudi", ADA_BODY);
        const orig = ownSigs(m, t);
        m.ip = IP.liste; m.helo = "relais.listes.port443"; m.mf = "bounces@listes.port443";
        m.h.subject = "[guilde-liste] " + m.h.subject; m.body.push("--", "Vous recevez ce message via la liste guilde-liste.");
        if (x.listRew) { m.h.from = "Maître Ada via la liste <liste@listes.port443>"; m.sigs = []; } else m.sigs = orig;
        m.sigs = m.sigs.concat([signMsg(m, "listes.port443", "l1", "listes", ["from", "to", "subject", "date"], t, 0)]);
        m.label = "Courrier d'Ada passé par la liste de diffusion (pied de page et préfixe ajoutés)"; break;
      }
      case "rejeu": m = base(IP.mallory, "poste-pirate.port443", "direction@" + DOM, "Maître Ada <direction@" + DOM + ">", "Convocation : réunion de jeudi", ADA_BODY); m.sigs = ownSigs(m, T0); m.label = "Rejeu par Mallory d'un VRAI courrier signé, capturé le jour 0"; break;
      case "piege": m = base(IP.ada, "mail." + DOM, "bob@" + DOM, "Bob <bob@" + DOM + ">", "Nouveau RIB du fournisseur", ["Bonjour,", "le compte du fournisseur a changé :", "virez désormais sur PORT 0000 9999 (fictif)."]); m.sigs = ownSigs(m, t); m.label = "Courrier envoyé depuis le VRAI serveur, avec le compte de Bob volé"; break;
    }
    return m;
  }
  function evaluate(m, o) {
    o = o || {};
    const mfd = m.mf.split("@")[1], fd = fromDom(m);
    const sp = spfEval(m.ip, mfd), dk = m.sigs.map(sg => verifyDkim(m, sg)), lk = dmarcFor(fd);
    const pol = lk && lk.pr.ok ? Object.assign({}, lk.pr) : null;
    if (pol && o.ov && org(fd) === DOM) Object.assign(pol, o.ov);
    const ev = { sp, dk, fd, mfd, lk, pol, dm: null, fixed: null, dkBest: dk.some(r => r.res === "pass") ? "pass" : dk.length ? dk[0].res : "none" };
    if (pol) {
      const rel = (a, b, mode) => (mode === "s" ? a === b : org(a) === org(b));
      const spfAl = sp.res === "pass" && rel(mfd, fd, pol.aspf);
      const dkOk = dk.filter(r => r.res === "pass" && rel(r.d, fd, pol.adkim));
      ev.dm = { pol, spfAl, dkAl: dkOk.length > 0, pass: spfAl || dkOk.length > 0 };
    } else ev.fixed = sp.res === "fail" ? "reject" : sp.res === "softfail" ? "spam" : "inbox";
    return ev;
  }
  function single(ev, seed) {
    if (ev.fixed) return { k: ev.fixed, why: ev.fixed === "inbox" ? "aucune politique DMARC, SPF ne dit pas « fail » : le courrier passe" : ev.fixed === "reject" ? "aucune politique DMARC : le récepteur suit SPF seul, et SPF dit « fail »" : "aucune politique DMARC : SPF dit « softfail », le récepteur met le courrier de côté" };
    if (ev.dm.pass) return { k: "inbox", why: "DMARC réussi" };
    const { p, pct } = ev.dm.pol, tg = parseInt(sha256("pct|" + seed).slice(0, 6), 16) % 100 < pct;
    if (p === "none") return { k: "inbox", why: "DMARC échoue, mais p=none : on observe sans bloquer (le rapport en parlera)" };
    const tgTxt = pct < 100 ? (tg ? " (ce courrier tombe dans les " + pct + " % ciblés)" : " (ce courrier n'est pas parmi les " + pct + " % ciblés : traité selon la politique inférieure)") : "";
    if (p === "quarantine") return tg ? { k: "spam", why: "DMARC échoue, p=quarantine" + tgTxt } : { k: "inbox", why: "DMARC échoue, p=quarantine" + tgTxt };
    return tg ? { k: "reject", why: "DMARC échoue, p=reject" + tgTxt } : { k: "spam", why: "DMARC échoue, p=reject" + tgTxt };
  }
  function breakdown(vol, ev) {
    if (ev.fixed) return { inbox: ev.fixed === "inbox" ? vol : 0, spam: ev.fixed === "spam" ? vol : 0, reject: ev.fixed === "reject" ? vol : 0 };
    if (ev.dm.pass) return { inbox: vol, spam: 0, reject: 0 };
    const { p, pct } = ev.dm.pol, k = Math.round(vol * pct / 100);
    if (p === "reject") return { inbox: 0, spam: vol - k, reject: k };
    if (p === "quarantine") return { inbox: vol - k, spam: k, reject: 0 };
    return { inbox: vol, spam: 0, reject: 0 };
  }

  /* ---------- Trafic de la semaine (rejoué avec la configuration actuelle) ---------- */
  const BASE = [
    { id: "ada", ptr: "mail.guilde.port443", vol: 4200, legit: true },
    { id: "campagne", ptr: "s1.envoi.port443", vol: 900, legit: true },
    { id: "facture", ptr: "relais.facture-cloud.port443", vol: 310, legit: true },
    { id: "transfert", ptr: "redirection.alice.port443", vol: 40, legit: true },
    { id: "liste", ptr: "relais.listes.port443", vol: 120, legit: true },
    { id: "mallory", ptr: "(inconnu)", vol: 57, legit: false },
    { id: "malin", ptr: "(inconnu)", vol: 12, legit: false },
  ];
  function profile(ov) {
    const rows = BASE.map(b => { const m = mk(b.id), ev = evaluate(m, { ov }); return Object.assign({}, b, { m, ev, bd: breakdown(b.vol, ev) }); });
    const sum = (arr, f2) => arr.reduce((a, r) => a + f2(r), 0);
    const L = rows.filter(r => r.legit), S2 = rows.filter(r => !r.legit);
    return { rows, legitTot: sum(L, r => r.vol), legitLost: sum(L, r => r.bd.spam + r.bd.reject), legitFail: sum(L, r => (r.ev.dm && !r.ev.dm.pass ? r.vol : 0)), spoofTot: sum(S2, r => r.vol), spoofStopped: sum(S2, r => r.bd.spam + r.bd.reject) };
  }
  const failLegit = () => profile({ p: "reject", pct: 100 }).legitLost;

  /* ---------- Carnet ---------- */
  const notes = {
    usurpation: ["Écrire « De : » ne prouve rien", "Dans le protocole de base du courrier (SMTP), l'expéditeur annonce lui-même deux adresses : celle de l'enveloppe (MAIL FROM) et celle de l'en-tête « From: » que le lecteur voit. Le serveur récepteur ne vérifie ni l'une ni l'autre : n'importe qui peut écrire « direction@guilde.port443 ». Tout le reste (SPF, DKIM, DMARC) a été ajouté après coup, par-dessus, en s'appuyant sur le DNS."],
    spf: ["SPF : qui a le droit d'envoyer", "Le domaine publie dans un enregistrement TXT la liste des adresses IP autorisées à envoyer en son nom (ip4, include, a, mx) et se termine par une règle pour tout le reste : -all (refuser), ~all (suspect), ?all (aucun avis), +all (tout autoriser, absurde). SPF teste l'IP de l'envoyeur contre le domaine de l'ENVELOPPE, pas celui du « From ». Limite : 10 recherches DNS (include, a, mx...) ; au-delà, c'est une erreur permanente (permerror) et le SPF est ignoré. Erreurs classiques : trop de include, un prestataire oublié, une règle finale trop laxiste."],
    dkim: ["DKIM : une signature qui voyage avec le courrier", "Le serveur d'envoi signe une forme canonisée des en-têtes choisis (h=) et d'une empreinte du corps (bh=) avec une clé privée ; la clé publique est publiée dans le DNS (sélecteur._domainkey.domaine). Le récepteur recalcule : si le corps ou un en-tête signé a changé, la signature échoue. Ici : une RSA miniature de 52 bits (jouet) ; en vrai, RSA 2048 bits ou Ed25519. Un en-tête NON listé dans h= peut être modifié sans que DKIM le voie : il faut signer from, to, subject, date, reply-to..."],
    dkimvie: ["DKIM au quotidien : expiration, rotation, rejeu", "Une signature valide reste valide : un courrier légitime capturé peut être rejoué plus tard à d'autres destinataires et passer DKIM (et donc DMARC). On limite le risque avec une expiration (x=) et en signant aussi les en-têtes To et Date. Les clés se renouvellent : on publie le nouveau sélecteur, on bascule la signature, on laisse vivre l'ancien le temps que les courriers en transit soient lus, puis on le révoque (p= vide). Révoquer avant de basculer, c'est casser son propre courrier."],
    dmarc: ["DMARC : la politique et les rapports", "L'enregistrement _dmarc.domaine dit quoi faire quand un courrier ne passe pas : p=none (observer), p=quarantine (mettre de côté), p=reject (refuser), pour un pourcentage pct des échecs. rua= est l'adresse qui reçoit les rapports agrégés : qui a envoyé du courrier au nom du domaine, depuis quelles IP, avec quel résultat. Sans rapports, on avance à l'aveugle."],
    alignement: ["L'alignement : le « pass » doit porter sur le bon domaine", "DMARC exige que SPF ou DKIM réussisse ET que le domaine validé corresponde au domaine du « From » que lit l'humain. SPF valide le domaine de l'enveloppe, DKIM le domaine d du signataire. En mode relaxé (r), il suffit d'un même domaine d'organisation (news.guilde.port443 s'aligne avec guilde.port443) ; en strict (s), il faut le même domaine exactement. Un prestataire qui envoie avec SON domaine obtient des « pass » non alignés : DMARC échoue quand même."],
    deploiement: ["Le déploiement progressif", "On ne passe pas à p=reject d'un coup : 1) p=none avec rua pour observer ; 2) lire les rapports, identifier chaque source légitime, la corriger (SPF, DKIM, alignement) ; 3) p=quarantine avec un pct qui monte (10, 50, 100) ; 4) p=reject. À chaque étape, on vérifie qu'aucun courrier légitime n'est perdu. Aller trop vite coûte des factures, des convocations, des lettres d'information."],
    transferts: ["Transferts et listes de diffusion", "Un transfert (redirection) envoie le courrier depuis un autre serveur : l'IP n'est plus autorisée, SPF échoue ; DKIM, lui, survit tant que rien n'est modifié. Une liste de diffusion modifie le corps et le sujet : SPF et DKIM échouent, et sous p=reject le courrier légitime est refusé. Remèdes : la liste réécrit le « From » avec son propre domaine ; ARC (Authenticated Received Chain) laisse les intermédiaires attester de ce qu'ils ont vu, à la discrétion du récepteur."],
    limites: ["Ce que l'authentification ne dit pas", "SPF, DKIM et DMARC prouvent QUI a envoyé, pas que le contenu est honnête. Un domaine voisin (gui1de.port443) obtient des « pass » valides pour son propre domaine ; un compte légitime volé envoie du vrai courrier signé. Il faut aussi surveiller les noms de domaine proches, protéger les comptes (MFA) et former les gens. BIMI affiche le logo de la marque, mais seulement si DMARC est appliqué : une vitrine de plus, pas une preuve de bonne foi."],
  };

  /* ---------- Entités ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle sait que son nom se falsifie en une ligne." },
    alice: { npc: true, names: ["alice", "scribe"], label: "Alice", desc: () => "Alice, scribe du registre, tient la zone DNS de la Guilde. Elle redirige son courrier professionnel vers sa boîte personnelle." },
    bob: { npc: true, names: ["bob", "postier"], label: "Bob (postier)", desc: () => "Bob, postier du guichet, connaît tous les expéditeurs légitimes et la plupart des illégitimes." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, près de la fenêtre qui donne sur les relais, regarde passer (et parfois modifier) les courriers en transit." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory (jouée par Ada, pour l'audit)", desc: () => "Mallory, l'attaquante. Ici elle est simulée : domaines et adresses sont fictifs, rien ne sort du jeu." },
    boite: { names: ["boite", "casier", "courrier", "guichet", "boite essai"], label: "le casier d'essai", desc: () => "Le casier d'essai : tu y déposes un courrier fictif et le bureau de poste destinataire (marchands.port443) l'évalue.\n`envoyer ada` (légitime) · `envoyer mallory` · `envoyer malin` · `envoyer typo` · `envoyer campagne` · `envoyer facture` · `envoyer transfert` · `envoyer liste` · `envoyer rejeu` · `envoyer piege`\n`alterer corps|sujet|reponse` simule une modification en transit." },
    registre: { names: ["registre", "zone", "dns", "enregistrements", "tableau"], label: "le registre DNS de la Guilde", desc: () => zoneText() },
    signeuse: { names: ["signeuse", "machine", "presse"], label: "la signeuse DKIM", desc: () => dkimText() },
    pile: { names: ["pile", "dossiers", "pile rapports"], label: "la pile de rapports", desc: () => "Les rapports agrégés DMARC arrivent ici, résumés par source. `rapports` les lit." },
  };
  const rooms = {
    hall: { name: "Le hall du Bureau de Poste", short: "Hall", alias: ["hall", "bureau"], ents: ["ada"], exits: { est: "guichet", nord: "registre", ouest: "scriptorium", sud: "rapports" },
      desc: () => "Sous une horloge de cuivre, Maître Ada trie à la main les lettres arrivées. Quatre portes : à l'est le guichet des essais, au nord le registre DNS, à l'ouest le scriptorium des signatures, au sud la salle des rapports." },
    guichet: { name: "Le guichet des essais", short: "Guichet", alias: ["guichet", "essais"], ents: ["bob", "mallory", "boite"], exits: { ouest: "hall" },
      desc: () => "Un comptoir de chêne, un casier d'essai, une balance à lettres. Bob affranchit, Mallory (jouée par Ada) attend son tour avec un grand sourire. Tout ce qui est posté ici est un courrier fictif." },
    registre: { name: "Le registre DNS", short: "Registre", alias: ["registre", "dns"], ents: ["alice", "registre"], exits: { sud: "hall" },
      desc: () => "Des tiroirs étiquetés par nom de domaine. Alice y range les enregistrements TXT : SPF, DKIM, DMARC. Un tableau affiche la zone de guilde.port443." },
    scriptorium: { name: "Le scriptorium des signatures", short: "Scriptorium", alias: ["scriptorium", "signatures"], ents: ["signeuse", "eve"], exits: { est: "hall" },
      desc: () => "Une presse à cacheter aligne les lettres de la Guilde ; chacune reçoit un sceau calculé sur son contenu. Ève regarde par la fenêtre les relais qui passent." },
    rapports: { name: "La salle des rapports", short: "Rapports", alias: ["rapports", "archives"], ents: ["pile"], exits: { nord: "hall" },
      desc: () => "Des étagères de rapports agrégés : chaque ligne dit quelle adresse IP a envoyé du courrier au nom de la Guilde, combien, et ce que DMARC en a pensé." },
  };

  /* ---------- Affichage de la zone et de la signeuse ---------- */
  function zoneText() {
    const x = F();
    let s = "La zone de " + DOM + " (extraits utiles) :\n";
    const lines = [DOM + "   TXT   " + x.zone.spf, "_dmarc." + DOM + "   TXT   " + (x.zone.dmarc || "(aucun enregistrement)")];
    ["s1", "s2"].forEach(k => lines.push(k + "._domainkey." + DOM + "   TXT   " + (x.zone.keys[k] === "pub" ? "v=DKIM1; k=rsa-toy; n=…" + String(keyOf(OWNKEY[k]).N).slice(-6) + "; e=65537" : x.zone.keys[k] === "revoked" ? "v=DKIM1; p=   (révoquée)" : "(aucune clé)")));
    lines.push("envoi1._domainkey." + DOM + "   TXT   " + (x.zone.envoi ? "clé du prestataire d'envoi (déléguée)" : "(aucune clé)"));
    code(s + lines.join("\n"));
    return "`dns spf ‹enregistrement›` · `dns dmarc ‹enregistrement›` · `dns delegue envoi` · `spf ‹source›` pour tracer SPF.";
  }
  function dkimText() {
    const x = F(), s = x.sign;
    code(`sélecteur de signature : ${s.on ? s.sel : "(aucun : le serveur n'a pas de clé)"}\nen-têtes signés (h=)  : ${s.h.join(":")}\nexpiration (x=)       : ${s.ttl ? s.ttl + " jours" : "aucune"}\nclés publiées         : s1 ${x.zone.keys.s1 || "-"} · s2 ${x.zone.keys.s2 || "-"}`);
    return "`dkim cle ‹s1|s2›` · `dkim choisir ‹s1|s2›` · `dkim entetes ‹liste›` · `dkim expire ‹jours›` · `dkim revoquer ‹s1|s2›`";
  }

  /* ---------- Objectif et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.spoof) return "spoof";
    if (!x.spfok) return "spf";
    if (!x.dkimok) return "dkim1";
    if (!(x.tc && x.ts)) return "dkim2";
    if (!x.d0) return "dmarc0";
    if (!x.rapport) return "rapport";
    if (failLegit() > 0) return "fix";
    if (!x.q) return "quar";
    if (!x.rej) return "rej";
    if (!x.exp) return "replay";
    if (!x.rot) return "rot";
    if (!x.typo) return "typo";
    if (!x.piege) return "piege";
    if (!x.end) return "end";
    return "fin";
  };
  function advice() {
    const P = profile({ p: "reject", pct: 100 });
    const tip = { facture: "SPF : `dns spf v=spf1 mx include:_spf.facture.port443 -all`", campagne: "alignement : `dns delegue envoi` (le prestataire signera avec ton domaine)", liste: "`regler liste reecriture` (au guichet)", transfert: "la signature DKIM doit rester valide (scriptorium : `dkim voir`)", ada: "ton propre serveur doit passer SPF ou DKIM aligné (`spf ada`, `dkim voir`)" };
    return P.rows.filter(r => r.legit && r.bd.spam + r.bd.reject > 0).map(r => r.ptr + " (" + r.vol + ") → " + tip[r.id]);
  }
  const hints = {
    quest: () => ["Maître Ada t'attend dans le hall.", "`parler ada`"],
    spoof: () => ["Va au guichet et fais écrire à Mallory « De : direction@guilde.port443 » : vois si le bureau destinataire s'en aperçoit.", "`aller est`, `envoyer mallory`"],
    spf: () => ["Va au registre (nord du hall) : trace l'évaluation SPF contre l'IP de Mallory et celle d'Ada, puis publie un enregistrement qui autorise ton serveur de courrier (mx) et refuse le reste.", "`aller nord`, `spf mallory`, `spf ada`, puis `dns spf v=spf1 mx -all`"],
    dkim1: () => {
      const x = F();
      if (!x.zone.keys.s1) return ["Au scriptorium (ouest du hall), publie une clé DKIM : la clé publique va dans le DNS.", "`aller ouest`, `dkim cle s1`, `dkim choisir s1`"];
      if (!x.sign.on) return ["La clé est publiée : dis à la signeuse de s'en servir.", "`dkim choisir s1`"];
      return ["Envoie un courrier d'Ada depuis le guichet et regarde la ligne DKIM.", "`aller est` (retour au hall), `aller est`, `envoyer ada`"];
    },
    dkim2: () => ["Au guichet, simule des modifications en transit : corps, sujet. Si un en-tête reste modifiable sans casser la signature, élargis la liste des en-têtes signés (scriptorium).", "`alterer corps`, `alterer sujet`, et si le sujet passe : `dkim entetes from,to,subject,date,reply-to`, puis `alterer sujet`, `alterer reponse`"],
    dmarc0: () => ["Retourne au registre et publie DMARC en mode observation, avec une adresse de rapports (rua).", "`dns dmarc v=DMARC1; p=none; rua=mailto:rapports@guilde.port443`"],
    rapport: () => ["Va à la salle des rapports (sud du hall) et lis le rapport de la semaine.", "`aller sud`, `rapports`"],
    fix: () => { const a = advice(); return ["Certaines sources LÉGITIMES échouent DMARC. Identifie-les dans le rapport (Bob, au guichet, connaît les expéditeurs), puis corrige-les une à une : " + a.map(s => s.split(" → ")[0]).join(" ; ") + ".", a.join("\n") + "\nVérifie ensuite : `rapports`."]; },
    quar: () => ["Plus aucune source légitime en échec : resserre progressivement. Commence par la quarantaine, d'abord sur une partie du courrier.", "`dns dmarc v=DMARC1; p=quarantine; pct=25; rua=mailto:rapports@guilde.port443`, `rapports`, puis `pct=100`"],
    rej: () => ["Passe en refus total, pour 100 % du courrier en échec.", "`dns dmarc v=DMARC1; p=reject; rua=mailto:rapports@guilde.port443`"],
    replay: () => ["Mallory a un dernier tour : elle rejoue un VRAI courrier signé, bien plus tard. Laisse passer du temps, essaie, puis limite la durée de vie des signatures au scriptorium.", "`aller est` (guichet), `attendre 10`, `envoyer rejeu`, puis `aller ouest`, `aller ouest`, `dkim expire 3`, et retour `envoyer rejeu`"],
    rot: () => ["Renouvelle la clé DKIM sans casser le courrier : publie la nouvelle, bascule, puis révoque l'ancienne.", "Au scriptorium : `dkim cle s2`, `dkim choisir s2`, `dkim revoquer s1`"],
    typo: () => ["Au guichet, teste un domaine voisin du tien : que dit DMARC ?", "`envoyer typo` (puis `surveiller` au registre)"],
    piege: () => ["Dernier cas : un compte légitime volé qui écrit depuis le vrai serveur.", "`envoyer piege` (au guichet)"],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé. Relis ton carnet.", "`carnet`"],
  };

  /* ---------- Courrier : commandes ---------- */
  function rawMail(m) {
    const L = [`HELO ${m.helo}    (connexion depuis ${m.ip})`, `MAIL FROM:<${m.mf}>`, `RCPT TO:<${RCPT}>`, "DATA"];
    m.sigs.forEach(sg => L.push(`DKIM-Signature: d=${sg.d}; s=${sg.s};\n   h=${sg.h.join(":")};\n   bh=${sg.bh.slice(0, 10)}…; t=${dateOf(sg.t)}${sg.x ? "; x=" + dateOf(sg.x) : ""}`));
    L.push("From: " + m.h.from, "To: " + m.h.to, "Subject: " + m.h.subject, "Date: " + m.h.date);
    if (m.h["reply-to"]) L.push("Reply-To: " + m.h["reply-to"]);
    L.push("", ...m.body);
    return L.join("\n");
  }
  function pickSrc(t) {
    if (/rejeu|replay/.test(t)) return "rejeu";
    if (/malin|astuc|propre/.test(t)) return "malin";
    if (/typo|proche|gui1de|voisin|sosie/.test(t)) return "typo";
    if (/piege|compromis/.test(t)) return "piege";
    if (/campagne|lettre|newsletter|envoi/.test(t)) return "campagne";
    if (/factur/.test(t)) return "facture";
    if (/transf|redirect|suiv/.test(t)) return "transfert";
    if (/liste|diffusion/.test(t)) return "liste";
    if (/mallory|usurp|faux|forge/.test(t)) return "mallory";
    if (/ada|direction|legit|convoc/.test(t)) return "ada";
    return null;
  }
  const SPFN = r => ({ pass: "pass", fail: "fail", softfail: "softfail", neutral: "neutral", none: "none", permerror: "permerror" }[r] || r);
  function sendCmd(c) {
    const x = F();
    if (S.room !== "guichet") { out("Les courriers d'essai se postent au guichet (est du hall) : `aller est`.", "sys"); return; }
    const id = pickSrc(norm(c.rawArg));
    if (!id) { out("Quel courrier ? `envoyer ada` · `envoyer mallory` · `envoyer malin` · `envoyer typo` · `envoyer campagne` · `envoyer facture` · `envoyer transfert` · `envoyer liste` · `envoyer rejeu` · `envoyer piege`", "err"); return; }
    x.n++;
    const m = mk(id), ev = evaluate(m), d = single(ev, x.n);
    x.last = { id, m, ev, d };
    out(m.label, "title");
    code(rawMail(m));
    out("Le bureau de poste destinataire (fictif) évalue :", "sys");
    const dk = ev.dk.length ? ev.dk.map(r => `${r.res} (d=${r.d} s=${r.s} : ${r.why})`).join("\n       ") : "aucune signature";
    code(`SPF   : ${SPFN(ev.sp.res)}   [domaine de l'enveloppe ${ev.mfd}]\n        ${spfWhy(ev.sp)}\nDKIM  : ${dk}\nDMARC : ${ev.dm ? (ev.dm.pass ? "pass" : "fail") + ` (SPF ${ev.dm.spfAl ? "aligné" : "non aligné"}, DKIM ${ev.dm.dkAl ? "aligné" : "non aligné"} avec « ${ev.fd} » ; p=${ev.dm.pol.p}${ev.dm.pol.pct < 100 ? " pct=" + ev.dm.pol.pct : ""})` : (ev.lk && !ev.lk.pr.ok ? "enregistrement invalide" : "aucun enregistrement _dmarc." + ev.fd)}`);
    const label = { inbox: "LIVRÉ en boîte de réception", spam: "MIS EN QUARANTAINE (dossier indésirables)", reject: "REJETÉ (550 : refus à la réception)" }[d.k];
    const bad = ["mallory", "malin", "typo", "rejeu", "piege"].includes(id);
    out(`Décision : **${label}**. Pourquoi : ${d.why}.`, (d.k === "inbox") === bad ? "err" : "ok");
    progress(id, m, ev, d);
  }
  function progress(id, m, ev, d) {
    const x = F();
    if (id === "mallory" && !x.spoof) {
      x.spoof = true; note("usurpation"); fig("chemin");
      say("Maître Ada", "Voilà : « direction@guilde.port443 » est tombé dans la boîte, sans que personne ne vérifie quoi que ce soit. Notre enregistrement SPF est cassé (tu verras pourquoi), et il n'y a ni signature ni politique. Va au registre DNS (nord) : on commence par SPF.");
    }
    if (id === "ada" && !x.dkimok && ev.dm !== undefined && ev.dk.some(r => r.res === "pass" && r.d === DOM)) {
      x.dkimok = true; note("dkim"); fig("dkim");
      say("Maître Ada", "La signature est valide : le récepteur a retrouvé la clé dans le DNS et recalculé la même chose. Mais une signature n'a de valeur que si elle casse quand on triche. Teste : `alterer corps`, `alterer sujet` (ici, au guichet).");
    }
    if (id === "campagne" && ev.sp.res === "pass" && ev.dk.some(r => r.res === "pass") && ev.dm && !ev.dm.pass && !x.alignSeen) {
      x.alignSeen = true; note("alignement"); fig("alignement");
      out("SPF « pass », DKIM « pass »… et pourtant DMARC échoue : ils valident le domaine du prestataire, pas celui du « De ». C'est le principe de l'alignement.", "sys");
    }
    if (id === "malin" && ev.sp.res === "pass" && ev.dk.some(r => r.res === "pass") && ev.dm && !ev.dm.pass) {
      out("Mallory a, elle aussi, des « pass » valides… pour son propre domaine. Sans alignement, DMARC les prendrait pour de bons : c'est exactement pour cela qu'il l'exige.", "sys");
      if (!x.alignSeen) { x.alignSeen = true; note("alignement"); fig("alignement"); }
    }
    if ((id === "transfert" || id === "liste") && !x.fwdSeen) {
      x.fwdSeen = true; note("transferts");
      out(id === "transfert" ? "Le transfert change l'IP d'envoi : SPF échoue. La signature DKIM, elle, n'a pas bougé : c'est elle qui sauve le courrier une fois DMARC en place." : "La liste ajoute un pied de page et un préfixe : SPF et DKIM échouent tous les deux. Sous p=reject, ce courrier légitime serait refusé.", "sys");
    }
    if (id === "rejeu") {
      if (ev.dk.some(r => /expir/.test(r.why))) {
        if (!x.exp) { x.exp = true; out("L'expiration (x=) protège contre le rejeu tardif. Elle ne protège pas pendant la fenêtre de validité : signe aussi To et Date, et surveille les volumes.", "sys"); }
      } else if (ev.dk.some(r => r.res === "pass") && d.k === "inbox" && x.rej) {
        out("DMARC est en p=reject, et ce courrier arrive en boîte : sa signature est authentique (DKIM aligné). Seule l'expiration le bloquera : `dkim expire 3` au scriptorium.", "sys");
      } else if (!x.sign.on) out("Sans signature DKIM, il n'y a rien à rejouer ici : le courrier est bloqué par SPF/DMARC. (Ce test n'a de sens qu'avec DKIM actif.)", "sys");
    }
    if (id === "typo") {
      x.typo = true;
      out("Tout passe, pour le domaine de Mallory : DMARC ne protège QUE ton domaine. Un nom voisin qu'elle a enregistré lui-même est authentique à ses yeux. `surveiller` au registre liste ces noms.", "sys");
    }
    if (id === "piege") {
      x.piege = true;
      out("Tout passe, et pour cause : le courrier vient VRAIMENT de ton serveur, avec un VRAI compte. L'authentification prouve l'origine, pas l'honnêteté du contenu ni l'intégrité du compte (mot de passe fort, MFA).", "sys");
    }
    if (x.typo && x.piege && !x.limNote) { x.limNote = true; note("limites"); }
  }
  function tamperCmd(c) {
    const x = F();
    if (S.room !== "guichet") { out("Les modifications en transit se simulent au guichet (est du hall).", "sys"); return; }
    const t = norm(c.rawArg), kind = /corps|texte|montant/.test(t) ? "corps" : /sujet|objet/.test(t) ? "sujet" : /repon|reply/.test(t) ? "reponse" : null;
    if (!kind) { out("Quoi modifier ? `alterer corps` · `alterer sujet` · `alterer reponse`", "err"); return; }
    const m = mk("ada");
    if (!m.sigs.length) { out("Le courrier d'Ada n'est pas signé : il n'y a rien à casser ni à protéger. Publie une clé et active la signature au scriptorium (`dkim cle s1`, `dkim choisir s1`).", "sys"); return; }
    const sg = m.sigs[0], before = verifyDkim(m, sg);
    let what;
    if (kind === "corps") { m.body[1] = "la réunion est annulée : envoyez vos cotisations"; m.body[2] = "sur le compte PORT 0000 1234 (fictif)."; what = "le corps (un relais malhonnête change le compte à créditer)"; }
    else if (kind === "sujet") { m.h.subject = "URGENT : " + m.h.subject; what = "l'en-tête Subject"; }
    else { m.h["reply-to"] = "ada.direction@" + MALD; what = "l'en-tête Reply-To (les réponses iraient à Mallory)"; }
    const after = verifyDkim(m, sg);
    x.lastDkim = after;
    out(`Ève (jouée par Ada) modifie en transit : ${what}. On isole ici le contrôle DKIM (SPF et DMARC ne sont pas évalués).`, "sys");
    code(`en-têtes signés (h=) : ${sg.h.join(":")}\nDKIM avant : ${before.res} (${before.why})\nDKIM après : ${after.res} (${after.why})`);
    if (after.res === "fail") {
      out("**La modification est détectée** : DKIM échoue.", "ok");
      if (kind === "corps") x.tc = true;
      if (kind === "sujet") x.ts = true;
    } else {
      out(`**DKIM n'a rien vu** : l'en-tête ${kind === "sujet" ? "Subject" : "Reply-To"} n'est pas dans h=, donc pas signé. Un attaquant peut le changer à sa guise. Au scriptorium : \`dkim entetes from,to,subject,date,reply-to\`.`, "err");
    }
    if (x.tc && x.ts && !x.dkim2) {
      x.dkim2 = true;
      say("Maître Ada", "Corps et sujet sont désormais protégés. Une signature qui casse quand on triche, c'est ce qu'on veut. Maintenant, DMARC : retourne au registre et publie une politique, mais d'abord en mode observation.");
    }
  }
  function setCmd(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "guichet") { out("Les réglages de la liste se font au guichet (Bob).", "sys"); return; }
    if (/liste/.test(t)) {
      if (/reecri|from|domaine|oui|active/.test(t)) { x.listRew = true; out("La liste de diffusion réécrit désormais le « From » : « Maître Ada via la liste <liste@listes.port443> ». Le courrier passe alors par le domaine de la liste, qui l'authentifie lui-même (SPF et DKIM alignés avec listes.port443). `envoyer liste` pour essayer.", "ok"); afterChange(); }
      else if (/normal|non|desactiv|aucun/.test(t)) { x.listRew = false; out("La liste conserve le « From » d'origine (comportement par défaut).", "sys"); afterChange(); }
      else out("`regler liste reecriture` (la liste réécrit le From) ou `regler liste normal`.", "err");
    } else out("Réglage inconnu. `regler liste reecriture` · `regler liste normal`", "err");
  }
  function afterChange() {
    const x = F();
    if (!x.rapport) return;
    const lost = failLegit();
    if (lost === 0 && !x.cleanSaid) { x.cleanSaid = true; say("Maître Ada", "Plus aucune source légitime en échec : le rapport est propre. C'est le moment de resserrer, par étapes : quarantaine (d'abord une partie), puis refus."); }
    if (lost > 0) x.cleanSaid = false;
  }
  function waitCmd(c) {
    const x = F(), n = parseInt(c.rawArg, 10);
    if (!n || n < 1 || n > 400) { out("Combien de jours ? `attendre 10`", "err"); return; }
    x.day += n;
    out(`${n} jour(s) passent. Nous sommes le ${dateOf(nowT())} (jour ${x.day}).`, "sys");
  }

  /* ---------- Registre DNS : commandes ---------- */
  function spfCmd(c) {
    if (S.room !== "registre") { out("Le traçage SPF se fait au registre DNS (nord du hall).", "sys"); return; }
    const a = (c.rawArg || "").trim(), t = norm(a);
    let ip = null, label = "";
    const mi = /\b(\d{1,3}\.){3}\d{1,3}\b/.exec(a);
    if (mi) { ip = mi[0]; label = "l'adresse " + ip; }
    else { const id = pickSrc(t); if (id && IP[id]) { ip = IP[id]; label = { ada: "le serveur de courrier de la Guilde", campagne: "le prestataire de campagnes", facture: "le prestataire de facturation", transfert: "la redirection d'Alice", liste: "la liste de diffusion", mallory: "Mallory" }[id] + " (" + ip + ")"; } }
    if (!ip) { out("Quelle source ? `spf ada` · `spf mallory` · `spf campagne` · `spf facture` · `spf transfert` · `spf liste`, ou une adresse : `spf 203.0.113.10`", "err"); return; }
    const sp = spfEval(ip, DOM);
    F().lastSpf = sp;
    out(`Évaluation SPF de ${label} contre ${DOM} :`, "sys");
    code(sp.tr.map(r => "  ".repeat(r.d) + (r.k === "info" ? "• " + r.term + " : " : "") + (r.k === "info" ? r.eff : r.t)).join("\n") + `\n→ résultat : ${sp.res.toUpperCase()}   (recherches DNS : ${Math.min(sp.look, 11)}/10${sp.look > LIM ? ", limite dépassée" : ""})`);
    out({ pass: "SPF autorise cette IP.", fail: "SPF refuse cette IP (-all).", softfail: "SPF trouve cette IP suspecte mais n'en dit pas plus (~all).", neutral: "SPF n'a pas d'avis (?all) : c'est comme ne rien dire.", none: "Aucun SPF.", permerror: "ERREUR PERMANENTE : le récepteur ignore ton SPF. Plus de 10 recherches DNS (include, a, mx...), ou enregistrement invalide." }[sp.res], sp.res === "pass" ? "ok" : sp.res === "permerror" ? "err" : "sys");
  }
  function dnsCmd(c) {
    const x = F();
    if (S.room !== "registre") { out("La zone DNS se modifie au registre (nord du hall).", "sys"); return; }
    const a = (c.rawArg || "").trim(), sub = norm(a.split(/\s+/)[0] || "");
    const rest = a.slice((a.split(/\s+/)[0] || "").length).trim().replace(/^"(.*)"$/, "$1");
    if (!sub || sub === "voir") { out(zoneText(), "sys"); return; }
    if (sub === "spf") {
      if (!/^v=spf1(\s|$)/i.test(rest)) { out("Un enregistrement SPF commence par « v=spf1 » : `dns spf v=spf1 mx -all`", "err"); return; }
      x.zone.spf = rest;
      out("Enregistrement SPF publié :", "ok"); code(rest);
      const ada = spfEval(IP.ada, DOM), mal = spfEval(IP.mallory, DOM);
      x.lastSpf = mal;
      const perm = Object.values(IP).some(ip => spfEval(ip, DOM).res === "permerror");
      code(`serveur d'Ada (${IP.ada})      → ${ada.res}\nMallory (${IP.mallory})        → ${mal.res}   [${Math.min(mal.look, 11)}/10 recherches]`);
      if (perm) out("Une évaluation finit en **permerror** : plus de 10 recherches DNS (chaque include, a ou mx en coûte une, et les include imbriqués comptent aussi). Un SPF en erreur est ignoré. Retire ce qui ne sert plus : `spf ada` et `spf mallory` montrent où l'on se perd.", "err");
      else if (ada.res !== "pass") out("Ton propre serveur de courrier ne passe pas : tu bloques ta propre convocation. Ajoute `mx` (ou `ip4:" + IP.ada + "`).", "err");
      else if (!["fail", "softfail"].includes(mal.res)) out(`Mallory obtient « ${mal.res} » : la règle finale est trop laxiste (?all : aucun avis ; +all : tout le monde). Termine par -all (ou au minimum ~all).`, "err");
      else {
        out("Mallory est refusée, ton serveur passe, et l'évaluation tient dans la limite." + (/~all\s*$/i.test(rest) ? " (~all signale sans refuser : acceptable pendant le déploiement, -all est plus ferme.)" : ""), "ok");
        if (!x.spfok) { x.spfok = true; note("spf"); fig("spf"); say("Maître Ada", "Bien. Mais SPF ne regarde que l'IP et l'enveloppe : un transfert le casse, et il ne dit rien du contenu. Au scriptorium (ouest), on ajoute une signature : DKIM."); }
      }
      afterChange(); return;
    }
    if (sub === "dmarc") { dmarcPublish(rest); return; }
    if (sub === "delegue" || sub === "deleguer" || sub === "envoi") {
      if (x.zone.envoi) { out("La clé du prestataire est déjà publiée sous envoi1._domainkey." + DOM + ".", "sys"); return; }
      x.zone.envoi = true;
      out("Tu publies la clé publique fournie par le prestataire sous envoi1._domainkey." + DOM + ". Il signera désormais « info@" + NEWS + " » avec d=" + DOM + " : sa signature s'aligne avec ton domaine. `envoyer campagne` au guichet pour voir.", "ok");
      afterChange(); return;
    }
    out("Quoi publier ? `dns voir` · `dns spf ‹enregistrement›` · `dns dmarc ‹enregistrement›` · `dns delegue envoi`", "err");
  }
  function dmarcPublish(rest) {
    const x = F();
    if (!x.dkim2) { say("Maître Ada", "Pas encore : DMARC s'appuie sur SPF et DKIM. Termine d'abord les tests du scriptorium et du guichet (`alterer corps`, `alterer sujet`)."); return; }
    if (/^(aucun|supprimer|rien)$/i.test(rest)) { x.zone.dmarc = null; out("Enregistrement DMARC supprimé.", "sys"); return; }
    const pr = parseDmarc(rest);
    if (!pr.ok) { out("Enregistrement DMARC invalide : " + pr.err + " Exemple : `dns dmarc v=DMARC1; p=none; rua=mailto:rapports@guilde.port443`", "err"); return; }
    x.zone.dmarc = rest;
    out(`DMARC publié : politique ${pr.p}, pct=${pr.pct}, SPF ${pr.aspf === "s" ? "strict" : "relaxé"}, DKIM ${pr.adkim === "s" ? "strict" : "relaxé"}, rapports ${pr.rua ? "à " + pr.rua : "aucun (pas de rua)"}.`, "ok");
    const P = profile();
    if (pr.p === "none") {
      if (!pr.rua) out("p=none sans rua : tu n'observes rien, personne ne t'enverra de rapport. Ajoute `rua=mailto:rapports@guilde.port443`.", "err");
      else if (!x.d0) { x.d0 = true; note("dmarc"); say("Maître Ada", "Parfait : on observe sans rien bloquer. Les rapports des récepteurs arriveront ; va les lire dans la salle des rapports (sud du hall)."); }
      return;
    }
    const lost = P.legitLost, ok = lost === 0;
    out(`Rejeu du trafic de la semaine avec cette politique : ${P.legitTot - P.legitLost}/${P.legitTot} courriers légitimes livrés, ${P.spoofStopped}/${P.spoofTot} courriers usurpés arrêtés.`, ok ? "ok" : "err");
    if (!ok) {
      x.hasty = true;
      const bad = P.rows.filter(r => r.legit && r.bd.spam + r.bd.reject > 0).map(r => `· ${r.ptr} : ${r.bd.spam + r.bd.reject} courriers ${r.bd.reject ? "refusés" : "en indésirables"}`);
      out("**Tu perds du courrier légitime** :\n" + bad.join("\n"), "err");
      say("Alice", "Les factures ne partent plus, et la lettre d'information non plus ! On aurait dû regarder les rapports d'abord.");
      out("Reviens en arrière (`dns dmarc v=DMARC1; p=none; rua=mailto:rapports@guilde.port443`), lis les rapports, corrige les sources, puis resserre.", "sys");
      return;
    }
    if (!x.d0 || !x.rapport) { out("Aucune perte… mais tu n'as pas observé avant : sans rapports, tu ne sais pas ce que tu ignores. (Cette étape ne compte pas encore : publie p=none avec rua, lis `rapports`.)", "sys"); return; }
    if (pr.p === "quarantine") { if (!x.q) { x.q = true; note("deploiement"); fig("deploiement"); say("Maître Ada", "Aucune perte en quarantaine. Monte le pourcentage jusqu'à 100, puis passe à reject quand tu es sûr."); } }
    if (pr.p === "reject") {
      if (pr.pct < 100) out("Avec pct<100, la part non ciblée est mise en quarantaine, pas livrée : pour finir, il faut pct=100.", "sys");
      else if (!x.rej) {
        x.rej = true; x.q = true; if (!S.notes.includes("deploiement")) note("deploiement");
        fig("deploiement");
        say("Maître Ada", "Refus total, sans perte : c'est un déploiement réussi. Mais Mallory n'a pas dit son dernier mot. Retourne au guichet.");
      }
    }
  }
  function watchCmd() {
    const x = F();
    if (S.room !== "registre") { out("La veille des domaines se consulte au registre (nord du hall).", "sys"); return; }
    const lev = (a, b) => { const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]); for (let j = 1; j <= b.length; j++) d[0][j] = j; for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); return d[a.length][b.length]; };
    const L = ["gui1de.port443", "guilde.p0rt443", "guilde-port443.port443", "guild3.port443", "marchands.port443", "port443.port443"];
    out("Domaines nouvellement enregistrés (flux fictif), comparés à " + DOM + " :", "sys");
    code(L.map(d => d.padEnd(26) + "distance " + lev(d, DOM) + (lev(d, DOM) <= 2 ? "  ← ressemble au tien" : "")).join("\n"));
    out("Ni SPF, ni DKIM, ni DMARC ne protègent contre ces noms : ils ne sont pas à toi. Parades : les enregistrer à l'avance, les surveiller, demander leur retrait, et former les destinataires.", "sys");
    x.watch = true;
  }

  /* ---------- Scriptorium : DKIM ---------- */
  function dkimCmd(c) {
    const x = F();
    if (S.room !== "scriptorium") { out("La signature se règle au scriptorium (ouest du hall).", "sys"); return; }
    const a = (c.rawArg || "").trim().split(/\s+/), sub = norm(a[0] || ""), arg = norm(a.slice(1).join(" "));
    const selOf = s => (/^s[12]$/.test(s) ? s : null);
    if (!sub || sub === "voir") { out(dkimText(), "sys"); return; }
    if (sub === "cle") {
      const s = selOf(arg); if (!s) { out("Quel sélecteur ? `dkim cle s1` ou `dkim cle s2`.", "err"); return; }
      x.zone.keys[s] = "pub";
      out(`Une paire de clés est créée pour le sélecteur ${s}. La clé PRIVÉE reste sur le serveur ; la clé PUBLIQUE est publiée dans le DNS :`, "ok");
      code(`${s}._domainkey.${DOM}  TXT  "${pubTxt(OWNKEY[s])}"`);
      out("(Clé jouet : RSA de 52 bits, trop petite pour la vraie vie ; en pratique RSA 2048 ou Ed25519.) Prochaine étape : `dkim choisir " + s + "`.", "sys");
      return;
    }
    if (sub === "choisir") {
      const s = selOf(arg); if (!s) { out("Quel sélecteur ? `dkim choisir s1`", "err"); return; }
      x.sign.on = true; x.sign.sel = s;
      out(`Le serveur signe désormais avec le sélecteur ${s}.`, "ok");
      if (x.zone.keys[s] !== "pub") out(`Attention : aucune clé publique active pour ${s} dans le DNS. Les récepteurs ne pourront pas vérifier : DKIM sera en erreur (${x.zone.keys[s] === "revoked" ? "clé révoquée" : "clé introuvable"}). \`dkim cle ${s}\`.`, "err");
      checkRot(); return;
    }
    if (sub === "entetes" || sub === "headers") {
      const names = (a.slice(1).join(" ").toLowerCase().split(/[\s,:;]+/).filter(Boolean));
      const OK = ["from", "to", "cc", "subject", "date", "reply-to", "message-id"], good = names.filter(n => OK.includes(n));
      if (!good.length) { out("Donne une liste : `dkim entetes from,to,subject,date,reply-to`. Noms valides : " + OK.join(", ") + ".", "err"); return; }
      x.sign.h = [...new Set(good)];
      out(`En-têtes signés (h=) : ${x.sign.h.join(":")}.`, "ok");
      if (!x.sign.h.includes("from")) out("Sans « from » dans h=, le récepteur rejette la signature (permerror) : l'en-tête From est obligatoire.", "err");
      else if (!x.sign.h.includes("subject") || !x.sign.h.includes("reply-to")) out("Subject et Reply-To ne sont pas protégés : un en-tête non signé reste modifiable.", "sys");
      return;
    }
    if (sub === "expire" || sub === "expiration") {
      const n = parseInt(arg, 10);
      if (isNaN(n) || n < 0 || n > 365) { out("Combien de jours ? `dkim expire 3` (0 pour aucune expiration).", "err"); return; }
      x.sign.ttl = n;
      out(n ? `Les signatures expirent ${n} jour(s) après leur création (tag x=). Un courrier rejoué plus tard échouera.` : "Plus d'expiration : une signature vaut pour toujours.", n ? "ok" : "sys");
      return;
    }
    if (sub === "revoquer") {
      const s = selOf(arg); if (!s) { out("Quel sélecteur ? `dkim revoquer s1`", "err"); return; }
      if (x.zone.keys[s] !== "pub") { out(`Le sélecteur ${s} n'a pas de clé publiée.`, "sys"); return; }
      x.zone.keys[s] = "revoked";
      out(`Clé ${s} révoquée : l'enregistrement devient « v=DKIM1; p= » (clé vide).`, "ok");
      if (x.sign.sel === s) out(`Mais tu signes encore avec ${s} : tout ton courrier échoue DKIM. Bascule d'abord (\`dkim choisir ...\`).`, "err");
      checkRot(); return;
    }
    out("`dkim voir` · `dkim cle ‹s1|s2›` · `dkim choisir ‹s1|s2›` · `dkim entetes ‹liste›` · `dkim expire ‹jours›` · `dkim revoquer ‹s1|s2›`", "err");
  }
  function checkRot() {
    const x = F();
    if (x.rot || x.zone.keys.s1 !== "revoked" || x.zone.keys.s2 !== "pub" || x.sign.sel !== "s2") return;
    const m = mk("ada"), ok = m.sigs.length && verifyDkim(m, m.sigs[0]).res === "pass";
    if (!ok) return;
    x.rot = true; note("dkimvie");
    say("Maître Ada", "Rotation propre : nouvelle clé publiée avant la bascule, ancienne révoquée après. Et ton courrier légitime n'a pas bronché.");
  }

  /* ---------- Rapports ---------- */
  function reportCmd() {
    const x = F();
    if (S.room !== "rapports") { out("Les rapports sont dans la salle des rapports (sud du hall).", "sys"); return; }
    const pr = x.zone.dmarc ? parseDmarc(x.zone.dmarc) : null;
    if (!pr || !pr.ok || !pr.rua) { out("Aucun rapport n'arrive : ton enregistrement DMARC n'a pas de rua= (adresse de rapports).", "err"); return; }
    const P = profile();
    out(`Rapport agrégé DMARC pour ${DOM} : une semaine de trafic (rejoué avec ta configuration actuelle), politique p=${pr.p}${pr.pct < 100 ? " pct=" + pr.pct : ""}.`, "title");
    const lines = P.rows.map(r => {
      const ev = r.ev, dm = ev.dm;
      const s = ev.sp.res + (ev.sp.res === "pass" ? (dm.spfAl ? " aligné" : " non aligné") : "");
      const d = ev.dk.length ? ev.dkBest + (ev.dkBest === "pass" ? (dm.dkAl ? " aligné" : " non aligné") : "") : "aucune";
      const b = r.bd, eff = [b.inbox && b.inbox + " livrés", b.spam && b.spam + " indésirables", b.reject && b.reject + " refusés"].filter(Boolean).join(", ");
      return `${IP[r.id === "malin" ? "mallory" : r.id].padEnd(15)}${r.ptr.padEnd(30)}${String(r.vol).padStart(5)}\n  SPF ${s} · DKIM ${d}\n  DMARC ${dm.pass ? "pass" : "FAIL"} → ${eff}`;
    });
    code(lines.join("\n"));
    const lf = P.legitFail;
    out(`Sources qui échouent DMARC : ${P.rows.filter(r => r.ev.dm && !r.ev.dm.pass).length}. Dont ${lf} courrier(s) de sources que tu reconnais comme légitimes ? Un rapport ne dit pas qui est légitime : c'est à toi d'identifier chaque adresse (Bob connaît les expéditeurs du guichet).`, "sys");
    if (!x.rapport) {
      x.rapport = true;
      say("Maître Ada", "Voilà la vérité du terrain. Les lignes en échec ne sont pas toutes des attaquants : certaines sont des gens à nous qu'on avait oubliés. Parle à Bob pour savoir qui est qui, puis corrige chaque source légitime.");
    }
    afterChange();
  }

  /* ---------- Dialogues ---------- */
  const ADA = {
    spoof: "Au guichet, à l'est : fais écrire à Mallory un courrier « De : direction@guilde.port443 », et regarde comment le bureau destinataire réagit.",
    spf: "Au registre DNS (nord), regarde notre enregistrement SPF avec `spf mallory` : il est cassé. Puis publie-en un qui autorise notre serveur de courrier et refuse le reste.",
    dkim1: "Au scriptorium (ouest) : crée une clé, active la signature, puis teste avec `envoyer ada` au guichet.",
    dkim2: "Une signature qui ne casse pas quand on triche ne sert à rien. Au guichet : `alterer corps`, `alterer sujet`, et élargis la liste des en-têtes signés si besoin.",
    dmarc0: "Au registre : publie DMARC en observation (p=none) avec une adresse de rapports.",
    rapport: "Salle des rapports, au sud : lis `rapports`.",
    fix: "Il reste des sources légitimes en échec. Bob, au guichet, sait qui est qui ; les rapports te disent comment ça échoue.",
    quar: "Plus de perte : resserre. Quarantaine d'abord, avec un pourcentage qui monte.",
    rej: "Passe à `p=reject` à 100 %, par le registre.",
    replay: "Mallory a gardé un vrai courrier signé. Au guichet : `attendre 10`, `envoyer rejeu` ; puis limite la vie des signatures (`dkim expire 3`).",
    rot: "Dernier ménage : la rotation de clé au scriptorium (`dkim cle s2`, `dkim choisir s2`, `dkim revoquer s1`).",
    typo: "Teste le domaine voisin de Mallory au guichet : `envoyer typo`.",
    piege: "Dernier cas, au guichet : `envoyer piege`.",
  };
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada": {
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue au Bureau de Poste. Une vérité qui dérange : dans le courrier de base, n'importe qui peut écrire « De : direction@guilde.port443 ». Le protocole ne vérifie rien. Mon nom se falsifie en une ligne.");
          say("Maître Ada", "Ton travail : publier les bons enregistrements DNS pour que le courrier légitime de la Guilde passe et que le faux soit refusé, sans perdre une seule lettre vraie. Tout est simulé, sur des données fictives. Va au guichet, à l'est.");
          out("`aller est`, puis `envoyer mallory`.", "sys");
        } else if (x.end) say("Maître Ada", "Merci. Le bureau tient, et les lettres vraies arrivent.");
        else if (objective() === "end") ending();
        else say("Maître Ada", ADA[objective()] || "L'audit continue. `indice` si tu bloques.");
        break;
      }
      case "bob":
        if (!x.rapport) say("Bob", "Je trie les lettres et je tamponne. Si tu veux des réponses sur nos expéditeurs, lis d'abord un rapport DMARC : on pourra comparer.");
        else {
          say("Bob", "Voici nos expéditeurs légitimes. Le serveur de courrier mail.guilde.port443. Le prestataire de lettres d'information (s1.envoi.port443). Le prestataire de facturation (relais.facture-cloud.port443) : on l'avait oublié ! La redirection automatique d'Alice (redirection.alice.port443). Et la liste de diffusion des membres (relais.listes.port443). Le reste, je ne connais pas.");
          if (!x.bobTalk) { x.bobTalk = true; out("Le rapport te donne l'IP ; Bob te donne le nom. À toi de décider quoi corriger.", "sys"); }
        }
        break;
      case "alice":
        if (!x.spfok) say("Alice", "Voici la zone : un SPF hérité d'un ancien administrateur. Il liste des prestataires dont on n'a plus entendu parler depuis des années. Et je me demande combien de recherches DNS il coûte...");
        else if (!x.d0) say("Alice", "Chaque enregistrement a son rôle : SPF pour les serveurs, DKIM pour les signatures, DMARC pour la politique.");
        else say("Alice", "Rappel : j'ai une redirection de mon courrier professionnel vers ma boîte personnelle. Si ça casse, ce sera la faute de qui ?");
        break;
      case "eve":
        if (!x.dkimok) say("Ève", "Je regarde passer les courriers. Sans signature, je peux changer ce qui me plaît en chemin, personne ne le saura.");
        else say("Ève", "Avec une signature, je ne peux plus toucher au corps sans que ça se voie. Mais ce que je ne suis pas censée modifier... encore faut-il que ce soit signé. Et si je garde un courrier signé pour le renvoyer plus tard ?");
        break;
      case "mallory":
        say("Mallory", "(Jouée par Ada, pour l'exercice.) J'écris ce que je veux dans « De ». Utilise `envoyer ‹courrier›` pour me voir tenter, et regarde quels contrôles m'arrêtent, ou pas.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Le domaine de la Guilde est protégé : SPF, DKIM, DMARC en reject, et rien de légitime n'a été perdu. Nous allons surveiller les noms voisins, renouveler les clés chaque année, et regarder du côté d'ARC pour les listes et de BIMI pour afficher notre logo. Mais retiens-le : ces enregistrements disent QUI envoie, jamais si le message est honnête.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le Bureau de Poste = SMTP.** L'enveloppe (MAIL FROM) et la lettre (« From: ») portent deux adresses, toutes deux déclarées par l'expéditeur. Le protocole d'origine ne vérifie rien : SPF, DKIM et DMARC sont venus après, en s'appuyant sur le DNS.");
    out("**Le registre des facteurs autorisés = SPF.** Un enregistrement TXT liste les IP qui peuvent envoyer pour le domaine de l'enveloppe : ip4, a, mx, include, puis -all, ~all, ?all ou +all. Le récepteur l'évalue de gauche à droite et s'arrête à la première correspondance ; include, a, mx et redirect comptent pour 10 recherches DNS au maximum (permerror au-delà). Trop de prestataires imbriqués, un prestataire oublié (la facturation), ou une règle finale trop laxiste sont les erreurs classiques.");
    out("**Le sceau de cire = DKIM.** La signeuse canonise les en-têtes choisis (h=) et le corps (bh=), signe avec une clé privée ; le récepteur lit la clé publique à sélecteur._domainkey.domaine et recalcule. Corps modifié : échec. En-tête non signé : modifiable sans le voir. Expiration (x=) contre le rejeu, rotation de clés par sélecteurs successifs, révocation par un p= vide.");
    out("**Le règlement du bureau = DMARC.** Il demande qu'un SPF ou un DKIM réussisse ET soit aligné avec le domaine du « From » (relaxé : même domaine d'organisation ; strict : identique), puis dit quoi faire de l'échec : none, quarantine, reject, pour un pct des cas. Les rapports agrégés (rua) montrent toutes les sources, légitimes comme pirates.");
    out("**Le déploiement progressif.** p=none et rapports, correction de chaque source légitime (prestataire de facturation dans le SPF, prestataire de campagnes en DKIM aligné, liste qui réécrit le From), quarantine avec un pourcentage croissant, puis reject. À aucun moment on ne perd de courrier légitime.");
    out("**Transferts et listes.** Un transfert casse SPF mais DKIM survit s'il n'a pas touché au message ; une liste qui modifie le corps casse les deux. Remèdes : réécrire le From, et ARC (chaîne d'attestations des intermédiaires, que le récepteur est libre d'ignorer). BIMI affiche le logo de la marque, à condition d'avoir DMARC en quarantine ou reject.");
    out("**Les simplifications du jeu.** (1) Le DNS est fictif et réduit à quelques enregistrements ; le trafic de la semaine est un petit jeu de sept sources rejoué avec ta configuration. (2) DKIM utilise une RSA de 52 bits sans remplissage, une canonisation simplifiée et une signature unique par courrier ; en vrai : 2048 bits ou Ed25519, canonisation « simple » ou « relaxed », signatures multiples, l= possible. (3) Le récepteur fictif suit un modèle lisible : sans DMARC, il rejette sur « fail » SPF ; les vrais récepteurs combinent réputation, apprentissage et leurs propres règles, et ne suivent pas toujours DMARC à la lettre. (4) Le domaine d'organisation est « les deux derniers labels » (en vrai : la liste des suffixes publics) ; sp=, ruf=, redirect= et ptr ne sont pas modélisés. (5) pct est appliqué de façon déterministe ; ARC et BIMI sont seulement mentionnés. (6) L'évaluation SPF s'arrête à la première correspondance mais ne modélise pas les erreurs temporaires du DNS. (7) Tout est simulé sur des données fictives, dans un cadre d'audit autorisé.");
    out("Rappel utile : **SPF, DKIM et DMARC prouvent QUI envoie, pas que le message est honnête. Déploie-les dans l'ordre (observer, corriger, resserrer), surveille les noms de domaine voisins, protège les comptes avec un second facteur, et reste méfiant devant le contenu d'un message, même parfaitement authentifié.**", "ok");
  }

  /* ---------- Schémas ---------- */
  const lastOr = () => { const x = F(); if (x.last) return x.last; const m = mk("ada"), ev = evaluate(m); return { id: "ada", m, ev, d: single(ev, 0) }; };
  const figs = {
    chemin: () => {
      const L = lastOr(), m = L.m, ev = L.ev, d = L.d;
      const box = r => (r === "pass" ? "f-ok" : r === "none" ? "" : "f-bad"), tc = r => (r === "pass" ? "ft-ok" : r === "none" ? "" : "ft-bad");
      const dmr = ev.dm ? (ev.dm.pass ? "pass" : "fail") : "none";
      return {
        cap: "Le chemin d'un courrier et les trois contrôles du récepteur. Couleurs : résultat du dernier courrier envoyé au guichet.",
        svg: SVG(258, "Chemin d'un courrier et trois contrôles",
          R(8, 14, 130, 58) + T(73, 33, "Envoyeur", "f-b") + T(73, 49, "IP " + m.ip, "f-s") + T(73, 63, cut("De : " + ev.fd, 21), "f-s") +
          AR(138, 43, 282, 43) + T(210, 36, "SMTP", "f-s") +
          R(282, 14, 130, 58, "f-pub") + T(347, 33, "Récepteur", "f-b ft-pub") + T(347, 49, "bureau de poste", "f-s") + T(347, 63, "(DNS : lit les clés)", "f-s") +
          LN(347, 72, 347, 86) + LN(73, 86, 347, 86) + AR(73, 86, 73, 100) + AR(210, 86, 210, 100) + AR(347, 86, 347, 100) +
          R(8, 100, 130, 80, box(ev.sp.res)) + T(73, 118, "① SPF", "f-b " + tc(ev.sp.res)) + T(73, 135, ev.sp.res, "f-b " + tc(ev.sp.res)) + T(73, 152, "IP contre", "f-s") + T(73, 166, cut(ev.mfd, 19), "f-s") +
          R(145, 100, 130, 80, box(ev.dkBest)) + T(210, 118, "② DKIM", "f-b " + tc(ev.dkBest)) + T(210, 135, ev.dkBest, "f-b " + tc(ev.dkBest)) + T(210, 152, "signature de", "f-s") + T(210, 166, ev.dk.length ? cut(ev.dk[0].d, 19) : "(aucune)", "f-s") +
          R(282, 100, 130, 80, box(dmr)) + T(347, 118, "③ DMARC", "f-b " + tc(dmr)) + T(347, 135, dmr, "f-b " + tc(dmr)) + T(347, 152, ev.dm ? "p=" + ev.dm.pol.p : "pas de politique", "f-s") + T(347, 166, ev.dm ? (ev.dm.pass ? "aligné" : "non aligné") : "", "f-s") +
          AR(210, 180, 210, 196) +
          R(8, 196, 404, 50, d.k === "inbox" ? "f-ok" : "f-bad") + T(210, 216, { inbox: "Livré en boîte de réception", spam: "Mis en quarantaine", reject: "Rejeté à la réception" }[d.k], "f-b " + (d.k === "inbox" ? "ft-ok" : "ft-bad")) + T(210, 234, cut(d.why, 56), "f-s"))
      };
    },
    spf: () => {
      const x = F(), sp = x.lastSpf || spfEval(IP.mallory, DOM);
      const rows = sp.tr.filter(r => r.k !== "info" || r.d === 0);
      const shown = rows.slice(0, 11), cls = { hit: "ft-ok", err: "ft-bad", no: "", inc: "ft-pub", info: "ft-pub" };
      let b = T(8, 14, cut("IP " + sp.ip + " contre le SPF de " + sp.dom, 62), "f-b", "start");
      for (let i = 0; i < 10; i++) b += `<rect x="${8 + i * 21}" y="24" width="17" height="12" rx="3" class="f-box ${i < Math.min(sp.look, 10) ? (sp.look > 10 ? "f-bad" : "f-pub") : ""}"/>`;
      b += T(226, 34, "recherches DNS : " + sp.look + " / 10", "f-s " + (sp.look > 10 ? "ft-bad" : ""), "start");
      shown.forEach((r, i) => { const y = 58 + i * 17; b += T(8 + r.d * 12, y, cut(r.k === "info" ? "▸ " + r.term : r.term, 34 - r.d * 2), "f-s " + (cls[r.k] || ""), "start") + (r.k === "info" ? "" : T(412, y, cut(r.eff, 26), "f-s " + (cls[r.k] || ""), "end")); });
      if (rows.length > shown.length) b += T(8, 58 + shown.length * 17, "… (" + (rows.length - shown.length) + " étapes de plus)", "f-s", "start");
      const yy = 58 + (shown.length + (rows.length > shown.length ? 1 : 0)) * 17 + 14;
      b += R(8, yy - 12, 404, 28, sp.res === "pass" ? "f-ok" : sp.res === "permerror" ? "f-bad" : "") + T(210, yy + 6, "Résultat : " + sp.res.toUpperCase(), "f-b " + (sp.res === "pass" ? "ft-ok" : sp.res === "permerror" || sp.res === "fail" ? "ft-bad" : ""));
      return { cap: "Évaluation SPF pas à pas : l'enregistrement est lu de gauche à droite jusqu'à la première correspondance ; include, a et mx coûtent chacun une recherche DNS (limite : 10).", svg: SVG(yy + 24, "Évaluation SPF pas à pas", b) };
    },
    dkim: () => {
      const x = F(), s = x.sign, m = mk("ada"), bh = bodyHash(m.body).slice(0, 12), ld = x.lastDkim;
      const res = ld ? ld.res : "pass", why = ld ? ld.why : "corps et en-têtes intacts";
      return {
        cap: "DKIM : le serveur signe en-têtes choisis + empreinte du corps ; le récepteur refait le calcul avec la clé publique du DNS.",
        svg: SVG(250, "Signature et vérification DKIM",
          R(8, 14, 196, 62, "f-pub") + T(106, 32, "① en-têtes signés (h=)", "f-b ft-pub") + T(106, 49, cut(s.h.join(":"), 30), "f-s") + T(106, 65, "(valeurs canonisées)", "f-s") +
          R(216, 14, 196, 62, "f-pub") + T(314, 32, "② corps", "f-b ft-pub") + T(314, 49, "bh = sha256 : " + bh, "f-s") + T(314, 65, "(canonisé)", "f-s") +
          AR(106, 76, 106, 98) + AR(314, 76, 314, 98) +
          R(8, 98, 404, 56, "f-priv") + T(210, 116, "③ b = signature de (① + ② + date) avec la clé privée", "f-b ft-priv f-s") + T(210, 133, "sélecteur : " + (s.on ? s.sel : "(aucun)") + (s.ttl ? " · expire dans " + s.ttl + " j" : " · sans expiration"), "f-s") + T(210, 148, "courrier = en-têtes + corps + signature", "f-s") +
          AR(210, 154, 210, 174) +
          R(8, 174, 404, 66, res === "pass" ? "f-ok" : "f-bad") + T(210, 192, "④ le récepteur lit la clé publique (DNS) et refait ① ②", "f-b f-s") + T(210, 212, "DKIM : " + res, "f-b " + (res === "pass" ? "ft-ok" : "ft-bad")) + T(210, 230, cut(why, 58), "f-s"))
      };
    },
    alignement: () => {
      const L = lastOr(), m = L.m, ev = L.ev, fd = ev.fd, pol = ev.pol || { aspf: "r", adkim: "r" };
      const rel = (a, b, mode) => (mode === "s" ? a === b : org(a) === org(b));
      const sa = rel(ev.mfd, fd, pol.aspf), sp = ev.sp.res === "pass";
      const dkp = ev.dk.find(r => r.res === "pass"), da = dkp ? rel(dkp.d, fd, pol.adkim) : false;
      const pass = (sp && sa) || (dkp && da);
      const row = (y, nm, res, dom, ok, mode, passRes) => R(8, y, 404, 62, ok ? "f-ok" : "f-bad") + T(16, y + 18, nm + " : " + res, "f-b f-s", "start") + T(16, y + 36, "domaine validé : " + cut(dom, 26), "f-s", "start") + T(16, y + 52, passRes ? (ok ? "aligné avec le « De » (" + (mode === "s" ? "strict" : "relaxé") + ") ✔" : "NON aligné avec le « De » (" + (mode === "s" ? "strict" : "relaxé") + ") ✘") : "rien à aligner", "f-b f-s " + (ok ? "ft-ok" : "ft-bad"), "start");
      return {
        cap: "L'alignement DMARC : le « pass » de SPF ou de DKIM n'est utile que s'il porte sur le même domaine que le « De » affiché.",
        svg: SVG(250, "Alignement DMARC",
          R(8, 12, 404, 36, "f-pub") + T(16, 28, "« De » affiché : " + cut(fromAddr(m), 30), "f-s", "start") + T(16, 42, "domaine à protéger : " + fd, "f-b ft-pub f-s", "start") +
          row(58, "SPF", ev.sp.res, ev.mfd, sp && sa, pol.aspf, sp) +
          row(126, "DKIM", dkp ? "pass" : ev.dkBest, dkp ? dkp.d : ev.dk.length ? ev.dk[0].d : "(aucune signature)", da, pol.adkim, !!dkp) +
          T(210, 208, pass ? "DMARC : au moins un pass aligné → réussi" : "DMARC : aucun pass aligné → échec", "f-b " + (pass ? "ft-ok" : "ft-bad")) +
          T(210, 228, "relaxé : même domaine d'organisation · strict : domaine identique", "f-s"))
      };
    },
    deploiement: () => {
      const stages = [["none", 100, "p=none"], ["quarantine", 10, "q 10 %"], ["quarantine", 50, "q 50 %"], ["quarantine", 100, "q 100 %"], ["reject", 100, "reject"]];
      let b = T(8, 14, "Courrier légitime perdu (rouge) · usurpation arrêtée (vert)", "f-s", "start");
      b += LN(30, 30, 30, 150) + LN(30, 150, 412, 150);
      [0, 50, 100].forEach(v => { b += T(26, 154 - v * 1.2, v + "%", "f-s", "end"); });
      stages.forEach(([p, pct, lbl], i) => {
        const P = profile({ p, pct }), lp = 100 * P.legitLost / P.legitTot, sp = 100 * P.spoofStopped / P.spoofTot, x0 = 44 + i * 74;
        b += `<rect x="${x0}" y="${150 - lp * 1.2}" width="28" height="${lp * 1.2}" rx="3" fill="var(--bad)" opacity=".75"/><rect x="${x0 + 30}" y="${150 - sp * 1.2}" width="28" height="${sp * 1.2}" rx="3" fill="var(--ok)" opacity=".75"/>` + T(x0 + 29, 168, lbl, "f-s") + T(x0 + 14, 146 - lp * 1.2, Math.round(lp) ? Math.round(lp) + "" : "", "f-s ft-bad") + T(x0 + 44, 146 - sp * 1.2, Math.round(sp) ? Math.round(sp) + "" : "", "f-s ft-ok");
      });
      b += T(210, 192, "Courbe de ta configuration actuelle, étape par étape.", "f-s") + T(210, 210, "Une source légitime oubliée fait monter le rouge dès la quarantaine.", "f-s");
      return { cap: "Déploiement progressif : pour chaque étape, part du courrier légitime perdu et de l'usurpation arrêtée, calculées sur le trafic de la semaine avec ta configuration actuelle.", svg: SVG(222, "Courbe de déploiement DMARC", b) };
    },
  };

  GAMES.mailauth = {
    id: "mailauth", order: 31, title: "Le Bureau de Poste", pageTitle: "Mail Auth Quest", subtitle: "aventure textuelle · SPF, DKIM, DMARC",
    blurb: "Fais écrire à Mallory « De : direction » puis publie SPF, DKIM et DMARC pour rejeter le faux sans perdre le vrai courrier.",
    concept: "Authentification du courrier : SPF, DKIM, DMARC",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    figAlias: { chemin: ["courrier", "controles", "path"], spf: ["evaluation", "enregistrement"], dkim: ["signature", "cle"], alignement: ["align", "dmarc"], deploiement: ["courbe", "progressif", "etapes"] },
    setup() {
      const x = F();
      x.day = 0; x.zone = { spf: INIT_SPF, dmarc: null, keys: {}, envoi: false };
      x.sign = { on: false, sel: null, h: ["from"], ttl: 0 };
      x.listRew = false; x.n = 0; x.last = null; x.lastSpf = null; x.lastDkim = null;
    },
    gate(dest) {
      const x = F();
      if (dest === "registre" && !x.spoof) { say("Maître Ada", "Pas encore : commence par le guichet (est), pour voir ce que fait Mallory."); return true; }
      if (dest === "scriptorium" && !x.spfok) { say("Maître Ada", "Une chose à la fois : le SPF d'abord (registre, au nord)."); return true; }
      if (dest === "rapports" && !x.d0) { say("Maître Ada", "Les rapports n'arrivent qu'une fois DMARC publié avec une adresse rua. Retourne au registre."); return true; }
      return false;
    },
    verbs: {
      send: { words: ["envoyer", "expedier", "poster", "deposer"], run: sendCmd },
      tamper: { words: ["alterer", "falsifier", "modifier"], run: tamperCmd },
      dns: { words: ["dns", "publier"], run: dnsCmd },
      spf: { words: ["spf", "tracer", "evaluer"], run: spfCmd },
      dkim: { words: ["dkim"], run: dkimCmd },
      reports: { words: ["rapports", "rapport"], run: reportCmd },
      set: { words: ["regler", "configurer", "parametrer"], run: setCmd },
      wait: { words: ["attendre", "patienter"], run: waitCmd },
      watch: { words: ["surveiller", "veille"], run: watchCmd },
    },
    help: "Spécifiques : `envoyer ‹courrier›` · `alterer corps|sujet|reponse` · `dns spf|dmarc ‹enregistrement›` · `dns delegue envoi` · `spf ‹source›` · `dkim cle|choisir|entetes|expire|revoquer` · `rapports` · `regler liste reecriture` · `attendre ‹jours›` · `surveiller`",
    intro() {
      out("Le Bureau de Poste", "title");
      out("Dans le courrier de base, n'importe qui peut écrire « De : direction@guilde.port443 » : le protocole ne vérifie rien. Maître Ada t'engage pour un audit autorisé : publier, dans le DNS fictif de la Guilde, les enregistrements SPF, DKIM et DMARC qui font passer le courrier légitime et rejeter le faux, sans perdre une lettre vraie. Tout est simulé, sur des données fictives.", "");
    },
  };
})();
