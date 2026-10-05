"use strict";
/* La Salle des Journaux : journaux, détection d'intrusion, règles d'alerte.
   Jeux de données fictifs générés de façon déterministe (environ 5 500 lignes, une intrusion cachée dans le bruit normal).
   Le mini-langage de requête, l'évaluation des règles et la chaîne d'empreintes (SHA-256) sont réels. */
(function () {
  const F = () => f();
  const DAY = 86400, TOL = 10;
  const ATT = "203.0.113.66", SPR = "203.0.113.141", EXF = "198.51.100.99";
  const WEB1 = "10.0.2.10", DB1 = "10.0.3.30", BKP = "10.0.3.40", SVC = "10.0.3.55", NAT = "192.0.2.77", CRAWL = "198.51.100.200";
  const KNOWN = [["192.0.2.10", "serveur de mises à jour"], ["192.0.2.25", "relais de courrier"], ["192.0.2.50", "sauvegarde externalisée (chaque nuit)"], ["192.0.2.80", "réseau de diffusion de contenus (CDN)"]];
  const MAL = new Set([ATT, SPR]);
  const FIX = { auth: 0, web: -3600, fw: 0, sys: 271 }; // correction à appliquer à chaque source pour retrouver l'heure UTC
  const SRCS = { auth: "auth", web: "web", fw: "pare-feu", sys: "systeme" };
  const FIELDS = {
    auth: ["heure", "ip", "user", "resultat", "service"],
    web: ["heure", "ip", "methode", "chemin", "code", "octets"],
    fw: ["heure", "ip", "dst", "port", "action", "sens", "octets"],
    sys: ["heure", "hote", "user", "evenement", "ip", "detail"],
  };
  const NUMF = new Set(["code", "port", "octets"]);

  /* ---------- outils ---------- */
  const hms = s => { s = ((Math.round(s) % DAY) + DAY) % DAY; return [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60].map(v => String(v).padStart(2, "0")).join(":"); };
  const hm2s = str => { const m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(str); return m && +m[1] < 24 && +m[2] < 60 && +(m[3] || 0) < 60 ? (+m[1]) * 3600 + (+m[2]) * 60 + (+(m[3] || 0)) : null; };
  const fo = n => n >= 1e9 ? (n / 1e9).toFixed(2).replace(".", ",") + " Go" : n >= 1e6 ? (n / 1e6).toFixed(1).replace(".", ",") + " Mo" : n >= 1e3 ? (n / 1e3).toFixed(1).replace(".", ",") + " Ko" : n + " o";
  const dec = s => { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch (e) { return s; } };
  const pct = v => Math.round(v * 100) + " %";
  const nf = n => n.toLocaleString("fr-FR");
  const durTxt = s => { const a = Math.abs(s), h = Math.floor(a / 3600), m = Math.floor((a % 3600) / 60), r = a % 60; return (s < 0 ? "-" : "+") + (h ? h + "h" : "") + (m ? m + "m" : "") + (r || (!h && !m) ? r + "s" : ""); };

  /* ---------- jeu de données déterministe ---------- */
  let seed = 443;
  const rnd = () => { seed = (seed + 0x6D2B79F5) >>> 0; let t = seed; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
  const pick = a => a[Math.floor(rnd() * a.length)];
  const W = [1, 1, 1, 1, 1, 1, 2, 4, 10, 12, 12, 10, 8, 10, 11, 10, 9, 7, 4, 3, 3, 2, 2, 1], WS = W.reduce((a, b) => a + b, 0);
  const dayT = () => { let x = rnd() * WS, h = 0; while (h < 23 && x >= W[h]) { x -= W[h]; h++; } return h * 3600 + Math.floor(rnd() * 3600); };
  const bizT = () => 7 * 3600 + 1800 + Math.floor(rnd() * 11 * 3600);

  const D = [], K = {};
  // tt = heure vraie (UTC) ; t = heure telle qu'écrite par la source (avec son fuseau ou sa dérive)
  function add(s, tt, o) { tt = Math.round(tt); const r = Object.assign({ s, tt, t: tt - FIX[s] }, o); D.push(r); if (r.k) K[r.k] = r; return r; }

  const USERS = ["alice", "bob", "carla", "dave", "erin", "frank", "gaelle", "hugo", "ines", "jean", "karim", "lea", "marc", "nina", "omar", "paul"];
  const LOG = [
    "02:12:22 web-01 connexion de alice depuis 203.0.113.66",
    "02:13:50 web-01 fichier téléversé /uploads/s.php par alice",
    "02:14:30 web-01 www-data exécute une commande (cmd=id)",
    "02:19:40 web-01 élévation de privilèges : www-data devient root",
    "02:21:15 web-01 lecture de /etc/app/backup.conf par root",
    "02:31:12 db-01 connexion SSH de svc-backup depuis 10.0.2.10",
    "02:44:10 db-01 archive créée /tmp/.cache.tgz (481 Mo)",
    "02:52:05 db-01 transfert sortant vers 198.51.100.99:443",
  ];
  const GONE = [2, 3, 4, 5];

  (function build() {
    /* --- authentification --- */
    USERS.forEach((u, i) => {
      const ip = "10.0.3." + (11 + i), home = "198.51.100." + (130 + i), n = ri(12, 24);
      for (let k = 0; k < n; k++) {
        const vpn = rnd() < 0.15, t = vpn ? ri(19 * 3600, 22 * 3600) : bizT(), svc = vpn ? "vpn" : pick(["portail", "portail", "messagerie"]), a = vpn ? home : ip;
        if (rnd() < 0.07) add("auth", t - ri(8, 40), { ip: a, user: u, resultat: "ECHEC", service: svc });
        add("auth", t, { ip: a, user: u, resultat: "OK", service: svc });
      }
    });
    const PU = ["pdubois", "pmoreau", "pleroy", "pgarcia", "pfontaine", "pbernard", "pmartin", "probert", "psimon"];
    for (let i = 0; i < 22; i++) add("auth", 9 * 3600 + 10 + Math.floor(i * 13.2), { ip: NAT, user: PU[i % 9], resultat: "ECHEC", service: "portail" });
    PU.forEach((u, i) => add("auth", 9 * 3600 + 320 + i * 40, { ip: NAT, user: u, resultat: "OK", service: "portail" }));
    for (let b = 0; b < 96; b++) for (let k = 0; k < 14; k++) add("auth", b * 900 + 120 + k * 3, { ip: SVC, user: "svc-inventaire", resultat: "ECHEC", service: "ssh" });
    const SU = ["admin", "root", "test", "backup", "guest", "bob", "carla", "dave", "erin", "frank", "gaelle", "hugo", "ines", "jean", "karim", "lea", "marc", "nina", "omar", "paul", "alice", "svc-web", "svc-backup", "deploy", "support", "compta", "rh", "stagiaire", "dev", "oracle", "postgres", "ftp", "www", "mail", "info"];
    for (let i = 0; i < 70; i++) add("auth", 4 * 3600 + i * 77 + ri(0, 20), { ip: SPR, user: SU[i % SU.length], resultat: "ECHEC", service: "portail", cat: "spr" });
    const bf = []; for (let i = 0; i < 187; i++) bf.push(2 * 3600 + 180 + Math.floor(rnd() * 510)); bf.sort((a, b) => a - b);
    bf.forEach(t => { const x = rnd(); add("auth", t, { ip: ATT, user: x < 0.8 ? "alice" : x < 0.9 ? "admin" : "bob", resultat: "ECHEC", service: "portail", cat: "bf" }); });
    add("auth", 2 * 3600 + 11 * 60 + 36, { ip: ATT, user: "alice", resultat: "OK", service: "portail", cat: "ok", k: "acces" });

    /* --- web --- */
    const QS = ["chaussures", "veste", "lampe", "cadeau", "l%27ete", "selection+cadeau", "union+europeenne", "drapeau", "script+film", "sac+a+dos", "cafe", "promo", "livre", "stylo", "or+jaune", "tee-shirt"];
    for (let i = 0; i < 1750; i++) {
      const ip = "198.51.100." + (20 + ri(0, 59)), t = dayT(), x = rnd();
      let m = "GET", p, c = 200, o = ri(2000, 60000);
      if (x < 0.13) p = "/";
      else if (x < 0.24) p = "/produits";
      else if (x < 0.38) p = "/produits?id=" + ri(1, 60);
      else if (x < 0.42) p = "/panier";
      else if (x < 0.45) p = "/contact";
      else if (x < 0.48) p = "/connexion";
      else if (x < 0.51) { m = "POST"; p = "/connexion"; c = 302; o = 300; }
      else if (x < 0.60) p = "/recherche?q=" + pick(QS);
      else if (x < 0.66) { p = "/static/css/site.css"; o = ri(8000, 9000); c = pick([200, 304]); }
      else if (x < 0.76) { p = "/static/js/description.js"; o = ri(3000, 3400); c = pick([200, 304]); }
      else if (x < 0.82) { p = "/static/js/app.js"; o = ri(20000, 21000); c = pick([200, 304]); }
      else if (x < 0.87) { p = "/static/img/logo.png"; o = ri(5000, 5200); }
      else if (x < 0.93) p = "/api/stock?id=" + ri(1, 60);
      else if (x < 0.955) p = "/produits?cat=reunion";
      else if (x < 0.985) { p = pick(["/ancien-catalogue", "/produits?id=99", "/promo-2019", "/favicon.ico"]); c = 404; o = ri(150, 400); }
      else { p = "/produits?id=" + ri(1, 60); c = 500; o = ri(300, 500); }
      add("web", t, { ip, methode: m, chemin: p, code: c, octets: o });
    }
    for (let i = 0; i < 70; i++) add("web", bizT(), { ip: "10.0.3." + ri(11, 26), methode: "GET", chemin: pick(["/backoffice/", "/backoffice/commandes", "/backoffice/clients", "/backoffice/stock"]), code: 200, octets: ri(3000, 30000) });
    const PW = ["Printemps26", "Soleil2024", "Azerty!77", "Chaton123", "Velo2025", "Lyon69!", "Cafe&Lait9", "Ocean_44", "Tulipe2026", "Marron88", "Papillon7", "Blanc2025"];
    for (let i = 0; i < 12; i++) add("web", bizT(), { ip: "10.0.3." + (11 + i), methode: "GET", chemin: `/intranet/login?user=${USERS[i]}&mdp=${PW[i]}`, code: 302, octets: 310, pw: 1 });
    for (let i = 0; i < 85; i++) add("web", 5 * 3600 + Math.floor(i * 10.5), { ip: CRAWL, methode: "GET", chemin: i < 70 ? "/ancien-catalogue/page" + (i + 1) : "/produits?id=" + (i - 69), code: i < 70 ? 404 : 200, octets: i < 70 ? 220 : 9000 });
    // balayage
    const BASES = ["admin", "login", "backup", "db", "config", "test", "old", "dev", "upload", "wp-admin", "phpmyadmin", "server-status", ".env", ".git/config", "api/v1/users", "console", "manager/html", "setup", "install", "cgi-bin/test.cgi", "debug", "phpinfo.php", "info.php", "shell.php", "logs", "dump.sql", "backup.zip", "site.tar.gz", "id_rsa", "web.config"];
    for (let i = 0; i < 150; i++) {
      const b = BASES[i % BASES.length], p = "/" + b + (i >= 30 ? pick([".bak", "~", ".old", "2", ".txt"]) : "");
      add("web", 1 * 3600 + 32 * 60 + Math.floor(i * 3.6), { ip: ATT, methode: "GET", chemin: i === 7 ? "/backoffice/" : i === 3 ? "/robots.txt" : p, code: i === 7 ? 302 : i === 3 ? 200 : b === "admin" && i < 30 ? 403 : 404, octets: ri(150, 400), cat: "scan", mal: 2 });
    }
    // injections
    const P = ["/produits?id=1%27%20OR%20%271%27=%271", "/produits?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", "/recherche?q=%3Cscript%3Ealert(1)%3C/script%3E", "/fichier?nom=../../../../etc/passwd",
      "/produits?id=1;%20DROP%20TABLE%20clients--", "/produits?id=1%20AND%20SLEEP(5)--", "/produits?id=1/**/UNION/**/SELECT/**/1,2,3--", "/recherche?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
      "/produits?id=-1%20or%201=1", "/api/stock?id=1%20union%20select%20null,version()--", "/fichier?nom=..%2F..%2F..%2Fetc%2Fshadow"];
    const PC = [500, 500, 200, 404, 500, 500, 500, 200, 500, 500, 404];
    for (let i = 0; i < 45; i++) add("web", 1 * 3600 + 44 * 60 + Math.floor(i * 18.7), { ip: ATT, methode: "GET", chemin: P[i % P.length].replace(/id=1(?!\d)/, "id=" + ri(2, 9)), code: PC[i % P.length], octets: PC[i % P.length] === 500 ? ri(400, 700) : ri(300, 1500), cat: "inj", mal: 1 });
    // après la compromission du compte alice
    add("web", 2 * 3600 + 12 * 60 + 22, { ip: ATT, methode: "GET", chemin: "/backoffice/", code: 200, octets: 4120, cat: "acc", mal: 2, k: "ancW_web" });
    add("web", 2 * 3600 + 12 * 60 + 40, { ip: ATT, methode: "GET", chemin: "/backoffice/clients", code: 200, octets: 18420, cat: "acc", mal: 2 });
    add("web", 2 * 3600 + 13 * 60 + 10, { ip: ATT, methode: "GET", chemin: "/backoffice/televerser", code: 200, octets: 2210, cat: "acc", mal: 2 });
    add("web", 2 * 3600 + 13 * 60 + 50, { ip: ATT, methode: "POST", chemin: "/backoffice/televerser", code: 200, octets: 640, cat: "acc", mal: 2, k: "webshell" });
    [["id", 14 * 60 + 30], ["whoami", 14 * 60 + 41], ["hostname", 15 * 60 + 20], ["ls+/etc/app", 17 * 60 + 5], ["cat+/etc/app/backup.conf", 21 * 60 + 20], ["id", 29 * 60 + 55]].forEach(([cmd, s]) => add("web", 2 * 3600 + s, { ip: ATT, methode: "GET", chemin: "/uploads/s.php?cmd=" + cmd, code: 200, octets: ri(40, 900), cat: "shell", mal: 1 }));

    /* --- pare-feu --- */
    for (let i = 0; i < 600; i++) add("fw", dayT(), { ip: "198.51.100." + (20 + ri(0, 59)), dst: WEB1, port: 443, action: "AUTORISE", sens: "ENTRANT", octets: ri(20000, 400000) });
    for (let i = 0; i < 40; i++) add("fw", dayT(), { ip: "192.0.2.25", dst: "10.0.2.20", port: 25, action: "AUTORISE", sens: "ENTRANT", octets: ri(5000, 900000) });
    for (let i = 0; i < 250; i++) add("fw", dayT(), { ip: "198.51.100." + ri(100, 120), dst: pick([WEB1, "10.0.2.20", "10.0.3.25"]), port: pick([23, 3389, 22, 445, 8080, 3306, 5900]), action: "REFUSE", sens: "ENTRANT", octets: 0 });
    for (let i = 0; i < 350; i++) add("fw", bizT(), { ip: "10.0.3." + ri(11, 26), dst: "198.51.100." + ri(150, 199), port: 443, action: "AUTORISE", sens: "SORTANT", octets: ri(100000, 5000000) });
    for (let i = 0; i < 40; i++) add("fw", dayT(), { ip: pick([WEB1, DB1, "10.0.3.25"]), dst: "192.0.2.10", port: 443, action: "AUTORISE", sens: "SORTANT", octets: ri(1000000, 15000000) });
    for (let i = 0; i < 60; i++) add("fw", dayT(), { ip: "10.0.2.20", dst: "192.0.2.25", port: 25, action: "AUTORISE", sens: "SORTANT", octets: ri(50000, 2000000) });
    for (let i = 0; i < 20; i++) add("fw", bizT(), { ip: "10.0.3." + ri(11, 26), dst: "192.0.2.80", port: 443, action: "AUTORISE", sens: "SORTANT", octets: ri(1000000, 20000000) });
    [10, 90, 180].forEach(s => add("fw", 3 * 3600 + s, { ip: BKP, dst: "192.0.2.50", port: 443, action: "AUTORISE", sens: "SORTANT", octets: 100000000 }));
    add("fw", 3 * 3600 + 2, { ip: BKP, dst: DB1, port: 22, action: "AUTORISE", sens: "INTERNE", octets: 14000 });
    [8 * 3600 + 32 * 60, 11 * 3600 + 10 * 60, 14 * 3600 + 20 * 60].forEach(t => add("fw", t, { ip: "10.0.3.12", dst: DB1, port: 22, action: "AUTORISE", sens: "INTERNE", octets: ri(20000, 90000) }));
    [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080].forEach((p, i) => add("fw", 1 * 3600 + 25 * 60 + i * 9, { ip: ATT, dst: WEB1, port: p, action: p === 80 || p === 443 ? "AUTORISE" : "REFUSE", sens: "ENTRANT", octets: p === 80 || p === 443 ? 600 : 0, cat: "scan", mal: 2 }));
    [[1, 31, 50], [1, 43, 50], [2, 3, 0], [2, 12, 20], [2, 14, 25], [2, 29, 50]].forEach(([h, m, s], i) => add("fw", h * 3600 + m * 60 + s, { ip: ATT, dst: WEB1, port: 443, action: "AUTORISE", sens: "ENTRANT", octets: ri(20000, 90000), cat: "acc", k: i === 3 ? "ancW_fw" : undefined }));
    for (let i = 0; i < 12; i++) add("fw", 4 * 3600 + i * 450 + ri(0, 60), { ip: SPR, dst: WEB1, port: 443, action: "AUTORISE", sens: "ENTRANT", octets: ri(1500, 3000), cat: "spr" });
    add("fw", 2 * 3600 + 31 * 60 + 10, { ip: WEB1, dst: DB1, port: 22, action: "AUTORISE", sens: "INTERNE", octets: 52000, cat: "lat", k: "ancS_fw" });
    for (let i = 0; i < 12; i++) add("fw", 2 * 3600 + 52 * 60 + 5 + i * 100 + (i ? ri(0, 20) : 0), { ip: DB1, dst: EXF, port: 443, action: "AUTORISE", sens: "SORTANT", octets: 40000000 + ri(-2000000, 2500000), cat: "exf", k: i === 0 ? "exfil" : undefined });

    /* --- hôtes --- */
    ["web-01", "db-01", "backup-01"].forEach(h => { for (let hr = 0; hr < 24; hr++) add("sys", hr * 3600 + ri(1, 59), { hote: h, user: "root", evenement: "cron", detail: "rotation des journaux (logrotate)" }); });
    [[8 * 3600 + 30 * 60, "connexion_ssh", "admin", "10.0.3.12", "accepté (clé publique)"], [8 * 3600 + 34 * 60, "sudo", "admin", "", "systemctl status postgresql"], [11 * 3600 + 10 * 60, "connexion_ssh", "admin", "10.0.3.12", "accepté (clé publique)"], [14 * 3600 + 20 * 60, "connexion_ssh", "admin", "10.0.3.12", "accepté (clé publique)"], [14 * 3600 + 26 * 60, "sudo", "admin", "", "pg_dump (sauvegarde ponctuelle)"]]
      .forEach(([t, e, u, ip, d]) => add("sys", t, { hote: "db-01", user: u, evenement: e, ip: ip || undefined, detail: d }));
    add("sys", 4 * 3600 + 20, { hote: "web-01", user: "root", evenement: "maj_paquets", detail: "12 paquets mis à jour" });
    add("sys", 16 * 3600, { hote: "web-01", user: "deploy", evenement: "deploiement", detail: "application version 2.4.1" });
    add("sys", 3 * 3600 + 2, { hote: "db-01", user: "svc-backup", evenement: "connexion_ssh", ip: BKP, detail: "accepté (clé publique)" });
    add("sys", 3 * 3600 + 40, { hote: "db-01", user: "svc-backup", evenement: "archive_cree", detail: "/var/backups/db.tgz (310 Mo)" });
    add("sys", 2 * 3600 + 19 * 60 + 40, { hote: "web-01", user: "www-data", evenement: "elevation", detail: "www-data devient root (script d'entretien mal protégé)", cat: "esc", k: "escalade" });
    add("sys", 2 * 3600 + 21 * 60 + 15, { hote: "web-01", user: "root", evenement: "lecture_fichier", detail: "/etc/app/backup.conf", cat: "esc" });
    add("sys", 2 * 3600 + 31 * 60 + 12, { hote: "db-01", user: "svc-backup", evenement: "connexion_ssh", ip: WEB1, detail: "accepté (mot de passe)", cat: "lat", k: "lateral" });
    add("sys", 2 * 3600 + 44 * 60 + 10, { hote: "db-01", user: "svc-backup", evenement: "archive_cree", detail: "/tmp/.cache.tgz (481 Mo)", cat: "prep" });
  })();

  /* ---------- horloges ---------- */
  const sh = s => ((F().shift) || {})[s] || 0;
  const eff = r => r.t + sh(r.s);
  const clkOK = () => Math.abs(sh("web") + 3600) <= TOL && Math.abs(sh("sys") - 271) <= TOL && sh("auth") === 0 && sh("fw") === 0;
  const anchorGaps = () => ({ web: eff(K.ancW_web) - eff(K.ancW_fw), sys: eff(K.lateral) - eff(K.ancS_fw) });
  const srcCount = s => D.filter(r => r.s === s).length;

  /* ---------- requêtes ---------- */
  const ALIAS = { adresse: "ip", utilisateur: "user", compte: "user", statut: "code", status: "code", etat: "code", url: "chemin", path: "chemin", uri: "chemin", taille: "octets", volume: "octets", destination: "dst", dest: "dst", machine: "hote", host: "hote", event: "evenement", temps: "heure", horodatage: "heure", time: "heure", verbe: "methode", res: "resultat" };
  const fieldOf = s => { const n = norm(s).replace(/ /g, ""); return ALIAS[n] || n; };
  const chem = r => F().masked ? r.chemin.replace(/(mdp=)[^&\s]*/gi, "$1***") : r.chemin;
  const fval = (r, k) => k === "heure" ? eff(r) : k === "source" ? SRCS[r.s] : k === "chemin" ? (r.s === "web" ? chem(r) : undefined) : r[k];
  const srcKey = t => { t = norm(t); if (/^(auth|authentification|connexions?)$/.test(t)) return "auth"; if (/^(web|http|serveur web)$/.test(t)) return "web"; if (/^(pare feu|parefeu|fw|firewall|pare feux)$/.test(t)) return "fw"; if (/^(systeme|sys|systemes|hotes|hote)$/.test(t)) return "sys"; if (/^(tout|tous|toutes|all|tout les journaux)$/.test(t)) return "tout"; return null; };
  const srcLabel = k => k === "tout" ? "tous les journaux" : SRCS[k];
  function validFields() { const x = F(); return x.src === "tout" ? [...new Set(Object.values(FIELDS).flat()), "source"] : [...FIELDS[x.src], "source"]; }

  function parseConds(raw) {
    const re = /([A-Za-zÀ-ÿ_]+)\s*(!=|>=|<=|=|~|>|<)\s*("[^"]*"|'[^']*'|[^\s]+)/g;
    const conds = []; let m;
    while ((m = re.exec(raw))) { let v = m[3]; if (/^["']/.test(v) && v.length > 1) v = v.slice(1, -1); conds.push({ f: fieldOf(m[1]), op: m[2], v, txt: m[1] + m[2] + m[3] }); }
    return { conds, left: raw.replace(re, "").trim() };
  }
  function prep(c) {
    const p = { f: c.f, op: c.op, v: c.v, lv: String(c.v).toLowerCase() };
    if (c.f === "heure") {
      const rg = /^(\d{1,2}:\d{2}(?::\d{2})?)-(\d{1,2}:\d{2}(?::\d{2})?)$/.exec(c.v);
      if (rg) { p.t0 = hm2s(rg[1]); p.t1 = hm2s(rg[2]) + (rg[2].length <= 5 ? 59 : 0); }
      else { const t = hm2s(c.v); p.t0 = t; p.t1 = t !== null && c.v.length <= 5 ? t + 59 : t; }
    } else if (NUMF.has(c.f)) {
      const m = /^(\d+(?:[.,]\d+)?)\s*(ko|mo|go|k|m|g|o)?$/i.exec(c.v);
      p.n = m ? parseFloat(m[1].replace(",", ".")) * ({ k: 1e3, ko: 1e3, m: 1e6, mo: 1e6, g: 1e9, go: 1e9 }[(m[2] || "").toLowerCase()] || 1) : NaN;
    } else if (c.v.includes("*")) p.rx = new RegExp("^" + c.v.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");
    return p;
  }
  function testCond(r, p) {
    if (p.f === "heure") {
      const t = ((eff(r) % DAY) + DAY) % DAY;
      switch (p.op) {
        case "=": return t >= p.t0 && t <= p.t1;
        case "!=": return !(t >= p.t0 && t <= p.t1);
        case ">": return t > p.t1; case ">=": return t >= p.t0; case "<": return t < p.t0; case "<=": return t <= p.t1;
        default: return false;
      }
    }
    const vals = p.f === "ip" ? [r.ip, r.dst].filter(Boolean) : [fval(r, p.f)];
    if (vals[0] === undefined) return false;
    if (NUMF.has(p.f)) {
      const v = vals[0];
      switch (p.op) { case "=": return v === p.n; case "!=": return v !== p.n; case ">": return v > p.n; case ">=": return v >= p.n; case "<": return v < p.n; case "<=": return v <= p.n; default: return false; }
    }
    const eq = v => p.rx ? p.rx.test(String(v)) : String(v).toLowerCase() === p.lv;
    if (p.op === "=") return vals.some(eq);
    if (p.op === "!=") return !vals.some(eq);
    if (p.op === "~") return vals.some(v => { const s = String(v).toLowerCase(); return s.includes(p.lv) || (p.f === "chemin" && dec(s).includes(p.lv)); });
    return false;
  }
  const sv = (r, k) => k === "heure" ? eff(r) : NUMF.has(k) ? (r[k] === undefined ? -1 : r[k]) : String(fval(r, k) === undefined ? "" : fval(r, k)).toLowerCase();
  function result() {
    const x = F(), ps = x.flt.map(prep);
    let rs = D.filter(r => (x.src === "tout" || r.s === x.src) && ps.every(p => testCond(r, p)));
    const s = x.sort || { f: "heure", d: 1 };
    return rs.map((r, i) => [r, i]).sort((a, b) => { const va = sv(a[0], s.f), vb = sv(b[0], s.f); const c = va < vb ? -1 : va > vb ? 1 : 0; return (c * s.d) || (a[1] - b[1]); }).map(p => p[0]);
  }
  function lineText(r) {
    const tm = hms(eff(r)) + (r.s === "web" && sh("web") === 0 ? "+01" : "");
    switch (r.s) {
      case "auth": return `${tm} [auth] ip=${r.ip} user=${r.user} service=${r.service} resultat=${r.resultat}`;
      case "web": return `${tm} [web] ip=${r.ip} ${r.methode} ${chem(r)} code=${r.code} octets=${r.octets}`;
      case "fw": return `${tm} [pare-feu] ${r.sens} ${r.action} ${r.ip} > ${r.dst}:${r.port} octets=${fo(r.octets)}`;
      default: return `${tm} [systeme] hote=${r.hote} user=${r.user} evenement=${r.evenement}${r.ip ? " ip=" + r.ip : ""} detail=${r.detail}`;
    }
  }
  const pipeLabel = () => { const x = F(); return [srcLabel(x.src), ...x.flt.map(c => c.txt)].join(" | "); };

  function observe(rs, groups, gfield) {
    const x = F(), n = rs.length; if (!n) return;
    x.seen = x.seen || {};
    const cnt = {}; let atk = 0; const srcs = new Set();
    for (const r of rs) { if (r.cat) cnt[r.cat] = (cnt[r.cat] || 0) + 1; if (r.pw) cnt.pw = (cnt.pw || 0) + 1; if (r.ip === ATT || r.dst === ATT) { atk++; srcs.add(r.s); } }
    const c = k => cnt[k] || 0;
    if (c("bf") >= 20 && c("bf") / n >= 0.3) x.seen.bf = 1;
    if (c("ok") >= 1 && n <= 300) x.seen.ok = 1;
    if (c("spr") >= 20 && c("spr") / n >= 0.3) x.seen.spr = 1;
    if (c("scan") >= 20 && c("scan") / n >= 0.3) x.seen.scan = 1;
    if (c("inj") >= 5 && (c("inj") / n >= 0.3 || n <= 150)) x.seen.inj = 1;
    if (c("exf") >= 3 && n <= 150) x.seen.exf = 1;
    if (c("pw") >= 1 && n <= 60) x.seen.pw = 1;
    if (groups && gfield === "dst" && groups.slice(0, 5).some(g => g[0] === EXF)) x.seen.exf = 1;
    if (srcs.size >= 2 && atk / n >= 0.5 && !x.corr) {
      x.corr = true;
      out("Une même adresse (" + ATT + ") apparaît maintenant dans plusieurs journaux à la fois : authentification, web, pare-feu. C'est cela, **corréler** : chaque journal est un témoin partiel, le recoupement raconte l'histoire.", "ok");
      note("corr");
    }
  }

  /* ---------- notes ---------- */
  const notes = {
    sources: ["Les sources de journaux", "Chaque système écrit un journal : l'authentification (qui se connecte, avec quel résultat), le serveur web (chaque requête : adresse, chemin, code de retour, volume), le pare-feu (chaque connexion autorisée ou refusée, avec son volume) et les hôtes (commandes sensibles, élévations de privilèges, services). Pris séparément, ils racontent peu. Un collecteur central les rassemble, un SIEM les indexe, les corrèle et déclenche des alertes."],
    corr: ["La corrélation", "Une même adresse, un même compte ou un même hôte apparaît dans plusieurs journaux. C'est en recoupant les sources que l'on reconstitue une histoire : des échecs d'authentification, puis un succès, puis des requêtes web depuis la même adresse, puis des connexions internes. Chaque journal n'est qu'un témoin partiel."],
    force: ["La force brute", "Beaucoup d'échecs d'authentification depuis une même adresse en peu de temps, suivis d'un succès : l'attaquant a trouvé le mot de passe. Variante lente (« password spraying ») : un ou deux essais par compte, sur de nombreux comptes, étalés dans le temps pour passer sous les seuils courts. Un gros total n'est pas forcément un danger : une tâche automatique au mot de passe périmé échoue sans cesse. Parades : mots de passe longs et uniques, authentification multifacteur, limitation ou verrouillage temporaire, alerte sur « échecs puis succès »."],
    inject: ["Balayage et injection dans les journaux web", "Un balayage cherche des pages cachées (/admin, /.env, /phpmyadmin…) : rafale de codes 404 depuis une même adresse. Une injection glisse du code dans un paramètre : on voit dans le chemin des fragments SQL (UNION SELECT, ' OR 1=1, --), de script (<script>) ou de traversée de répertoires (../../etc/passwd), souvent encodés (%27, %3C). Un code 500 en réponse signale une entrée mal traitée, donc une application fragile. Les mots-clés seuls déclenchent aussi sur du trafic légitime (« selection », « union européenne »)."],
    exfil: ["L'exfiltration", "Voler des données, c'est les faire sortir : l'indice est un volume sortant anormal vers une destination inconnue, souvent hors des heures de bureau. Il faut une référence (destinations habituelles, volumes habituels par heure) pour distinguer la sauvegarde nocturne légitime d'un vol. On regarde le volume par destination, pas seulement le nombre de connexions. Filtrer les sorties (egress), segmenter le réseau et surveiller les volumes réduisent le risque."],
    chrono: ["La chronologie et l'horodatage", "Reconstituer l'enchaînement exige des horloges cohérentes : tout en UTC, synchronisé par NTP. Un serveur qui écrit en heure locale (+01:00) ou dont l'horloge dérive fausse l'ordre apparent : on voit un effet avant sa cause. On aligne les sources grâce à des événements « balises » vus par deux journaux. Enchaînement type d'une intrusion : accès initial, exécution, escalade de privilèges, mouvement latéral, exfiltration."],
    regles: ["Règles de détection, faux positifs et faux négatifs", "Une règle de seuil (« N échecs en M minutes ») ou de motif (mots-clés) se teste sur des données réelles. Trop sensible : faux positifs, les analystes sont noyés et finissent par ignorer les alertes. Trop sourde : faux négatifs, l'attaque passe. On mesure la précision (part des alertes justifiées) et le rappel (part des attaques détectées). On règle fenêtre et seuil ; exclure une source bénigne connue aide mais crée un angle mort ; un attaquant peut contourner un motif (encodage, commentaires SQL)."],
    integrite: ["L'intégrité des journaux", "Un attaquant qui obtient les droits d'administrateur efface ses traces. Parades : envoyer les journaux en continu vers un collecteur hors de sa portée (écriture seule), et chaîner les lignes : l'empreinte SHA-256 de chaque ligne inclut celle de la précédente, donc retirer ou modifier une ligne casse la chaîne. Mais l'algorithme est public : on peut recalculer toute la chaîne. Il faut une ancre extérieure (la tête de chaîne conservée ailleurs, ou signée) pour démasquer aussi une chaîne refaite ou une fin tronquée."],
    conserv: ["Conservation et vie privée", "Durée : assez longue pour enquêter (les intrusions se découvrent souvent après des semaines : prévoir plusieurs mois), assez courte pour respecter la minimisation des données (adresses IP et identifiants sont des données personnelles : en pratique de quelques mois à un an, selon la loi applicable). Ne jamais journaliser mots de passe, jetons ou numéros de carte : on les masque à la source, sinon le journal devient une cible. Un secret déjà écrit dans un journal doit être considéré comme exposé et changé."],
  };

  /* ---------- entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle tient dans la main le ticket de l'alerte du matin." },
    alice: { npc: true, names: ["alice"], label: "Alice", desc: () => "Alice, comptable de la cité, un café à la main. Elle se connecte chaque jour depuis son poste, vers neuf heures." },
    bob: { npc: true, names: ["bob"], label: "Bob", desc: () => "Bob, analyste de garde. Les yeux cernés : une pile d'alertes automatiques s'est accumulée devant lui." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, qui écoute tout ce qui se dit dans la cité, et le range. Ici, c'est un métier : elle est le collecteur central." },
    console: { names: ["console", "terminal", "requete", "requetes"], label: "la console de requêtes", vis: () => S.room === "salle",
      desc: () => "La console des journaux. Quatre journaux : `ouvrir auth`, `ouvrir web`, `ouvrir pare-feu`, `ouvrir systeme` (ou `ouvrir tout`).\nPuis enchaîne :\n  `filtrer ‹champ›=‹valeur›` (opérateurs = != ~ > < >= <= ; `chemin~select`, `octets>10Mo`, `heure=02:00-03:00`, `ip=10.0.3.*`)\n  `compter par ‹champ›` (ajoute `volume` pour trier par octets) · `trier ‹champ›` · `chronologie` · `afficher ‹n› lignes`\nChamps : auth = heure ip user resultat service ; web = heure ip methode chemin code octets ; pare-feu = heure ip dst port action sens octets ; systeme = heure hote user evenement ip detail. `ip` couvre toute adresse de la ligne (source ou destination)." },
    registre: { names: ["registre", "destinations", "actifs", "inventaire des actifs"], label: "le registre des destinations connues", vis: () => S.room === "salle",
      desc: () => "Le registre des destinations externes légitimes de la cité :\n" + KNOWN.map(([ip, n]) => `  ${ip} : ${n}`).join("\n") + "\nHôtes internes : web-01 (10.0.2.10, DMZ), courrier (10.0.2.20), db-01 (10.0.3.30), backup-01 (10.0.3.40), postes (10.0.3.11 à 10.0.3.26).\nTout ce qui n'y figure pas n'est pas forcément malveillant, mais mérite une question." },
    cadran: { names: ["cadran", "horloges", "tableau", "table des horloges"], label: "le cadran des sources de temps", vis: () => S.room === "horloges", desc: () => clockText() },
    journal: { names: ["journal", "journal local", "copie locale", "fichier"], label: "le journal d'audit local de web-01", vis: () => S.room === "archives",
      desc: () => { F().sawLocal = true; return "La copie locale du journal d'audit, telle qu'elle est sur le disque de web-01 :\n" + LOG.filter((t, i) => !GONE.includes(i + 1)).map((t, i) => `  ${i + 1}. ${t}`).join("\n") + "\n\nIl y a un grand silence entre la première et la deuxième ligne. `comparer collecteur` pour confronter cette copie à celle d'Ève."; } },
  };
  function clockText() {
    const x = F();
    return "Table des sources de temps, d'après les administrateurs :\n  auth      : UTC, synchronisé par NTP\n  web       : heure locale de la cité (UTC+01:00), horodatage affiché avec le suffixe +01\n  pare-feu  : UTC, synchronisé par NTP\n  systeme   : UTC, mais NTP désactivé depuis 41 jours : l'horloge a dérivé, de combien ? personne ne l'a mesuré.\nCorrections appliquées : " + ["auth", "web", "fw", "sys"].map(k => `${SRCS[k]} ${durTxt(sh(k))}`).join(" · ") + "\n`decaler ‹source› ‹±durée›` (ex. `decaler web -2h`, `decaler systeme +1m30s`). Une correction se calcule avec une ancre : un même événement vu par deux journaux.";
  }

  const rooms = {
    hall: { name: "Le hall des alertes", short: "Hall", alias: ["hall", "alertes"], ents: ["ada", "alice"], exits: { nord: "salle", ouest: "horloges", est: "siem", sud: "archives" },
      desc: () => "Un écran géant affiche une seule ligne rouge, sans adresse ni heure : « comportement inhabituel ». Au nord, la salle des journaux. À l'ouest, la salle des horloges. À l'est, le centre de détection. Au sud, les archives." },
    salle: { name: "La salle des journaux", short: "Journaux", alias: ["salle", "journaux", "salle journaux"], ents: ["console", "registre"], exits: { sud: "hall" },
      desc: () => `Des étagères de rouleaux lumineux : quatre journaux de la journée, auth (${nf(srcCount("auth"))} lignes), web (${nf(srcCount("web"))}), pare-feu (${nf(srcCount("fw"))}) et systeme (${nf(srcCount("sys"))}). Au centre, la console de requêtes ; au mur, le registre des destinations connues.` },
    horloges: { name: "La salle des horloges", short: "Horloges", alias: ["horloges", "salle horloges", "horloge"], ents: ["cadran"], exits: { est: "hall" },
      desc: () => "Des dizaines d'horloges, toutes un peu en désaccord. Le cadran central indique quelle source de temps dit quoi." },
    siem: { name: "Le centre de détection", short: "Détection", alias: ["siem", "detection", "centre", "centre detection"], ents: ["bob"], exits: { ouest: "hall" },
      desc: () => "Un mur d'écrans où défilent des alertes. Bob y trie les alertes à la main. Ici on écrit les règles : `regle seuil ‹N› echecs en ‹M› min [sauf ‹ip›]` (ou `404` à la place de `echecs`) et `regle motif ‹mot› | ‹mot›…`. Chaque règle est évaluée sur les vraies données de la journée." },
    archives: { name: "Les archives", short: "Archives", alias: ["archives", "archive"], ents: ["eve", "journal"], exits: { nord: "hall" },
      desc: () => "Une voûte fraîche, des coffres sans serrure d'ouverture (on y dépose, on n'en retire rien). Ève y range une copie de chaque ligne écrite dans la cité. Ici on règle aussi la conservation (`conserver`) et le masquage (`masquer`)." },
  };

  /* ---------- progression ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.opened) return "open";
    if (!x.bf) return "bf";
    if (!x.scan) return "scan";
    if (!x.inj) return "inj";
    if (!x.exf) return "exf";
    if (!x.clk) return "clock";
    if (!x.order) return "order";
    if (!x.rs) return "rseuil";
    if (!x.rm) return "rmotif";
    if (!x.cmp) return "cmp";
    if (!x.chainBreak) { if (!x.ch) return "chain1"; if (!x.ch.anchor && !x.ch.deleted.length) return "chain2"; if (!x.ch.deleted.length) return "chain3"; return "chain4"; }
    if (!x.anchorHit) return "anchor";
    if (!x.retOK) return "ret";
    if (!x.masked) return "priv";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada attend dans le hall.", "`parler ada`"],
    open: () => ["La console de requêtes est dans la salle des journaux, au nord du hall.", "`aller nord`, puis `ouvrir auth`."],
    bf: () => ["Quelques échecs de connexion sont normaux. Cherche des adresses qui en cumulent beaucoup, puis regarde leur forme dans le temps : le plus gros total n'est pas forcément l'attaque. Cherche enfin si un succès a suivi.", "`ouvrir auth`, `filtrer resultat=ECHEC`, `compter par ip`, `filtrer ip=203.0.113.66`, `chronologie`. Puis `ouvrir auth`, `filtrer ip=203.0.113.66 resultat=OK`, `afficher 3 lignes`. Conclus : `signaler 203.0.113.66 force brute`."],
    scan: () => ["Passe aux journaux web. Un balayage cherche des pages cachées : beaucoup de « page introuvable » (404) d'affilée depuis la même adresse.", "`ouvrir web`, `filtrer code=404`, `compter par ip`, `filtrer ip=203.0.113.66`, `chronologie`, puis `signaler 203.0.113.66 balayage`."],
    inj: () => ["Cherche, dans les chemins demandés, des fragments de SQL, de script ou de traversée de répertoires (select, union, <script, ../).", "`ouvrir web`, `filtrer ip=203.0.113.66 chemin~select`, `afficher 8 lignes` (essaie aussi `chemin~script`, `chemin~../`), puis `signaler 203.0.113.66 injection`."],
    exf: () => ["Regarde ce qui sort du réseau : le volume par destination (pas seulement le nombre de connexions), puis compare avec le registre des destinations connues, dans la salle des journaux.", "`ouvrir pare-feu`, `filtrer sens=SORTANT`, `compter par dst volume`, `examiner registre`, `filtrer dst=198.51.100.99`, `chronologie`, puis `signaler 198.51.100.99 exfiltration`."],
    clock: () => ["Les sources ne s'accordent pas sur l'heure : une même activité apparaît à des heures incompatibles. Trouve des ancres (même événement dans deux journaux), calcule les écarts, et corrige à la salle des horloges (ouest du hall).", "Ancre web : `ouvrir tout`, `filtrer ip=203.0.113.66 heure=02:12-02:13` (pare-feu), puis `ouvrir tout`, `filtrer ip=203.0.113.66 heure=03:12-03:13` (web, une heure plus tard). Ancre systeme : `ouvrir tout`, `filtrer ip=10.0.2.10 heure=02:20-02:40` (le SSH est accepté avant d'être autorisé). Puis, salle des horloges : `decaler web -1h` et `decaler systeme +4m29s`."],
    order: () => ["Maintenant que les horloges concordent, remets les cinq étapes de l'attaque dans l'ordre.", "`ordonner acces webshell escalade lateral exfiltration`"],
    rseuil: () => ["Va au centre de détection (est du hall). Écris une règle de seuil sur les échecs d'authentification : trop sensible, Bob est noyé ; trop sourde, tu rates l'attaque lente. Lis les « exemples » que l'évaluation te donne.", "Essaie `regle seuil 3 echecs en 5 min`, puis `regle seuil 30 echecs en 5 min`, puis `regle seuil 30 echecs en 60 min sauf 10.0.3.55`."],
    rmotif: () => ["Écris maintenant une règle de motif sur les chemins web. Un mot trop courant (select, union, script, or) déclenche sur du trafic légitime. Lis les exemples de faux positifs et d'attaques manquées.", "`regle motif union select | <script | ../ | ' or | drop table | sleep( | or 1=1 | cmd=` (ajoute ce qui manque d'après les exemples)."],
    cmp: () => ["Va aux archives (sud du hall) : la copie locale du journal de web-01 a des trous. Compare-la avec celle d'Ève.", "`aller sud`, `examiner journal`, `comparer collecteur`."],
    chain1: () => ["Un journal chaîné rend la suppression détectable. Fais construire la chaîne à partir de la copie complète d'Ève.", "`chainer journal`"],
    chain2: () => ["Dépose la tête de la chaîne chez Ève, hors de portée de Mallory.", "`envoyer collecteur`"],
    chain3: () => ["Autorisée par la Guilde, Mallory rejoue son geste : effacer une ligne au milieu du journal.", "`effacer ligne 4`"],
    chain4: () => ["Contrôle maintenant la chaîne.", "`controler chaine`"],
    anchor: () => ["Mallory peut recalculer toutes les empreintes après son effacement : la chaîne paraîtra intacte. Qui peut la démasquer ?", "`chainer journal`, `envoyer collecteur`, `effacer ligne 4`, `recalculer chaine`, `controler chaine`."],
    ret: () => ["Règle la durée de conservation de chaque source : assez longue pour enquêter, assez courte pour respecter la vie privée.", "`conserver tout 180` (ou source par source : `conserver auth 180`)."],
    priv: () => ["Certaines lignes web contiennent des mots de passe. Retrouve-les dans la salle des journaux, puis fais-les masquer aux archives.", "`ouvrir web`, `filtrer chemin~mdp`, `afficher 5 lignes` ; puis aux archives : `masquer mdp`."],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Ce matin, le SIEM a craché une alerte : « comportement inhabituel ». Pas d'adresse, pas d'heure, pas de compte. Cette nuit, la cité a écrit des milliers de lignes de journaux. Quelque part dedans, il y a Mallory : il faut la retrouver, comprendre ce qu'elle a fait, puis écrire des règles pour qu'elle ne passe plus inaperçue.");
          say("Maître Ada", "L'audit est autorisé et tout est simulé sur des données fictives. Les journaux sont au nord. Interroge-les avec la console : filtrer, compter, trier, chronologie. Chaque conclusion se déclare ensuite avec `signaler ‹adresse› ‹type›`.");
          out("`aller nord`, puis `ouvrir auth`.", "sys");
        } else if (x.end) say("Maître Ada", "Les nouvelles règles tournent, les journaux sont chaînés, ancrés et masqués. Merci !");
        else if (objective() === "end") ending();
        else {
          const k = objective();
          const m = { bf: "Commence par l'authentification : cherche un pic d'échecs, puis un succès.", scan: "Passe aux journaux web : y a-t-il un balayage ?", inj: "Dans les journaux web aussi : des tentatives d'injection ?", exf: "Que fait le pare-feu côté sortant ? Cherche un gros volume vers une destination inconnue.", clock: "Les heures ne concordent pas entre les sources. Salle des horloges, à l'ouest.", order: "Remets les étapes de l'attaque dans l'ordre : `ordonner …`.", rseuil: "Il faut des règles que Bob puisse supporter : centre de détection, à l'est.", rmotif: "Il manque une règle de motif sur les chemins web.", cmp: "Mallory a effacé des lignes : aux archives, vois ce que sait Ève.", chain1: "Aux archives : construis une chaîne d'empreintes.", chain2: "Dépose la tête de la chaîne chez Ève.", chain3: "Rejoue le geste de Mallory pour voir si la chaîne la trahit.", chain4: "Contrôle la chaîne.", anchor: "Et si Mallory recalcule toute la chaîne ?", ret: "Les durées de conservation sont à régler, aux archives.", priv: "Des mots de passe traînent dans les journaux web : masque-les." };
          say("Maître Ada", (m[k] || "L'analyse n'est pas finie.") + " `indice` si tu bloques.");
        }
        break;
      case "alice":
        if (!x.bf) say("Alice", "Une alerte ? Je n'ai rien fait d'inhabituel. Je me connecte depuis mon poste (10.0.3.11), vers neuf heures, pas à deux heures du matin.");
        else say("Alice", "À deux heures du matin ? Je dormais ! Mon mot de passe suit toujours le même schéma : une saison et une année. Ce n'est pas très malin, je sais. Et je n'ai aucune authentification supplémentaire.");
        break;
      case "bob": {
        const n = evalSeuil(3, 5, "echecs", []).alerts.length;
        say("Bob", `Cette nuit, la règle par défaut (3 échecs en 5 minutes) a levé ${nf(n)} alertes. Je les ai toutes fermées sans les lire. Si tu veux que je lise la prochaine, qu'elle sonne pour de bon.`);
        out("`regle seuil ‹N› echecs en ‹M› min [sauf ‹ip›]` · `regle motif ‹mot› | ‹mot›`", "sys");
        break;
      }
      case "eve":
        if (!x.cmp) say("Ève", "J'écoute tout ce que la cité écrit, dès que c'est écrit, et je le range dans un coffre où personne d'ici n'a le droit de supprimer. Si quelqu'un efface quelque chose ailleurs, je l'ai encore. Compare : `comparer collecteur`.");
        else say("Ève", "Le journal local de web-01 a perdu quatre lignes. Heureusement, je les avais. Mais un collecteur n'est pas tout : il faut aussi qu'on puisse prouver qu'un journal est complet. Les chaînes d'empreintes font cela. Et dis-moi, tu as pensé à la durée de conservation, et aux mots de passe dans les journaux ?");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes de requête ---------- */
  function needConsole() {
    const x = F();
    if (S.room !== "salle") { out("La console de requêtes est dans la salle des journaux (nord du hall).", "sys"); return true; }
    if (!x.src) { out("Ouvre d'abord un journal : `ouvrir auth`, `ouvrir web`, `ouvrir pare-feu`, `ouvrir systeme` ou `ouvrir tout`.", "err"); return true; }
    return false;
  }
  function cmdOpen(c) {
    const x = F();
    if (S.room !== "salle") { out("Les journaux s'ouvrent à la console, dans la salle des journaux (nord du hall).", "sys"); return; }
    const k = srcKey(c.rawArg);
    if (!k) { out("Quel journal ? `ouvrir auth`, `ouvrir web`, `ouvrir pare-feu`, `ouvrir systeme` ou `ouvrir tout`.", "err"); return; }
    x.src = k; x.flt = []; x.sort = { f: "heure", d: 1 };
    const n = result().length;
    out(`Journal « ${srcLabel(k)} » ouvert : ${nf(n)} lignes. Champs : ${validFields().join(", ")}.`, "ok");
    if (!x.opened) {
      x.opened = true;
      out("Chaque ligne est un événement : une heure, des champs (qui, quoi, d'où). Ces journaux sont envoyés par chaque système vers un collecteur, puis lus par un SIEM.", "sys");
      note("sources"); fig("pipeline");
    }
  }
  function cmdFilter(c) {
    const x = F(); if (needConsole()) return;
    const raw = c.rawArg;
    if (!raw) { out("Filtrer quoi ? `filtrer ‹champ›=‹valeur›` (ex. `filtrer resultat=ECHEC`, `filtrer chemin~select`, `filtrer heure=02:00-03:00`).", "err"); return; }
    const { conds, left } = parseConds(raw);
    if (!conds.length) { out("Je ne trouve pas de condition. Forme attendue : `filtrer ‹champ›=‹valeur›`. Opérateurs : = (égal) != (différent) ~ (contient) > < >= <= (nombres, heures). Exemple : `filtrer code=404`.", "err"); return; }
    if (left) { out(`Je ne comprends pas « ${left} ». Plusieurs conditions se séparent par des espaces, une valeur avec espaces se met entre guillemets : \`filtrer chemin~"union select"\`.`, "err"); return; }
    const ok = validFields();
    for (const cd of conds) {
      if (!ok.includes(cd.f)) { out(`Le champ « ${cd.f} » n'existe pas dans « ${srcLabel(x.src)} ». Champs disponibles : ${ok.join(", ")}.`, "err"); return; }
      const p = prep(cd);
      if (cd.f === "heure" && p.t0 === null) { out("Heure attendue au format HH:MM, HH:MM:SS ou une plage `heure=02:00-03:00`.", "err"); return; }
      if (NUMF.has(cd.f) && Number.isNaN(p.n)) { out(`« ${cd.f} » est un nombre (octets accepte aussi Ko, Mo, Go : \`octets>10Mo\`).`, "err"); return; }
      if (!NUMF.has(cd.f) && cd.f !== "heure" && [">", "<", ">=", "<="].includes(cd.op)) { out(`Les comparaisons > et < ne servent que pour les nombres et les heures (code, port, octets, heure). Pour « ${cd.f} », utilise = != ou ~.`, "err"); return; }
      if (cd.f === "heure" && cd.op === "~") { out("Pour l'heure, utilise = (une minute ou une plage), > ou <.", "err"); return; }
      if (NUMF.has(cd.f) && cd.op === "~") { out(`« ${cd.f} » est numérique : utilise = != > < >= <=.`, "err"); return; }
    }
    const before = result().length;
    x.flt = x.flt.concat(conds.map(({ f: ff, op, v, txt }) => ({ f: ff, op, v, txt })));
    const rs = result();
    out(`→ ${nf(rs.length)} lignes sur ${nf(before)} (${before ? pct(rs.length / before) : "0 %"}).  Requête : ${pipeLabel()}`, rs.length ? "ok" : "err");
    if (!rs.length) out("Aucune ligne : filtre trop strict, champ mal orthographié, ou rien à voir ici (c'est aussi une réponse). `ouvrir ‹journal›` repart de zéro.", "sys");
    else if (rs.length === before) out("Ce filtre ne retire rien : il ne t'apprend rien.", "sys");
    observe(rs);
  }
  function cmdSort(c) {
    const x = F(); if (needConsole()) return;
    const t = norm(c.rawArg).split(" ").filter(Boolean);
    if (!t.length) { out("Trier par quoi ? `trier heure`, `trier octets desc`.", "err"); return; }
    const k = fieldOf(t[0]);
    if (!validFields().includes(k)) { out(`Le champ « ${t[0]} » n'existe pas ici. Champs : ${validFields().join(", ")}.`, "err"); return; }
    const desc = t.slice(1).some(w => /^(desc|decroissant|decr|inverse)/.test(w)) || (k === "octets" && !t.slice(1).some(w => /^(asc|croissant)/.test(w)));
    x.sort = { f: k, d: desc ? -1 : 1 };
    out(`Tri par ${k}, ${desc ? "décroissant" : "croissant"}. \`afficher ‹n› lignes\` pour voir le résultat.`, "ok");
  }
  function cmdShow(c) {
    const x = F(); if (needConsole()) return;
    const m = /\d+/.exec(c.rawArg), n = Math.min(40, m ? +m[0] : 10);
    const rs = result();
    if (!rs.length) { out("Aucune ligne à afficher : la requête ne retient rien. `ouvrir ‹journal›` pour repartir.", "err"); return; }
    out(`${Math.min(n, rs.length)} lignes sur ${nf(rs.length)} (tri : ${(x.sort || { f: "heure" }).f}). Requête : ${pipeLabel()}`, "sys");
    code(rs.slice(0, n).map(lineText).join("\n"));
    const shown = rs.slice(0, n), cats = new Set(shown.map(r => r.cat));
    if (rs.length > n) out(`(${nf(rs.length - n)} lignes de plus : \`afficher 40 lignes\`, ou resserre avec \`filtrer\`.)`, "sys");
    if (cats.has("ok")) out("Lecture : un succès (resultat=OK) arrive juste après des centaines d'échecs depuis la même adresse, hors des heures de bureau, pour un compte qui se connecte d'habitude depuis un poste interne. Soit la personne a fini par se souvenir de son mot de passe, soit l'attaquant l'a deviné. Le contexte (heure, adresse jamais vue, rafale juste avant) tranche.", "sys");
    if (cats.has("inj")) out("Lecture : les chemins contiennent du code d'attaque (SQL, script, traversée). Les 500 en réponse montrent que l'application a mal digéré l'entrée : elle n'a pas ouvert l'accès cette fois, mais elle est fragile. Remarque l'encodage (%27, %20, %3C) : les règles doivent le décoder.", "sys");
    if (cats.has("scan") && shown.some(r => r.s === "web")) out("Lecture : des chemins banals pour un attaquant (admin, .env, backup, phpmyadmin…), quasiment tous en 404. Un visiteur normal ne demande pas trente fichiers de configuration en dix minutes.", "sys");
    if (cats.has("exf")) out("Lecture : des transferts de ~40 Mo chacun, à intervalles réguliers, de la base de données vers une adresse hors du registre, en pleine nuit. Une base de données n'a aucune raison de parler à Internet.", "sys");
    if (shown.some(r => r.pw)) out("Lecture : des mots de passe en clair dans l'adresse de la requête ! Ils sont lisibles par quiconque lit le journal, la sauvegarde ou le SIEM.", "sys");
    observe(rs);
  }
  function groupKey(r, k) {
    if (k === "heure") return hms(Math.floor(eff(r) / 3600) * 3600).slice(0, 2) + "h";
    if (k === "chemin") return r.s === "web" ? chem(r).split("?")[0] : undefined;
    const v = fval(r, k); return v === undefined ? undefined : String(v);
  }
  function cmdCount(c) {
    const x = F(); if (needConsole()) return;
    const t = norm(c.rawArg).split(" ").filter(Boolean);
    if (t[0] === "par") t.shift();
    if (!t.length) { out("Compter par quoi ? `compter par ip`, `compter par code`…", "err"); return; }
    const k = fieldOf(t[0]);
    if (!validFields().includes(k)) { out(`Le champ « ${t[0]} » n'existe pas ici. Champs : ${validFields().join(", ")}.`, "err"); return; }
    const byVol = t.slice(1).some(w => /^(volume|octets|taille)/.test(w));
    const rs = result();
    if (!rs.length) { out("Aucune ligne à compter.", "err"); return; }
    const g = new Map(); let hasO = false;
    for (const r of rs) { const key = groupKey(r, k); if (key === undefined) continue; const e = g.get(key) || [key, 0, 0]; e[1]++; if (r.octets !== undefined) { e[2] += r.octets; hasO = true; } g.set(key, e); }
    const arr = [...g.values()].sort((a, b) => byVol && hasO ? b[2] - a[2] || b[1] - a[1] : b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
    if (!arr.length) { out(`Aucune ligne n'a de champ « ${k} ».`, "err"); return; }
    const top = arr.slice(0, 12), mx = Math.max(...top.map(a => byVol && hasO ? a[2] : a[1]), 1);
    const total = rs.length, w = Math.max(...top.map(a => a[0].length));
    out(`Comptage par ${k} sur ${nf(total)} lignes (${arr.length} valeurs distinctes), trié par ${byVol && hasO ? "volume" : "nombre"}. Requête : ${pipeLabel()}`, "sys");
    code(top.map(a => `${a[0].padEnd(w)}  ${String(a[1]).padStart(5)}  ${hasO ? fo(a[2]).padStart(10) + "  " : ""}${"█".repeat(Math.max(1, Math.round(((byVol && hasO ? a[2] : a[1]) / mx) * 24)))}`).join("\n") + (arr.length > 12 ? `\n… et ${arr.length - 12} autres valeurs` : ""));
    explainCount(k, arr, total, byVol);
    observe(rs, arr, k);
  }
  function explainCount(k, arr, total, byVol) {
    const x = F(), top = arr[0], share = Math.round(100 * top[1] / total);
    const hasFail = x.flt.some(c => c.f === "resultat" && /echec/i.test(c.v));
    if (k === "ip" && x.src === "auth" && hasFail) {
      out(`Lecture : quelques échecs par adresse sont normaux (fautes de frappe : 1 à 3). Ici ${arr.filter(a => a[1] >= 20).length} adresses en cumulent plus de 20. Attention : le total ne dit pas tout. Une machine qui échoue toute la journée à intervalles réguliers (tâche automatique au mot de passe périmé) n'est pas une attaque, et une attaque brève peut cumuler moins. Regarde la forme dans le temps : \`filtrer ip=‹adresse›\` puis \`chronologie\`.`, "sys");
    } else if (k === "user" && hasFail) {
      out(share >= 40 ? `Lecture : un seul compte concentre ${share} % des échecs : une attaque ciblée sur ce compte.` : "Lecture : les échecs sont répartis sur de nombreux comptes : typique d'une pulvérisation de mots de passe (un même mot de passe essayé sur beaucoup de comptes) ou d'une panne générale.", "sys");
    } else if (k === "code" && x.src === "web") {
      out("Lecture : 200 = succès, 3xx = redirection, 403 = interdit, 404 = introuvable, 500 = erreur du serveur. Une proportion anormale de 404 depuis une même adresse trahit un balayage ; des 500 en rafale trahissent souvent des entrées malformées (injection). Compte par `ip` pour savoir qui.", "sys");
    } else if (k === "ip" && x.src === "web") {
      out(`Lecture : un visiteur normal fait quelques dizaines de requêtes dans la journée. L'adresse en tête (${top[0]}, ${top[1]} lignes) mérite un coup d'œil : robot d'indexation, ou balayeur ? La chronologie et les chemins demandés le diront.`, "sys");
    } else if (k === "dst") {
      out(byVol ? "Lecture : volume total envoyé vers chaque destination. Une exfiltration se voit au volume vers une destination rare, pas au nombre de connexions (il y en a peu). Compare avec `examiner registre` : une destination connue et attendue (sauvegarde nocturne) n'est pas un vol ; une destination inconnue qui reçoit des centaines de Mo, si." : "Lecture : nombre de connexions par destination. Mais le nombre ne mesure pas le vol : quelques gros transferts passent sous le radar. Ajoute `volume` pour trier par octets : `compter par dst volume`.", "sys");
    } else if (k === "heure") {
      out("Lecture : répartition par heure (UTC). L'activité humaine suit les heures de bureau ; ce qui sort de cette courbe, surtout la nuit, mérite attention.", "sys");
    } else {
      out(`Lecture : ${arr.length} valeurs distinctes ; la plus fréquente (${top[0]}) pèse ${share} % des lignes${share >= 50 ? " : une valeur domine, c'est un signal" : ""}.`, "sys");
    }
  }
  function cmdTimeline(c) {
    const x = F(); if (needConsole()) return;
    const rs = result();
    if (!rs.length) { out("Aucune ligne : pas de chronologie.", "err"); return; }
    const ts = rs.map(r => eff(r)), t0 = Math.min(...ts), t1 = Math.max(...ts);
    let size = null; const m = /(\d+)\s*(h|min|m)?/i.exec(c.rawArg);
    if (m) size = (+m[1]) * (/^h/i.test(m[2] || "") ? 3600 : 60);
    const SZ = [60, 300, 600, 1800, 3600];
    const cap = s => Math.floor(t1 / s) - Math.floor(t0 / s) + 1;
    if (!size || size < 60 || cap(size) > 72) size = SZ.find(s => cap(s) <= 48) || 3600;
    const b0 = Math.floor(t0 / size), n = cap(size), cnt = new Array(n).fill(0);
    ts.forEach(t => cnt[Math.floor(t / size) - b0]++);
    const mx = Math.max(...cnt);
    out(`Chronologie (tranches de ${size >= 3600 ? size / 3600 + " h" : size / 60 + " min"}, heures affichées) sur ${nf(rs.length)} lignes. Requête : ${pipeLabel()}`, "sys");
    code(cnt.map((v, i) => `${hms((b0 + i) * size).slice(0, 5)} ${String(v).padStart(5)} ${v ? "█".repeat(Math.max(1, Math.round(v / mx * 32))) : "·"}`).join("\n"));
    const nz = cnt.filter(v => v > 0).sort((a, b) => a - b), med = nz[Math.floor(nz.length / 2)] || 1, pk = cnt.indexOf(mx);
    if (n >= 4 && mx >= 15 && mx >= 4 * med) out(`Lecture : un pic net, ${mx} lignes vers ${hms((b0 + pk) * size).slice(0, 5)}, soit ${Math.round(mx / med)} fois la tranche médiane. Un pic bref et intense trahit un acteur unique qui s'active (outil automatique) : c'est la signature d'une attaque, pas d'un usage humain.`, "sys");
    else if (t1 - t0 >= 6 * 3600 && n >= 8 && nz.length >= 0.8 * n && mx <= 2 * med + 1) out("Lecture : activité régulière sur toute la période, jour et nuit : c'est la signature d'une machine (tâche planifiée, supervision), pas d'une attaque ponctuelle. Reste à savoir si cette tâche est légitime et si elle échoue pour une bonne raison.", "sys");
    else if (t1 - t0 <= 3600 && rs.length >= 30) out(`Lecture : ${nf(rs.length)} lignes tiennent en ${Math.max(1, Math.round((t1 - t0) / 60))} minutes, à un rythme constant : une rafale. Un humain n'enchaîne pas ce nombre d'essais à cette cadence, un outil automatique si. Regarde ce qui se passe juste avant et juste après.`, "sys");
    else if (n >= 4) out(`Lecture : l'activité se concentre entre ${hms(t0).slice(0, 5)} et ${hms(t1).slice(0, 5)}. Compare avec les heures de bureau (08:00 à 18:00 UTC) : tout ce qui se passe hors de ces heures et ne ressemble pas à une tâche connue est à expliquer.`, "sys");
    observe(rs);
  }

  /* ---------- signalement ---------- */
  function cmdSignal(c) {
    const x = F(); x.seen = x.seen || {};
    const mi = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(c.rawArg);
    const tt = norm(c.rawArg.replace(/\d{1,3}(?:\.\d{1,3}){3}/g, " "));
    const type = /force|brute|brut/.test(tt) ? "bf" : /balay|scan|recon/.test(tt) ? "scan" : /inject|sql|xss/.test(tt) ? "inj" : /exfil|vol|fuite|sortie/.test(tt) ? "exf" : null;
    if (!mi || !type) { out("Forme attendue : `signaler ‹adresse› ‹type›` avec type = `force brute`, `balayage`, `injection` ou `exfiltration`. Exemple : `signaler 198.51.100.7 balayage`.", "err"); return; }
    const ip = mi[1];
    const need = (flag, msg) => { if (!x.seen[flag]) { say("Maître Ada", msg); return false; } return true; };
    if (ip === ATT) {
      if (type === "bf") {
        if (x.bf) { out("Déjà signalé.", "sys"); return; }
        if (!need("bf", "Sur quelle preuve ? Montre-moi dans les journaux d'authentification une rafale d'échecs depuis cette adresse (`filtrer resultat=ECHEC`, `compter par ip`, `chronologie`).")) return;
        if (!need("ok", "Une rafale d'échecs, bien. Mais l'attaque a-t-elle abouti ? Regarde si un `resultat=OK` suit, pour cette adresse.")) return;
        x.bf = true;
        const fails = D.filter(r => r.cat === "bf").length;
        say("Maître Ada", `Exact : ${ATT} a tenté ${fails} mots de passe en 8 minutes, sans aucun verrouillage, puis s'est connectée en tant que alice à ${hms(eff(K.acces))}, hors des heures de bureau, depuis une adresse jamais vue pour elle. Un échec isolé n'est rien ; c'est la rafale suivie d'un succès qui compte. Et voilà pourquoi une alerte « échecs puis succès » est précieuse.`);
        note("force"); fig("courbe");
        if (!x.corr) out("Astuce : pour recouper cette adresse avec les autres journaux, essaie `ouvrir tout` puis `filtrer ip=" + ATT + "`.", "sys");
      } else if (type === "scan") {
        if (x.scan) { out("Déjà signalé.", "sys"); return; }
        if (!need("scan", "Montre-moi d'abord, dans les journaux web, la rafale de 404 depuis cette adresse (`ouvrir web`, `filtrer code=404`, `compter par ip`, `chronologie`).")) return;
        x.scan = true;
        const n404 = D.filter(r => r.cat === "scan" && r.s === "web" && r.code === 404).length;
        say("Maître Ada", `Oui : ${n404} requêtes en « page introuvable » en neuf minutes, sur /admin, /.env, /phpmyadmin, /backup.zip… L'outil de balayage de Mallory cherche ce que le site n'affiche pas. Une seule réponse intéressante : /backoffice, qui redirige vers une page de connexion. Elle a trouvé la porte à forcer.`);
        if (x.inj) note("inject");
      } else if (type === "inj") {
        if (x.inj) { out("Déjà signalé.", "sys"); return; }
        if (!need("inj", "Montre-moi d'abord des requêtes qui contiennent du code d'attaque : `ouvrir web`, `filtrer ip=" + ATT + " chemin~select`, `afficher 8 lignes`.")) return;
        x.inj = true;
        say("Maître Ada", "Oui : UNION SELECT, ' OR 1=1, <script>, ../../etc/passwd, SLEEP(5)… un catalogue d'injections, répété sur plusieurs pages. Elles ont échoué ici (erreurs 500 ou 404), mais les 500 signalent une application fragile : à corriger. Et regarde l'encodage : %27, %20, %3C. Ce sera important pour écrire des règles.");
        if (x.scan) note("inject");
      } else {
        out("Cette adresse est celle d'où l'attaque est arrivée : elle n'a pas reçu de données. L'exfiltration part de l'intérieur vers une adresse extérieure : cherche dans le pare-feu, côté sortant.", "sys");
      }
      return;
    }
    if (ip === SPR) {
      if (type === "bf") {
        x.spray = true;
        say("Maître Ada", `Bien vu : ${SPR} essaie un mot de passe à la fois sur trente-cinq comptes, un essai toutes les 77 secondes, de 04:00 à 05:30. Aucun succès, mais une attaque lente passe sous les seuils courts : on l'appelle pulvérisation de mots de passe (password spraying). Garde-la en tête pour écrire tes règles.`);
      } else out("Cette adresse ne fait que des tentatives de connexion, lentes, sur le portail. Pas de preuve de ce type d'attaque.", "sys");
      return;
    }
    if (ip === EXF) {
      if (type === "exf") {
        if (x.exf) { out("Déjà signalé.", "sys"); return; }
        if (!need("exf", "Montre-moi le volume : `ouvrir pare-feu`, `filtrer sens=SORTANT`, `compter par dst volume`, puis `filtrer dst=" + EXF + "`.")) return;
        x.exf = true;
        const fl = D.filter(r => r.cat === "exf"), tot = fl.reduce((a, r) => a + r.octets, 0);
        say("Maître Ada", `Oui. ${fl.length} transferts de ${DB1} (la base de données !) vers ${EXF}, adresse absente du registre, de ${hms(eff(K.exfil))} à ${hms(Math.max(...fl.map(eff)))}, soit ${fo(tot)} au total. En pleine nuit, hors des heures de bureau. Et la sauvegarde nocturne de 300 Mo vers 192.0.2.50, elle, est attendue : destination connue, heure habituelle. C'est cela, un volume « anormal » : un écart à la référence, pas un gros chiffre.`);
        note("exfil");
      } else out("Cette adresse reçoit des données, elle n'attaque pas le site. Quel type de comportement est-ce ?", "sys");
      return;
    }
    if (ip === SVC) { say("Maître Ada", "Cette machine (compte svc-inventaire) échoue quatorze fois toutes les quinze minutes, jour et nuit : c'est une tâche planifiée dont le mot de passe a changé. Pas une attaque : un défaut de configuration, mais aussi du bruit qui noie les alertes. À corriger, et à exclure avec prudence des règles."); return; }
    if (ip === NAT) { say("Maître Ada", "Cette adresse est la passerelle du bureau partenaire : neuf personnes se connectent derrière la même adresse après un changement de mot de passe, et leurs échecs s'additionnent. Du trafic légitime, pas une attaque."); return; }
    if (ip === CRAWL) { say("Maître Ada", "Cette adresse est un robot d'indexation qui réclame d'anciennes pages : une rafale de 404, comme un balayage, mais sans mauvaise intention. Un seuil trop bas sur les 404 le prend pour un attaquant."); return; }
    if (ip === "192.0.2.50") { say("Maître Ada", "C'est la sauvegarde externalisée, présente au registre : un transfert nocturne volumineux, mais attendu. Un gros volume la nuit ne suffit pas à accuser."); return; }
    if (ip === DB1) { say("Maître Ada", "db-01 est la machine d'où partent les données, mais elle les envoie à l'adresse de quelqu'un. C'est la victime, pas l'attaquant. Qui reçoit ?"); return; }
    if (ip === WEB1) { say("Maître Ada", "web-01 est la machine compromise, le tremplin de l'attaquant : une victime, pas une adresse à bloquer."); return; }
    const n = D.filter(r => r.ip === ip || r.dst === ip).length;
    say("Maître Ada", n ? `Cette adresse apparaît ${n} fois dans les journaux et rien ne ressemble à une attaque de ce type : n'accuse pas sans preuve.` : "Cette adresse n'apparaît dans aucun journal.");
  }

  /* ---------- horloges et chronologie ---------- */
  function cmdShift(c) {
    const x = F();
    if (S.room !== "horloges") { out("Les corrections d'horloge se font à la salle des horloges (ouest du hall).", "sys"); return; }
    const p = c.rawArg.trim().split(/\s+/), k = srcKey(p[0] || "");
    if (!k || k === "tout" || !p[1]) { out("Forme attendue : `decaler ‹source› ‹±durée›`, avec source = auth, web, pare-feu ou systeme. Exemples : `decaler web -2h`, `decaler systeme +1m30s`, `decaler auth 0`.", "err"); return; }
    const v = parseDur(p.slice(1).join(""));
    if (v === null) { out("Durée non comprise. Exemples : `-1h`, `+4m29s`, `-90s`, `0`. La valeur est ce que tu AJOUTES à l'heure écrite par la source pour retrouver l'heure vraie.", "err"); return; }
    x.shift[k] = v;
    out(`Source « ${SRCS[k]} » : correction de ${durTxt(v)} appliquée à toutes ses lignes (heure vraie = heure écrite ${durTxt(v)}).`, "ok");
    const g = anchorGaps();
    out("Contrôle des ancres (le second journal doit suivre le premier de quelques secondes, jamais le précéder ni le suivre de minutes) :", "sys");
    const line = (lbl, gap) => `  ${lbl} : écart ${gap >= 0 ? "+" : ""}${gap >= 60 || gap <= -60 ? Math.floor(Math.abs(gap) / 60) * Math.sign(gap) + " min " + Math.abs(gap % 60) + " s" : gap + " s"} ${Math.abs(gap - 2) <= TOL ? "✓ cohérent" : gap < 0 ? "✗ effet avant sa cause" : "✗ trop tard"}`;
    code(line("web / pare-feu (connexion de " + ATT + " à 02:12)", g.web) + "\n" + line("systeme / pare-feu (SSH vers db-01 depuis " + WEB1 + ")", g.sys));
    if (["auth", "fw"].includes(k) && v !== 0) out("Cette source est déjà en UTC et synchronisée par NTP : n'y touche pas, c'est elle qui sert de référence. `decaler " + (k === "fw" ? "pare-feu" : "auth") + " 0` pour annuler.", "err");
    x.clk = clkOK();
    if (x.clk) { out("Les quatre sources racontent maintenant la même histoire sur la même horloge.", "ok"); say("Maître Ada", "Voilà. Plus de contradiction apparente : on peut reconstituer la chronologie. Refais une requête avec `ouvrir tout`, trie par heure, ou passe directement à `ordonner`."); }
  }
  function parseDur(s) {
    s = s.trim().toLowerCase().replace(/\s+/g, "");
    if (/^[+\-−]?0$/.test(s)) return 0;
    const m = /^([+\-−])?(?:(\d+)h)?(?:(\d+)m(?:in)?)?(?:(\d+)s)?$/.exec(s);
    if (!m || (!m[2] && !m[3] && !m[4])) return null;
    const v = (+m[2] || 0) * 3600 + (+m[3] || 0) * 60 + (+m[4] || 0);
    return m[1] === "-" || m[1] === "−" ? -v : v;
  }
  const CANON = ["acces", "webshell", "escalade", "lateral", "exfil"];
  const SNAME = { acces: "accès initial", webshell: "exécution (webshell)", escalade: "escalade de privilèges", lateral: "mouvement latéral", exfil: "exfiltration" };
  const SMAP = { acces: "acces", initial: "acces", entree: "acces", webshell: "webshell", shell: "webshell", televersement: "webshell", execution: "webshell", escalade: "escalade", elevation: "escalade", privileges: "escalade", lateral: "lateral", mouvement: "lateral", rebond: "lateral", exfil: "exfil", exfiltration: "exfil", vol: "exfil" };
  function stageText(k) {
    const r = K[k];
    return { acces: `${r.ip} se connecte en tant que ${r.user}, après 187 échecs`, webshell: `${r.ip} téléverse un fichier dans /backoffice/televerser`, escalade: `${r.user} devient root sur ${r.hote}`, lateral: `${r.hote} accepte le SSH de ${r.user} depuis ${r.ip}`, exfil: `${r.ip} envoie ~40 Mo vers ${r.dst} (douze fois)` }[k];
  }
  function cmdOrder(c) {
    const x = F();
    const toks = norm(c.rawArg).split(" ").filter(t => t && !["puis", "ensuite", "apres", "et", "de", "d", "l", "la", "le", "en"].includes(t));
    const seq = [];
    for (const t of toks) { const s = SMAP[t]; if (!s) { out(`Je ne connais pas l'étape « ${t} ». Étapes : acces, webshell, escalade, lateral, exfiltration.`, "err"); return; } if (seq[seq.length - 1] !== s) seq.push(s); }
    if (seq.length !== 5 || new Set(seq).size !== 5) { out("Donne les cinq étapes, chacune une fois, dans l'ordre où elles se sont produites : `ordonner acces webshell escalade lateral exfiltration` (accès initial, exécution par webshell, escalade de privilèges, mouvement latéral, exfiltration).", "err"); return; }
    const times = CANON.map(k => ({ k, t: eff(K[k]) })).sort((a, b) => a.t - b.t);
    const causal = eff(K.lateral) >= eff(K.ancS_fw) && eff(K.ancW_web) >= eff(K.ancW_fw);
    const coherent = times.map(o => o.k).join() === CANON.join() && causal;
    const tbl = () => code(times.map(o => { const r = K[o.k]; return `${hms(o.t)}  ${SRCS[r.s].padEnd(8)}  ${SNAME[o.k].padEnd(24)} ${stageText(o.k)}`; }).join("\n"));
    if (!coherent) {
      out("Avec les horodatages actuels, les lignes clés s'ordonnent ainsi :", "sys"); tbl();
      const issues = [];
      if (times.map(o => o.k).join() !== CANON.join()) issues.push("l'ordre apparent est impossible (par exemple, un fichier ne peut pas être téléversé après que les données ont déjà quitté le réseau)");
      if (!causal) issues.push("une connexion est acceptée avant que le pare-feu ne l'ait autorisée (l'effet précède la cause)");
      out("Les journaux se contredisent : " + issues.join(" ; ") + ". Ce n'est pas l'attaquant qui est incohérent, ce sont les horloges. Aligne-les à la salle des horloges (`decaler …`), puis recommence.", "err");
      return;
    }
    if (seq.join() !== CANON.join()) {
      out("Ce n'est pas l'ordre indiqué par les journaux alignés :", "err"); tbl();
      out("Une intrusion suit en général ce fil : on entre, on s'installe, on monte en privilèges, on se déplace, on sort avec les données. Chaque étape suppose la précédente.", "sys");
      return;
    }
    x.order = true;
    out("Chronologie reconstituée (UTC, horloges alignées) :", "ok"); tbl();
    say("Maître Ada", "Voilà l'attaque de bout en bout : cinq lignes, quatre sources différentes, sans aucun journal qui la raconte seul. L'accès initial à 02:11, la sortie des données à 02:52 : quarante et une minutes entre l'entrée et le vol. Et sans l'alignement des horloges, tu aurais conclu que le webshell est venu après le vol.");
    note("chrono"); fig("chrono");
  }

  /* ---------- règles ---------- */
  function evalSeuil(n, win, kind, excl) {
    const ev = D.filter(r => kind === "echecs" ? r.s === "auth" && r.resultat === "ECHEC" : r.s === "web" && r.code === 404);
    const by = new Map();
    for (const r of ev) { if (!by.has(r.ip)) by.set(r.ip, []); by.get(r.ip).push(r.t); }
    const WIN = win * 60, alerts = [], maxIn = {}, tot = {};
    for (const [ip, ts] of by) {
      ts.sort((a, b) => a - b); let j = 0, cool = -1, mx = 0; tot[ip] = ts.length;
      for (let i = 0; i < ts.length; i++) {
        while (ts[i] - ts[j] >= WIN) j++;
        const cnt = i - j + 1; if (cnt > mx) mx = cnt;
        if (!excl.includes(ip) && cnt >= n && ts[i] >= cool) { alerts.push({ ip, t: ts[i], n: cnt }); cool = ts[i] + WIN; }
      }
      maxIn[ip] = mx;
    }
    const truth = new Set(); for (const ip of by.keys()) if (MAL.has(ip)) truth.add(ip);
    return { alerts, truth, maxIn, tot };
  }
  function scoreOf(tp, fp, det, nt) { const pr = tp + fp ? tp / (tp + fp) : 0, rc = nt ? det / nt : 1; return { pr, rc, sc: pr + rc ? Math.round(200 * pr * rc / (pr + rc)) : 0 }; }
  function showScore(s, fp) {
    out(`Précision ${pct(s.pr)} (part des alertes justifiées) · Rappel ${pct(s.rc)} (part des attaques détectées) · **Score de qualité : ${s.sc}/100**`, s.sc >= 80 ? "ok" : "err");
    if (fp > 20) out(`Charge pour les analystes : ${nf(fp)} fausses alertes dans la journée. Au-delà d'une vingtaine, plus personne ne les lit sérieusement : l'alerte qui compte se noie au milieu (fatigue d'alerte).`, "err");
  }
  function cmdRule(c) {
    const x = F();
    if (S.room !== "siem") { out("Les règles s'écrivent au centre de détection (est du hall).", "sys"); return; }
    const a = c.rawArg.trim();
    const nb = t => t.replace(/\*\*/g, "*\u200b*");
    const usage = "Deux familles : `regle seuil ‹N› echecs en ‹M› min [sauf ‹ip›]` (aussi `404` à la place de `echecs`) et `regle motif ‹mot› | ‹mot› | …` (cherche dans les chemins web, décodés, sans tenir compte de la casse).";
    if (!a) { out(usage, "err"); return; }
    let m;
    if (/^seuil\b/i.test(a)) {
      m = /^seuil\s+(\d+)\s+(\S+)\s+(?:en|sur)\s+(\d+)\s*(h|heures?|min|minutes?|m)?\b\s*(?:par\s+ip)?\s*(?:sauf\s+(.+))?$/i.exec(a);
      const kind = m ? (/^(echecs?|échecs?)$/i.test(m[2]) ? "echecs" : /^(404|erreurs?)$/i.test(m[2]) ? "404" : null) : null;
      if (!m || !kind) { out("Forme attendue : `regle seuil ‹N› echecs en ‹M› min` (ex. `regle seuil 10 echecs en 5 min`), éventuellement suivie de `sauf ‹ip›`. Pour les pages introuvables : `regle seuil 40 404 en 5 min`.", "err"); return; }
      const n = +m[1], win = +m[3] * (/^h/i.test(m[4] || "") ? 60 : 1), excl = (m[5] || "").match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];
      if (n < 1 || n > 10000 || win < 1 || win > 1440) { out("Seuil entre 1 et 10 000, fenêtre entre 1 et 1 440 minutes.", "err"); return; }
      const e = evalSeuil(n, win, kind, excl);
      const tp = e.alerts.filter(al => MAL.has(al.ip)), fpA = e.alerts.filter(al => !MAL.has(al.ip));
      const det = [...e.truth].filter(ip => e.alerts.some(al => al.ip === ip)), miss = [...e.truth].filter(ip => !det.includes(ip));
      const s = scoreOf(tp.length, fpA.length, det.length, e.truth.size);
      out(`Règle : ${n} ${kind === "echecs" ? "échecs d'authentification" : "réponses 404"} en ${win} min depuis une même adresse${excl.length ? " (sauf " + excl.join(", ") + ")" : ""}. Évaluation sur la journée :`, "title");
      out(`Alertes levées : ${nf(e.alerts.length)} · vraies : ${tp.length} · fausses : ${nf(fpA.length)}`, e.alerts.length ? "sys" : "err");
      if (fpA.length) { const g = {}; fpA.forEach(al => g[al.ip] = (g[al.ip] || 0) + 1); out("Exemples de faux positifs : " + Object.entries(g).sort((p, q) => q[1] - p[1]).slice(0, 4).map(([ip, k]) => `${ip} ×${k}` + (ip === SVC ? " (tâche planifiée)" : ip === NAT ? " (bureau partenaire)" : ip === CRAWL ? " (robot d'indexation)" : "")).join(" · ") + ".", "sys"); }
      if (miss.length) out("Attaques manquées : " + miss.map(ip => `${ip} (${e.tot[ip]} événements en tout, au mieux ${e.maxIn[ip]} dans ta fenêtre de ${win} min, sous ton seuil de ${n})`).join(" ; ") + ". Un seuil trop haut ou une fenêtre trop courte laisse passer l'attaque lente.", "err");
      showScore(s, fpA.length);
      if (kind === "echecs") x.lastSeuil = { n, win, excl, kind };
      if (kind === "echecs") {
        if (s.sc >= 85 && fpA.length <= 3) {
          if (!x.rs) { x.rs = true; say("Bob", "Deux alertes, deux vraies. Celle-là, je la lis."); out("Règle déployée. Attention : exclure 10.0.3.55 est un choix à documenter. Si un attaquant prenait cette adresse, il serait invisible pour cette règle (angle mort).", "ok"); }
          else out("Cette règle est aussi bonne : déployée.", "ok");
        } else if (!x.rs) out("Pas encore assez bonne pour être déployée (il faut 85/100) : cherche le bon compromis entre seuil, fenêtre et exclusions.", "sys");
      } else if (s.sc >= 85) out("Bonne règle de rafales de 404, mais elle n'est pas obligatoire pour l'audit : la règle d'authentification et la règle de motif le sont.", "ok");
      note("regles"); fig("compromis");
      return;
    }
    if (/^motif\b/i.test(a)) {
      const pats = a.replace(/^motif\s*/i, "").split("|").map(s => s.trim().toLowerCase()).filter(Boolean);
      if (!pats.length) { out("Donne au moins un motif : `regle motif union select | <script | ../`. Sépare les motifs par `|`.", "err"); return; }
      if (pats.length > 14) { out("Trop de motifs (14 au plus) : une règle claire vaut mieux qu'une liste interminable.", "err"); return; }
      const hits = [], missed = []; let need = 0, got = 0;
      for (const r of D) {
        if (r.s !== "web") continue;
        const raw = chem(r).toLowerCase(), d = dec(chem(r)).toLowerCase();
        const hit = pats.some(p => raw.includes(p) || d.includes(p));
        if (r.mal === 1) need++;
        if (hit) { hits.push(r); if (r.mal === 1) got++; } else if (r.mal === 1) missed.push(r);
      }
      const tp = hits.filter(r => r.mal), fpL = hits.filter(r => !r.mal);
      const s = scoreOf(tp.length, fpL.length, got, 1);
      s.rc = need ? got / need : 1; s.sc = s.pr + s.rc ? Math.round(200 * s.pr * s.rc / (s.pr + s.rc)) : 0;
      out(nb(`Règle de motif : ${pats.map(p => "« " + p + " »").join(" ou ")}. Évaluation sur les ${nf(srcCount("web"))} requêtes web :`), "title");
      out(`Alertes levées : ${nf(hits.length)} · vraies : ${tp.length} · fausses : ${nf(fpL.length)} · attaques (injection, webshell) manquées : ${need - got} sur ${need}`, hits.length ? "sys" : "err");
      const top = (arr, k) => { const g = {}; arr.forEach(r => { const d = dec(chem(r)).toLowerCase(); g[d] = (g[d] || 0) + 1; }); return Object.entries(g).sort((p, q) => q[1] - p[1]).slice(0, k); };
      if (fpL.length) out(nb("Exemples de faux positifs : " + top(fpL, 3).map(([d, k]) => `${d} ×${k}`).join(" · ")) + ". Un mot courant du langage normal (selection, union, script, description…) ressemble à du code d'attaque.", "sys");
      if (missed.length) out(nb("Exemples d'attaques manquées : " + top(missed, 3).map(([d, k]) => `${d} ×${k}`).join(" · ")) + ". L'attaquant varie l'écriture (commentaires SQL, autres balises) pour passer entre les mailles.", "err");
      showScore(s, fpL.length);
      if (s.sc >= 85 && fpL.length <= 3) { if (!x.rm) { x.rm = true; out("Règle de motif déployée. Elle ne remplace pas une application correcte (requêtes paramétrées, échappement) : c'est un filet, pas un rempart. Un attaquant patient trouvera encore une forme que personne n'a prévue.", "ok"); } else out("Cette règle est aussi bonne : déployée.", "ok"); }
      else if (!x.rm) out("Pas encore assez bonne (85/100 et au plus 3 fausses alertes requis). Vise des fragments assez spécifiques pour ne pas toucher du trafic normal, assez variés pour couvrir les variantes.", "sys");
      note("regles"); fig("compromis");
      return;
    }
    out(usage, "err");
  }

  /* ---------- archives : intégrité, conservation, vie privée ---------- */
  const GEN = sha256("genese");
  const buildChain = () => { let prev = GEN; return LOG.map((t, i) => { const h = sha256(prev + "|" + t); const o = { n: i + 1, text: t, prev, hash: h }; prev = h; return o; }); };
  function verifyChain(ch) {
    let prevHash = GEN, brk = null, mod = null; const res = [];
    for (const l of ch.lines) {
      const okPrev = l.prev === prevHash, okHash = sha256(l.prev + "|" + l.text) === l.hash;
      res.push({ l, okPrev, okHash });
      if (!okPrev && !brk) brk = l; if (!okHash && !mod) mod = l;
      prevHash = l.hash;
    }
    return { res, brk, mod, head: prevHash };
  }
  const s8 = h => h.slice(0, 8);
  function needArch() { if (S.room !== "archives") { out("Cela se passe aux archives (sud du hall).", "sys"); return true; } return false; }
  function cmdCompare() {
    const x = F(); if (needArch()) return;
    out("Comparaison entre la copie locale de web-01 et celle d'Ève (collecteur) :", "sys");
    code(LOG.map((t, i) => `${GONE.includes(i + 1) ? "✗ absente en local" : "✓ présente        "}  ${t}`).join("\n"));
    out(`Local : ${LOG.length - GONE.length} lignes. Collecteur : ${LOG.length} lignes. Quatre lignes ont disparu du disque de web-01 : celles qui montrent le téléversement du webshell, l'exécution de commandes et l'élévation de privilèges, soit les traces de Mallory. Elle avait les droits root et a nettoyé. Sans la copie d'Ève, ce trou ne serait qu'un silence.`, "err");
    say("Ève", "Je reçois chaque ligne dès qu'elle est écrite, par un canal qui ne me laisse pas la modifier non plus : j'écris et je range, c'est tout. Un attaquant qui contrôle web-01 ne contrôle pas mon coffre.");
    if (!x.cmp) { x.cmp = true; out("Mais un collecteur n'est pas tout : peut-on prouver, sans lui, qu'un journal est complet ? Pour cela, on chaîne les lignes : `chainer journal`.", "sys"); }
  }
  function cmdChain() {
    const x = F(); if (needArch()) return;
    x.ch = { lines: buildChain(), anchor: null, deleted: [], rechained: false };
    out("On repart de la copie complète d'Ève. Chaque ligne reçoit une empreinte qui inclut celle de la ligne précédente : h(n) = SHA-256( h(n-1) | texte de la ligne n ), avec une valeur de départ fixe. (Les empreintes ci-dessous sont réelles ; 8 caractères sur 64 affichés.)", "ok");
    code(x.ch.lines.map(l => `${l.n}  ${s8(l.hash)} ← ${s8(l.prev)}  ${l.text.slice(0, 46)}…`).join("\n"));
    out("Modifier ou retirer une ligne change son empreinte, donc celle de toutes les suivantes. `envoyer collecteur` pour déposer la tête de la chaîne chez Ève.", "sys");
    fig("chaine");
  }
  function cmdSend() {
    const x = F(); if (needArch()) return;
    if (!x.ch) { out("Il n'y a pas encore de chaîne : `chainer journal`.", "err"); return; }
    if (x.ch.deleted.length) { out("Trop tard : la tête doit être déposée chez Ève quand le journal est encore sain (en vrai : en continu, à chaque ligne). `chainer journal` recommence la démonstration.", "err"); return; }
    x.ch.anchor = x.ch.lines[x.ch.lines.length - 1].hash;
    say("Ève", `Reçu. La tête de la chaîne est ${s8(x.ch.anchor)}… Je la garde dans mon coffre, hors de portée de la cité.`);
  }
  function cmdDelete(c) {
    const x = F(); if (needArch()) return;
    if (!x.ch) { out("Il faut d'abord une chaîne : `chainer journal`. (Sans chaîne, une ligne retirée ne laisse aucune trace dans le fichier lui-même : c'est ce qui s'est passé cette nuit.)", "err"); return; }
    const m = /\d+/.exec(c.rawArg), n = m ? +m[0] : 0;
    if (!x.ch.lines.some(l => l.n === n)) { out(`Quelle ligne ? \`effacer ligne ‹n›\` avec n parmi ${x.ch.lines.map(l => l.n).join(", ")}.`, "err"); return; }
    x.ch.lines = x.ch.lines.filter(l => l.n !== n); x.ch.deleted.push(n);
    out(`Simulation autorisée : Mallory, root sur la machine, retire la ligne ${n} du fichier. Il reste ${x.ch.lines.length} lignes. \`controler chaine\` pour voir si cela se voit.`, "ok");
    fig("chaine");
  }
  function cmdRechain() {
    const x = F(); if (needArch()) return;
    if (!x.ch || !x.ch.deleted.length) { out("Rien à dissimuler : la chaîne est intacte (`effacer ligne ‹n›` d'abord).", "err"); return; }
    let prev = GEN; x.ch.lines.forEach(l => { l.prev = prev; l.hash = sha256(prev + "|" + l.text); prev = l.hash; }); x.ch.rechained = true;
    out("Mallory connaît l'algorithme (il est public, aucun secret n'y est caché) : elle recalcule les empreintes de toutes les lignes restantes, de la première à la dernière. La chaîne redevient parfaitement cohérente.", "ok");
    fig("chaine");
  }
  function cmdVerify() {
    const x = F(); if (needArch()) return;
    if (!x.ch) { out("Il n'y a pas de chaîne à contrôler : `chainer journal`.", "err"); return; }
    const v = verifyChain(x.ch);
    out(`Contrôle de la chaîne (${x.ch.lines.length} lignes) :`, "sys");
    code(v.res.map(o => `${o.l.n}  ${o.okPrev && o.okHash ? "✓" : "✗"}  ${s8(o.l.hash)} ← ${s8(o.l.prev)}${!o.okPrev ? "  (cette ligne annonce un précédent qui n'est pas la ligne juste avant)" : !o.okHash ? "  (le contenu ne correspond plus à l'empreinte)" : ""}`).join("\n"));
    if (v.brk || v.mod) {
      const l = v.brk || v.mod, i = x.ch.lines.indexOf(l), before = i > 0 ? x.ch.lines[i - 1].n : 0;
      out(`**Rupture détectée** entre la ligne ${before || "de départ"} et la ligne ${l.n} : ${v.brk ? `la ligne ${l.n} a été chaînée à une ligne précédente qui n'est plus là. Des lignes ont disparu juste avant (et l'on ne peut pas les retrouver depuis ce fichier, mais on sait qu'elles ont existé).` : "le contenu a été modifié."}`, "err");
      if (!x.chainBreak) { x.chainBreak = true; note("integrite"); say("Ève", "La chaîne ne peut pas empêcher l'effacement, mais elle le rend visible. Voilà ce qui manquait à web-01 cette nuit."); }
      fig("chaine");
      return;
    }
    if (!x.ch.anchor) {
      out("La chaîne est cohérente de bout en bout. Mais personne d'extérieur ne peut dire si c'est bien la chaîne d'origine : si quelqu'un l'a refaite, ou a coupé la fin, rien ne le montre. Une ancre extérieure (la tête de chaîne déposée ailleurs) manquait : `chainer journal`, `envoyer collecteur`, puis rejoue l'effacement.", x.ch.deleted.length ? "err" : "sys");
      if (x.ch.deleted.length) fig("chaine");
      return;
    }
    const head = x.ch.lines.length ? x.ch.lines[x.ch.lines.length - 1].hash : GEN;
    if (head !== x.ch.anchor) {
      out(`**Falsification détectée** : la chaîne est cohérente, mais sa tête (${s8(head)}…) n'est pas celle qu'Ève a conservée (${s8(x.ch.anchor)}…). ${x.ch.rechained ? "Les empreintes ont été recalculées après l'effacement." : "La fin du journal a été tronquée : retirer les dernières lignes ne casse aucun maillon."} L'ancre extérieure démasque ce qu'aucun contrôle interne ne voyait.`, "err");
      if (!x.anchorHit) { x.anchorHit = true; say("Ève", "Je n'ai pas de pouvoir sur le journal de web-01, mais j'ai gardé la tête de la chaîne. Une chaîne refaite par un attaquant root ne ressemblera jamais à celle que j'ai déjà. En vrai on ancre en continu, ou on signe les têtes avec une clé que le serveur ne possède pas."); }
      fig("chaine");
    } else out(`La chaîne est cohérente et sa tête (${s8(head)}…) correspond à celle d'Ève : le journal est complet et intact.`, "ok");
  }
  function cmdKeep(c) {
    const x = F(); if (needArch()) return;
    const p = norm(c.rawArg).split(" ").filter(Boolean);
    const show = () => code(["auth", "web", "fw", "sys"].map(k => `${SRCS[k].padEnd(9)} ${String(x.ret[k]).padStart(4)} jours`).join("\n"));
    if (!p.length) { out("Durées de conservation actuelles :", "sys"); show(); out("`conserver ‹source› ‹jours›` (source = auth, web, pare-feu, systeme ou tout).", "sys"); return; }
    const k = srcKey(p[0]), d = +(p[1] || "").replace(/\D/g, "");
    if (!k || !d || !/^\d+$/.test(p[1] || "")) { out("Forme attendue : `conserver ‹source› ‹jours›` (ex. `conserver auth 180`).", "err"); return; }
    if (d < 90) { out(`${d} jours, c'est trop court : les intrusions se découvrent souvent des semaines, voire des mois, après les faits. Sans historique, on ne peut ni remonter à l'accès initial ni dater la compromission. Vise au moins 90 jours.`, "err"); return; }
    if (d > 365) { out(`${d} jours, c'est trop long : adresses IP et identifiants sont des données personnelles. Le principe de minimisation demande de ne conserver que ce qui est utile, le temps nécessaire. Au-delà d'un an, il faut une justification solide (obligation légale, enquête en cours).`, "err"); return; }
    (k === "tout" ? ["auth", "web", "fw", "sys"] : [k]).forEach(s => x.ret[s] = d);
    out(`Conservation de ${k === "tout" ? "toutes les sources" : "« " + srcLabel(k) + " »"} fixée à ${d} jours.`, "ok"); show();
    if (["auth", "web", "fw", "sys"].every(s => x.ret[s] >= 90 && x.ret[s] <= 365)) {
      if (!x.retOK) { x.retOK = true; say("Ève", "Entre trois mois et un an, selon ton contexte légal : assez pour enquêter, pas plus que nécessaire. Et chaque durée doit être écrite dans une politique, pas seulement dans une configuration."); if (x.masked) note("conserv"); }
    } else out("Il reste des sources hors de la fourchette 90 à 365 jours.", "sys");
  }
  function cmdMask(c) {
    const x = F(); if (needArch()) return;
    if (!/mdp|mot|passe|password|secret/.test(norm(c.rawArg))) { out("Quoi masquer ? `masquer mdp` (les mots de passe dans les adresses de requête).", "err"); return; }
    if (x.masked) { out("Déjà masqué.", "sys"); return; }
    if (!(x.seen && x.seen.pw)) { say("Ève", "Masquer quoi ? Va d'abord voir si des secrets traînent dans les journaux web (`ouvrir web`, `filtrer chemin~mdp`, `afficher 5 lignes`)."); return; }
    x.masked = true;
    const n = D.filter(r => r.pw).length;
    out(`Règle de masquage installée à la source : tout paramètre « mdp= » est remplacé par « mdp=*** » avant d'être écrit. ${n} lignes déjà écrites ont été réécrites.`, "ok");
    out("Mais ces mots de passe ont déjà été lus par ton analyse, copiés dans des sauvegardes, envoyés au collecteur : ils doivent être considérés comme exposés et changés. Et le vrai défaut est ailleurs : un formulaire qui envoie un mot de passe dans l'adresse (GET) au lieu du corps de la requête (POST).", "err");
    say("Ève", "Règle d'or : on journalise ce qui s'est passé, pas les secrets. Mots de passe, jetons, numéros de carte : jamais, ni en clair ni en paramètre d'URL.");
    if (x.retOK) note("conserv");
  }

  /* ---------- fin ---------- */
  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "L'alerte « comportement inhabituel » avait un nom, une heure et un chemin : une force brute à 02:03, un compte compromis à 02:11, un webshell, une escalade, un rebond vers la base de données et quatre cent quatre-vingts mégaoctets partis vers 198.51.100.99. Tout était dans les journaux. Il fallait seulement savoir les lire ensemble.");
    say("Maître Ada", "Désormais, les horloges sont alignées, Bob ne lira que de vraies alertes, les journaux sont chaînés et copiés chez Ève, la conservation est raisonnable et plus aucun mot de passe n'y traîne. Alice va changer son mot de passe et recevoir une authentification multifacteur. Mallory devra trouver une autre porte.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La salle des journaux et sa console = un SIEM** (Splunk, Elastic, Sentinel…). Son langage (`filtrer`, `compter par`, `trier`, `chronologie`) imite celui des vraies requêtes (SPL, KQL, Lucene…) : sélectionner, agréger, ordonner, tracer dans le temps. Les quatre journaux sont les sources classiques : authentification, serveur web, pare-feu, hôtes.");
    out("**La force brute et le pic** : des centaines d'échecs depuis une adresse puis un succès. Le pic se voit à la chronologie, la corrélation avec le succès fait la gravité. La même adresse retrouvée dans les journaux web et le pare-feu, c'est la **corrélation entre sources**. Le bruit (tâche planifiée aux mots de passe périmés, bureau partenaire derrière une même adresse, robot d'indexation) est la raison pour laquelle on ne se contente jamais de compter.");
    out("**Le balayage et l'injection** : une rafale de 404, puis des paramètres bourrés de SQL, de script et de `../`. Dans le monde réel, on les complète par un pare-feu applicatif (WAF) et, surtout, par une application correcte (requêtes paramétrées, validation) : un code 500 sur une entrée piégée est un défaut à corriger, pas une victoire.");
    out("**L'exfiltration** : une base de données qui envoie 480 Mo à une adresse inconnue la nuit. La détection repose sur une référence (destinations connues, volumes habituels) ; la prévention sur la segmentation (ici, la DMZ n'aurait pas dû pouvoir ouvrir de SSH vers l'interne) et sur le filtrage des sorties.");
    out("**Les horloges** : UTC et NTP partout. Un serveur en heure locale (+01:00) ou à l'horloge dérivée produit des histoires impossibles (effet avant cause). Les « ancres » sont des événements vus par deux sources, qui permettent de mesurer l'écart.");
    out("**Les règles** : un seuil (taux d'événements par fenêtre) et un motif (signature). Précision et rappel sont les deux faces du compromis faux positifs / faux négatifs ; la fatigue d'alerte est un risque de sécurité en soi. Exclure une source bénigne est utile et crée un angle mort ; les vraies règles s'écrivent en corrélant plusieurs événements (échecs puis succès, nouvelle adresse, heure inhabituelle) et se révisent.");
    out("**Ève et la chaîne d'empreintes** : Ève est le collecteur central (syslog sur TLS, agent, journal d'audit en écriture seule). La chaîne SHA-256 rend la suppression ou la modification d'une ligne détectable ; une ancre extérieure rend détectable la chaîne refaite et la fin tronquée. Le principe est celui des journaux de transparence et des blockchains, sans la partie consensus.");
    out("**Conservation et vie privée** : durée justifiée (de quelques mois à un an en pratique, selon la loi), accès restreint, masquage des secrets à la source, et un secret déjà journalisé est un secret compromis.");
    out("**Les simplifications du jeu.** (1) Les données comptent environ 5 500 lignes et un seul incident : un vrai SIEM en ingère des millions par jour, avec bien plus de bruit, d'ambiguïté et de sources (DNS, courrier, cloud, postes). (2) Le langage de requête est un jouet, pas du SPL ou du KQL. (3) Les règles évaluées sont deux familles simples ; les vraies corrèlent des séquences d'événements, des listes de réputation et des profils de comportement, et sont testées sur des mois de données. (4) La détection ne remplace pas la prévention : l'authentification multifacteur, un verrouillage ou une limitation des essais, des correctifs, la segmentation et le filtrage des sorties auraient bloqué cette attaque avant qu'elle ne laisse une ligne. (5) Une chaîne d'empreintes réelle utilise souvent des signatures ou des HMAC, des horodatages de confiance et un stockage non effaçable (WORM), pas seulement un SHA-256 et une ancre manuelle. (6) Les durées légales de conservation dépendent du pays et du secteur : ce que le jeu donne est un ordre de grandeur, pas un avis juridique. (7) Toutes les adresses sont des adresses de documentation (RFC 5737) et tout est fictif.");
    out("Rappel utile : **un journal ne vaut que s'il est complet, horodaté de façon cohérente, copié hors de portée de l'attaquant, et lu par des règles qui ne noient pas ceux qui doivent les lire.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    pipeline: () => ({
      cap: "Du système à l'alerte : chaque source écrit un journal, un collecteur en garde une copie hors de portée, le SIEM corrèle et applique des règles, un analyste reçoit l'alerte.",
      svg: SVG(230, "Pipeline de journalisation",
        ["connexions", "serveur web", "pare-feu", "hôtes"].map((n, i) => R(6, 14 + i * 38, 90, 30) + T(51, 33 + i * 38, n, "f-s")).join("") +
        [29, 67, 105, 143].map(y => AR(96, y, 128, 98 + (y - 98) * 0.3, "f-pub")).join("") +
        T(51, 10, "sources", "f-b") +
        R(128, 50, 82, 96, "f-ok") + T(169, 80, "collecteur", "f-b ft-ok") + T(169, 98, "copie hors", "f-s") + T(169, 112, "portée", "f-s") +
        AR(210, 98, 238, 98, "f-pub") +
        R(238, 50, 90, 96, "f-pub") + T(283, 80, "SIEM", "f-b ft-pub") + T(283, 98, "corrèle", "f-s") + T(283, 112, "règles", "f-s") + T(283, 126, "courbes", "f-s") +
        AR(328, 98, 346, 98, "f-bad") +
        R(346, 66, 68, 64, "f-bad") + T(380, 94, "alerte", "f-b ft-bad") + T(380, 112, "analyste", "f-s") +
        T(210, 178, "horloges alignées (UTC, NTP) · chaînage", "f-s") +
        T(210, 196, "masquage des secrets · conservation raisonnée", "f-s") +
        T(210, 218, "si un maillon manque, l'histoire a un trou", "f-s ft-priv"))
    }),
    courbe: () => {
      const x = F(), B = 144, cnt = new Array(B).fill(0), att = new Array(B).fill(0), spr = new Array(B).fill(0);
      for (const r of D) if (r.s === "auth" && r.resultat === "ECHEC") { const b = Math.min(B - 1, Math.floor(r.tt / 600)); if (r.ip === ATT) att[b]++; else if (r.ip === SPR) spr[b]++; else cnt[b]++; }
      const mx = Math.max(...cnt.map((v, i) => v + att[i] + spr[i])), H = 110, base = 140, bw = 2.6;
      let bars = "";
      for (let i = 0; i < B; i++) {
        const xx = 24 + i * bw, h1 = cnt[i] / mx * H, h2 = spr[i] / mx * H, h3 = att[i] / mx * H;
        const cA = x.bf ? "var(--bad)" : "var(--dim)", cS = x.rs ? "var(--note)" : "var(--dim)";
        bars += `<rect x="${xx.toFixed(1)}" y="${(base - h1).toFixed(1)}" width="2.2" height="${h1.toFixed(1)}" fill="var(--line)"/>` +
          (h2 ? `<rect x="${xx.toFixed(1)}" y="${(base - h1 - h2).toFixed(1)}" width="2.2" height="${h2.toFixed(1)}" fill="${cS}"/>` : "") +
          (h3 ? `<rect x="${xx.toFixed(1)}" y="${(base - h1 - h2 - h3).toFixed(1)}" width="2.2" height="${h3.toFixed(1)}" fill="${cA}"/>` : "");
      }
      const tk = [0, 6, 12, 18, 24].map(h => LN(24 + h * 6 * bw, base, 24 + h * 6 * bw, base + 4) + T(24 + h * 6 * bw, base + 16, String(h).padStart(2, "0") + "h", "f-s")).join("");
      return {
        cap: x.bf ? "Échecs d'authentification par tranche de 10 minutes, sur la journée : en rouge, la force brute (pic de 02:00) ; en gris, le bruit normal (dents de scie de la tâche planifiée toutes les 15 min)." + (x.rs ? " En violet : l'attaque lente de 04:00 à 05:30." : "")
          : "Échecs d'authentification par tranche de 10 minutes, sur la journée : un pic à 02:00 se détache d'un bruit régulier. Qui est derrière ? (Signale la force brute pour le colorer.)",
        svg: SVG(172, "Courbe des échecs d'authentification",
          LN(24, base, 24 + B * bw, base) + bars + tk +
          T(24 + 12 * bw, 14, x.bf ? "force brute" : "pic ?", x.bf ? "f-s ft-bad" : "f-s", "start") +
          (x.rs ? T(100, 110, "attaque lente", "f-s ft-pub", "start") : "") +
          T(6, 12, "échecs", "f-s", "start"))
      };
    },
    chrono: () => {
      const x = F(), t0 = 7200, t1 = 12600, X0 = 78, X1 = 408, ok = x.clk;
      const px = t => X0 + (Math.max(t0, Math.min(t1, t)) - t0) / (t1 - t0) * (X1 - X0);
      const lanes = { auth: 52, web: 92, fw: 132, sys: 172 };
      const nm = { auth: "auth", web: "web", fw: "pare-feu", sys: "systeme" };
      let b = Object.keys(lanes).map(k => T(8, lanes[k] + 4, nm[k], "f-s", "start") + LN(X0, lanes[k], X1, lanes[k], "f-dash")).join("");
      b += [7200, 9000, 10800, 12600].map(t => LN(px(t), 28, px(t), 196) + T(px(t), 212, hms(t).slice(0, 5), "f-s")).join("");
      const ev = [["acces", 1], ["webshell", 2], ["escalade", 3], ["lateral", 4], ["exfil", 5]];
      const pts = ev.map(([k, n]) => { const r = K[k], t = eff(r), cl = t < t0 || t > t1; return { k, n, x: px(t), y: lanes[r.s], cl, t }; });
      if (ok) b += pts.map((p, i) => i ? LN(pts[i - 1].x, pts[i - 1].y, p.x, p.y, "f-ok") : "").join("");
      b += pts.map(p => `<circle cx="${p.x.toFixed(1)}" cy="${p.y}" r="10" fill="var(--panel)" stroke="${ok ? "var(--ok)" : "var(--bad)"}" stroke-width="1.6"/>` + T(p.x.toFixed(1), p.y + 4, String(p.n), "f-b") + (p.cl ? T(p.x.toFixed(1), p.y - 14, hms(p.t).slice(0, 5), "f-s ft-bad") : "")).join("");
      b += T(8, 14, "1 accès  2 webshell  3 escalade  4 latéral  5 exfiltration", "f-s", "start");
      return {
        cap: ok ? "Cinq événements de quatre journaux, une fois les horloges alignées (web −1 h, systeme environ +4 min 30 s) : l'ordre est celui d'une intrusion, de l'accès initial à 02:11 à la sortie des données à 02:52."
          : "Avec les horodatages bruts, l'ordre des cinq étapes est incohérent : le webshell (2) apparaît après l'exfiltration (5), le SSH (4) avant d'être autorisé. Aligne les horloges pour retrouver l'ordre réel.",
        svg: SVG(222, "Chronologie de l'attaque", b)
      };
    },
    compromis: () => {
      const x = F(), L = x.lastSeuil || { n: 30, win: 5, excl: [] };
      const Ns = [2, 5, 10, 20, 30, 45, 60, 100, 200];
      const res = Ns.map(n => { const e = evalSeuil(n, L.win, "echecs", L.excl), fp = e.alerts.filter(a => !MAL.has(a.ip)).length, miss = [...e.truth].filter(ip => !e.alerts.some(a => a.ip === ip)).length; return { n, fp, miss }; });
      const mxl = Math.log10(1 + Math.max(...res.map(r => r.fp), 10)), base = 128, H = 80;
      let b = T(8, 14, "alertes inutiles (faux positifs) par jour", "f-s", "start");
      res.forEach((r, i) => {
        const xx = 40 + i * 40, h = Math.log10(1 + r.fp) / mxl * H, cur = Math.abs(Math.log(r.n / L.n)) < 0.2;
        b += (cur ? `<rect x="${xx - 18}" y="22" width="36" height="${base - 14}" rx="4" fill="none" stroke="var(--you)" stroke-dasharray="3 3"/>` : "") +
          `<rect x="${xx - 11}" y="${(base - h).toFixed(1)}" width="22" height="${h.toFixed(1)}" fill="var(--bad)" opacity=".75"/>` +
          T(xx, base - h - 4, String(r.fp), "f-s") + T(xx, base + 14, "N=" + r.n, "f-s") +
          T(xx, base + 42, String(r.miss), r.miss ? "f-b ft-bad" : "f-b ft-ok");
      });
      b += LN(24, base, 410, base) + T(8, base + 42, "manqués", "f-s", "start") + T(8, base + 62, `fenêtre ${L.win} min${L.excl.length ? ", sauf " + L.excl.join(", ") : ""}`, "f-s", "start") + T(8, base + 78, `cadre pointillé : ton dernier seuil (N = ${L.n})`, "f-s", "start");
      return {
        cap: "Plus le seuil N monte, moins il y a de fausses alertes (barres rouges, échelle logarithmique) mais plus on manque d'attaques (ligne « manqués », sur 2 attaquants). Fenêtre et exclusions changent la courbe : chaque point est calculé sur les vraies données.",
        svg: SVG(222, "Compromis faux positifs et faux négatifs", b)
      };
    },
    chaine: () => {
      const x = F(), ch = x.ch || { lines: buildChain(), anchor: null, deleted: [] };
      const bySlot = new Map(ch.lines.map(l => [l.n, l])); let prevHash = GEN, b = "", prevSlotOk = true;
      const present = ch.lines.map(l => l.n);
      for (let n = 1; n <= LOG.length; n++) {
        const col = (n - 1) % 4, row = Math.floor((n - 1) / 4), xx = 8 + col * 104, yy = 10 + row * 76, l = bySlot.get(n);
        if (!l) { b += `<rect x="${xx}" y="${yy}" width="96" height="60" rx="6" class="f-box f-bad f-dash"/>` + T(xx + 48, yy + 26, "n° " + n, "f-b ft-bad") + T(xx + 48, yy + 44, "effacée", "f-s ft-bad"); continue; }
        const okP = l.prev === prevHash, okH = sha256(l.prev + "|" + l.text) === l.hash; prevHash = l.hash;
        b += R(xx, yy, 96, 60, okP && okH ? "f-ok" : "f-bad") + T(xx + 48, yy + 16, "n° " + n, "f-b") + T(xx + 48, yy + 32, "préc " + s8(l.prev), "f-s" + (okP ? "" : " ft-bad")) + T(xx + 48, yy + 48, "hash " + s8(l.hash), "f-s" + (okH ? "" : " ft-bad"));
        if (col < 3 && bySlot.get(n + 1)) b += LN(xx + 96, yy + 30, xx + 104, yy + 30);
      }
      const head = ch.lines.length ? ch.lines[ch.lines.length - 1].hash : GEN, drift = ch.anchor && head !== ch.anchor;
      b += T(8, 176, ch.anchor ? `ancre ${s8(ch.anchor)}… · tête ${s8(head)}… ${drift ? "✗ différentes" : "✓ identiques"}` : "pas d'ancre extérieure (tête non déposée)", "f-s" + (drift ? " ft-bad" : ch.anchor ? " ft-ok" : ""), "start");
      return {
        cap: "Chaque case contient l'empreinte de la ligne et celle de la précédente (valeurs réelles, 8 caractères sur 64). Retirer une ligne casse le lien suivant (rouge) ; recalculer toute la chaîne la répare, mais sa tête ne ressemble plus à l'ancre déposée chez Ève.",
        svg: SVG(190, "Chaîne d'empreintes des journaux", b)
      };
    },
  };

  GAMES.logs = {
    id: "logs", order: 21, title: "La Salle des Journaux", pageTitle: "Logs Quest", subtitle: "aventure textuelle · journaux et détection",
    blurb: "Une alerte vague : fouille les journaux, retrouve l'intrusion de Mallory, écris des règles de détection qui ne noient personne.",
    concept: "Journaux, détection d'intrusion, règles d'alerte",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.shift = { auth: 0, web: 0, fw: 0, sys: 0 }; x.ret = { auth: 7, web: 14, fw: 7, sys: 30 }; x.seen = {}; x.flt = []; x.src = null; },
    figAlias: { pipeline: ["siem", "collecteur", "sources", "journalisation"], courbe: ["pic", "force", "brute", "echecs"], chrono: ["chronologie", "attaque", "horloge", "temps"], compromis: ["faux", "regle", "seuil", "positifs"], chaine: ["empreintes", "integrite", "hash", "chainage"] },
    help: "Spécifiques (salle des journaux) : `ouvrir ‹auth|web|pare-feu|systeme|tout›` · `filtrer ‹champ›=‹valeur›` · `compter par ‹champ› [volume]` · `trier ‹champ›` · `chronologie` · `afficher ‹n› lignes` · `signaler ‹ip› ‹type›`\nHorloges : `decaler ‹source› ‹±durée›` · `ordonner ‹étapes›` · Détection : `regle seuil …` / `regle motif …`\nArchives : `comparer collecteur` · `chainer journal` · `envoyer collecteur` · `effacer ligne ‹n›` · `recalculer chaine` · `controler chaine` · `conserver ‹source› ‹jours›` · `masquer mdp`",
    verbs: {
      open: { words: ["ouvrir", "charger"], run: cmdOpen },
      filter: { words: ["filtrer", "filtre"], run: cmdFilter },
      count: { words: ["compter", "grouper"], run: cmdCount },
      sort: { words: ["trier"], run: cmdSort },
      timeline: { words: ["chronologie", "histogramme"], run: cmdTimeline },
      show: { words: ["afficher", "montrer"], run: cmdShow },
      signal: { words: ["signaler", "declarer", "conclure"], run: cmdSignal },
      shift: { words: ["decaler", "corriger", "aligner"], run: cmdShift },
      order: { words: ["ordonner", "classer"], run: cmdOrder },
      rule: { words: ["regle", "regles"], run: cmdRule },
      compare: { words: ["comparer"], run: cmdCompare },
      chain: { words: ["chainer"], run: cmdChain },
      send: { words: ["envoyer", "transmettre", "ancrer"], run: cmdSend },
      del: { words: ["effacer", "supprimer", "retirer"], run: cmdDelete },
      rechain: { words: ["recalculer"], run: cmdRechain },
      verify: { words: ["controler", "auditer"], run: cmdVerify },
      keep: { words: ["conserver", "retenir"], run: cmdKeep },
      mask: { words: ["masquer", "caviarder"], run: cmdMask },
    },
    intro() {
      out("La Salle des Journaux", "title");
      out("Ce matin, le SIEM de Port-443 a levé une alerte d'une ligne : « comportement inhabituel ». Pas d'adresse, pas d'heure, pas de compte. Pendant la nuit, la cité a écrit des milliers de lignes dans quatre journaux : authentification, serveur web, pare-feu, hôtes. Quelque part dedans, Mallory.\nMaître Ada te confie l'audit, autorisé et simulé sur des données fictives : retrouve l'intrusion, reconstitue son déroulé, puis écris des règles qui la détecteront la prochaine fois sans noyer Bob sous les fausses alertes.", "");
    },
  };
})();
