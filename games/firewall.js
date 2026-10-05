"use strict";
/* La Muraille de Port-443 : pare-feu, règles ordonnées, état des connexions, NAT, DMZ et segmentation.
   Un vrai moteur de filtrage simulé évalue les règles écrites par le joueur. */
(function () {
  const F = () => f();
  const EPH = 51514;                 // port source éphémère des clients
  const PUB = "203.0.113.10";        // adresse publique de la cité (plage de documentation)
  const HOSTS = {
    web: { zone: "dmz", ip: "10.0.2.10", ports: [22, 80, 443, 8080] },
    courrier: { zone: "dmz", ip: "10.0.2.20", ports: [25] },
    comptes: { zone: "interne", ip: "10.0.3.5", ports: [22, 3306] },
    sauvegardes: { zone: "interne", ip: "10.0.3.6", ports: [445] },
    poste: { zone: "interne", ip: "10.0.3.25", ports: [3389] },
  };
  const SERV = { 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp", 8080: "http-alt" };
  const SCAN = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080];
  const PAIRS = [["internet", "dmz"], ["internet", "interne"], ["internet", "pare-feu"], ["dmz", "internet"], ["dmz", "interne"], ["interne", "internet"], ["interne", "dmz"]];
  const LEGIT = new Set(["internet>dmz>tcp/443", "internet>dmz>tcp/25", "interne>dmz>tcp/22", "interne>internet>tcp/443"]);
  const ZIP = { internet: "198.51.100.7", dmz: "10.0.2.10", interne: "10.0.3.25" };

  const notes = {
    filtrage: ["Le filtrage de paquets", "Un pare-feu examine chaque paquet qui traverse la frontière entre deux zones (protocole, adresses, ports) et décide : laisser passer, abandonner ou rejeter. Ses règles ne parlent que de ces en-têtes : il ne « comprend » pas ce que contient la requête."],
    defaut: ["Politique par défaut : tout refuser", "Une liste noire (« tout passe sauf ce que j'interdis ») oublie toujours quelque chose. On fait l'inverse (default deny) : tout est refusé par défaut, et l'on n'autorise que les flux dont on a besoin et que l'on sait décrire. Ce qui n'est pas prévu est bloqué."],
    ordre: ["L'ordre des règles", "Les règles sont lues de haut en bas et la première qui correspond décide : les suivantes ne sont pas lues. Une règle large placée trop haut (« autoriser tout ») rend inutiles toutes celles qui la suivent. Les règles précises passent avant les règles générales."],
    etat: ["Avec état ou sans état (stateful / stateless)", "Un filtre sans état juge chaque paquet isolément : il faut une règle pour l'aller ET une pour le retour. Un filtre à suivi de connexions (stateful) mémorise les connexions autorisées et accepte automatiquement leurs réponses ; un paquet « de retour » sans connexion connue est jugé comme un nouveau paquet. C'est le mode normal aujourd'hui."],
    ports: ["Ports ouverts, fermés, filtrés", "Un balayage (type nmap) envoie des sondes. Ouvert : un service répond. Fermé : la machine répond « personne ici » (RST). Filtré : un pare-feu abandonne la sonde (silence, le scanner patiente) ou la rejette par un message ICMP (immédiat) : on ne sait pas s'il y a quelque chose derrière. Abandonner ne renseigne pas l'attaquant et la ralentit ; rejeter est plus poli, utile en interne (l'erreur est immédiate). Un rejet par RST ressemblerait à « fermé »."],
    nat: ["Le NAT : traduction d'adresses", "Les machines de la cité ont des adresses privées (10.x.x.x), non routables sur Internet. Le NAT sortant (masquerade) remplace l'adresse source par l'adresse publique ; le NAT entrant (redirection de port, DNAT) envoie le port 443 de l'adresse publique vers le serveur web. La traduction a lieu avant le filtre : les règles voient l'adresse interne. Attention : le NAT n'est pas un pare-feu, ce sont les règles qui protègent."],
    dmz: ["DMZ et segmentation", "Les services exposés à Internet vivent dans une zone à part, la DMZ, séparée du réseau interne. Si le serveur web est compromis, l'attaquant est dans la DMZ : sans règle DMZ → interne, il ne peut pas rebondir (mouvement latéral) vers les comptes et les sauvegardes. On autorise l'interne vers la DMZ (administration), pas l'inverse."],
    egress: ["Le filtrage sortant (egress)", "On filtre aussi ce qui SORT : une machine compromise doit appeler son maître (commande et contrôle) ou exfiltrer des données. N'autoriser que les sorties nécessaires (ici : navigation en HTTPS depuis l'interne, rien depuis la DMZ) casse beaucoup de ces appels et rend les anomalies visibles."],
    limites: ["Les limites d'un pare-feu", "Le pare-feu a laissé passer l'attaque contre le site : le port 443 est légitime et il ne voit que des en-têtes. Il ne remplace ni la mise à jour des services, ni une application codée correctement, ni la surveillance. Il réduit la surface d'attaque et limite les dégâts, rien de plus. Et un appel HTTPS sortant autorisé reste possible pour un logiciel malveillant."],
  };

  /* ---------- analyse des commandes ---------- */
  const ACT = { autoriser: "autoriser", accepter: "autoriser", permettre: "autoriser", laisser: "autoriser", refuser: "refuser", bloquer: "refuser", abandonner: "refuser", interdire: "refuser", drop: "refuser", rejeter: "rejeter", reject: "rejeter" };
  const PROTO = { tcp: "tcp", udp: "udp", icmp: "icmp", tout: "tout", ip: "tout", tous: "tout" };
  const ZMAP = { internet: "internet", dehors: "internet", exterieur: "internet", dmz: "dmz", interne: "interne", lan: "interne", interieur: "interne", tout: "tout", toute: "tout", toutes: "tout", tous: "tout", partout: "tout", any: "tout", parefeu: "pare-feu" };
  const ALL = ["tout", "toute", "toutes", "tous", "any", "partout"];
  const toks = raw => norm(raw).replace(/\bpare feu\b|\bfirewall\b|\bmuraille\b/g, "parefeu").replace(/\breseau interne\b/g, "interne").split(" ").filter(Boolean);
  const EX = "Exemple : `regle autoriser tcp 443 de internet vers dmz`";

  function parseFlow(tk, withAct) {
    tk = tk.slice(); const o = { pm: "dport", port: null };
    if (withAct) {
      if (/^\d+$/.test(tk[0] || "") && tk.length > 1) o.pos = +tk.shift();
      const a = ACT[tk.shift()];
      if (!a) return { err: "Une règle commence par une action : `autoriser`, `refuser` (abandon silencieux) ou `rejeter` (refus annoncé). " + EX };
      o.act = a;
    }
    const pr = PROTO[tk.shift()];
    if (!pr || (!withAct && pr === "tout")) return { err: "Protocole attendu : `tcp`, `udp` ou `icmp`" + (withAct ? " (ou `tout`)" : "") + ". " + (withAct ? EX : "Exemple : `tester tcp 443 de internet vers dmz`") };
    o.proto = pr;
    const i = tk.findIndex(t => t === "de" || t === "depuis" || t === "d");
    if (i < 0) return { err: "Il manque « de ‹zone› vers ‹zone› » (zones : internet, dmz, interne" + (withAct ? ", ou tout" : "") + "). " + (withAct ? EX : "Exemple : `tester tcp 443 de internet vers dmz`") };
    const spec = tk.slice(0, i), rest = tk.slice(i + 1).filter(t => !["le", "la", "les", "l"].includes(t));
    if (pr === "tcp" || pr === "udp") {
      if (spec[0] === "port") spec.shift();
      if (spec[0] === "source") { if (!withAct) return { err: "Le banc d'essai envoie une NOUVELLE connexion : le port source est choisi par le client. Donne seulement le port de destination." }; o.pm = "sport"; spec.shift(); }
      if (!spec.length) return { err: "Précise le port" + (withAct ? " (ou `tout`)" : "") + " : `" + (withAct ? "regle autoriser" : "tester") + " " + pr + " 443 de internet vers dmz`." };
      if (spec.length > 1) return { err: "Je ne comprends pas « " + spec.slice(1).join(" ") + " » dans la description du port." };
      if (/^\d+$/.test(spec[0])) {
        const n = +spec[0];
        if (n < 1 || n > 65535) return { err: "Un numéro de port va de 1 à 65535." };
        o.port = n;
      } else if (ALL.includes(spec[0])) {
        if (!withAct) return { err: "Le banc d'essai envoie un paquet précis : donne un numéro de port (ex. `tester tcp 22 de internet vers interne`)." };
      } else return { err: "Port invalide : « " + spec[0] + " ». Un numéro (443) ou `tout`." };
    } else if (spec.length && !(spec.length === 1 && ALL.includes(spec[0]) && pr === "tout")) {
      return { err: pr === "icmp" ? "icmp n'a pas de numéro de port (c'est le ping et ses messages d'erreur)." : "Un numéro de port suppose `tcp` ou `udp` ; avec `tout`, écris directement « de ‹zone› vers ‹zone› »." };
    }
    if (rest.length < 3 || !["vers", "a", "au", "aux", "dans", "sur"].includes(rest[1])) return { err: "Il manque « vers ‹zone› » après la zone d'origine : `de internet vers dmz`." };
    const src = ZMAP[rest[0]], dst = ZMAP[rest[2]];
    if (!src) return { err: "Zone inconnue : « " + rest[0] + " ». Les zones sont `internet`, `dmz` et `interne`" + (withAct ? " (ou `tout`)." : ".") };
    if (!dst) return { err: "Zone inconnue : « " + rest[2] + " ». Les zones sont `internet`, `dmz` et `interne`" + (withAct ? " (ou `tout`)." : ".") };
    if (src === "pare-feu") return { err: "Le pare-feu lui-même n'est pas une zone d'origine ici." };
    if (!withAct && (src === "tout" || dst === "tout")) return { err: "Le banc d'essai envoie un paquet précis : choisis `internet`, `dmz` ou `interne`." };
    if (src === dst && src !== "tout") return { err: "Origine et destination dans la même zone : ce trafic ne traverse pas le pare-feu, il n'est donc pas filtré." };
    o.src = src; o.dst = dst;
    return o;
  }

  /* ---------- moteur de filtrage ---------- */
  const rtxt = r => `${r.act} ${r.proto}${r.port !== null ? " " + (r.pm === "sport" ? "port-source " : "") + r.port : (r.proto === "tcp" || r.proto === "udp" ? " tout" : "")} ${r.src}→${r.dst}`;
  const pk = (a, b, pr, po) => ({ proto: pr, sport: pr === "icmp" ? null : EPH, dport: pr === "icmp" ? null : po, src: a, dst: b });
  const pdesc = p => p.proto === "icmp" ? `icmp ${p.src}→${p.dst}` : `${p.proto} ${p.sport}→${p.dport} ${p.src}→${p.dst}`;
  function ruleMatch(r, p) {
    if (r.proto !== "tout" && r.proto !== p.proto) return false;
    if (r.port !== null && (r.pm === "sport" ? p.sport : p.dport) !== r.port) return false;
    if (r.src !== "tout" && r.src !== p.src) return false;
    if (r.dst !== "tout" && r.dst !== p.dst) return false;
    return true;
  }
  const covers = (e, r) => (e.proto === "tout" || e.proto === r.proto) && (e.port === null || (r.port !== null && e.port === r.port && e.pm === r.pm)) && (e.src === "tout" || e.src === r.src) && (e.dst === "tout" || e.dst === r.dst);
  function evalPkt(p) {
    const x = F();
    for (let i = 0; i < x.rules.length; i++) if (ruleMatch(x.rules[i], p)) {
      const later = [];
      for (let j = i + 1; j < x.rules.length; j++) if (ruleMatch(x.rules[j], p) && x.rules[j].act !== x.rules[i].act) later.push(j + 1);
      return { act: x.rules[i].act, idx: i + 1, later };
    }
    return { act: x.policy, idx: 0, later: [] };
  }
  function verdict(res) {
    const who = res.idx ? `règle ${res.idx} : ${rtxt(F().rules[res.idx - 1])}` : `politique par défaut : ${F().policy}`;
    const w = res.act === "autoriser" ? "AUTORISÉ" : res.act === "refuser" ? "ABANDONNÉ (silence)" : "REJETÉ (« interdit »)";
    return `${w}  [${who}]`;
  }
  const samplePkt = r => {
    const proto = r.proto === "tout" ? "tcp" : r.proto;
    let src = r.src === "tout" ? "internet" : r.src, dst = r.dst === "tout" ? "dmz" : r.dst;
    if (src === dst) src = "internet";
    const p = pk(src, dst, proto, r.pm === "dport" && r.port ? r.port : 443);
    if (r.pm === "sport" && r.port && proto !== "icmp") { p.sport = r.port; p.dport = EPH; }
    return p;
  };

  /* Simule une connexion complète : NAT entrant, filtre aller, réponse, filtre retour, NAT sortant. */
  function connect(A, Breq, proto, port, rec, srcIp) {
    const x = F(), L = [], r = { log: L, ok: false, why: "", state: "", pkt: null, noredirect: false, fwd: null };
    const sip = srcIp || ZIP[A];
    let host = null, B = Breq;
    const pn = proto === "icmp" ? "icmp" : `${proto}/${port}`;
    if (A === "internet") {
      const red = proto === "icmp" ? null : x.nat.find(n => n.proto === proto && n.port === port);
      if (red) {
        host = red.host; B = HOSTS[host].zone;
        const t = `${sip}:${EPH} → ${PUB}:${port}  ⇒  ${HOSTS[host].ip}:${port} (${host})`;
        L.push(`NAT entrant : ${PUB}:${port} → ${HOSTS[host].ip}:${port} (${host})`);
        if (rec) x.xlat = [proto + " " + t, ...(x.xlat || []).filter(s => s !== proto + " " + t)].slice(0, 5);
        if (Breq && B !== Breq) { r.noredirect = true; L.push(`  (tu visais ${Breq}, mais cette redirection mène en ${B})`); }
      } else {
        B = "pare-feu"; r.noredirect = true;
        L.push(proto === "icmp" ? `NAT entrant : un ping vise l'adresse publique ${PUB}, c'est-à-dire le pare-feu lui-même` : `NAT entrant : aucune redirection pour ${pn} : le paquet vise le pare-feu lui-même (${PUB})`);
      }
    }
    const fwd = pk(A, B, proto, port); r.pkt = fwd;
    const res = evalPkt(fwd); r.fwd = res;
    L.push(`Filtre (aller)  ${pdesc(fwd)} : ${verdict(res)}`);
    if (res.later.length) L.push(`  (la règle ${res.later[0]}, plus bas, dirait autre chose : elle n'est jamais lue pour ce paquet)`);
    if (res.act !== "autoriser") { r.why = "blocked-fwd"; r.state = res.act === "refuser" ? "filtered-drop" : "filtered-rej"; return r; }
    let listen;
    if (B === "pare-feu") listen = false;
    else if (A === "internet") listen = proto === "tcp" && HOSTS[host].ports.includes(port);
    else if (proto === "icmp" || B === "internet") listen = true;
    else listen = proto === "tcp" && Object.values(HOSTS).some(h => h.zone === B && h.ports.includes(port));
    if (B === "internet" && A !== "internet") {
      if (!x.masq[A]) {
        L.push(`NAT sortant : ${A} a des adresses privées (10.x) : sans masquerade, le paquet est jeté par le fournisseur d'accès`);
        r.why = "nomasq"; r.state = "lost"; return r;
      }
      const t = `${ZIP[A]}:${EPH} → ${PUB}:443  ⇒  ${PUB}:40001`;
      L.push(`NAT sortant : ${ZIP[A]}:${EPH} → ${PUB}:40001 (masquerade)`);
      if (rec) x.xlat = [proto + " " + t, ...(x.xlat || []).filter(s => s !== proto + " " + t)].slice(0, 5);
    }
    const what = proto === "icmp" ? "echo-reply" : listen ? (proto === "tcp" ? "SYN-ACK" : "réponse UDP") : (proto === "tcp" ? "RST (port fermé)" : "ICMP port inaccessible");
    const rp = proto === "icmp" || (proto === "udp" && !listen) ? { proto: "icmp", sport: null, dport: null, src: B, dst: A } : { proto, sport: port, dport: EPH, src: B, dst: A };
    if (x.stateful) L.push(`Suivi de connexion : la réponse (${what}) appartient à une connexion établie : AUTORISÉE d'office`);
    else {
      const rr = evalPkt(rp); r.ret = rr;
      L.push(`Filtre (retour) ${pdesc(rp)} : ${verdict(rr)}`);
      if (rr.act !== "autoriser") { r.why = "blocked-ret"; r.state = "filtered-ret"; r.pkt = rp; return r; }
    }
    if (r.noredirect) { r.why = listen ? "ok" : "closed"; r.state = "closed"; r.ok = false; return r; }
    if (listen) { r.ok = true; r.why = "ok"; r.state = "open"; } else { r.why = "closed"; r.state = "closed"; }
    r.host = host;
    return r;
  }

  /* Grille d'exposition : tout ce que le filtre laisse passer, par couple de zones. */
  function grid() {
    const x = F();
    const ports = new Set([21, 22, 23, 25, 80, 110, 443, 445, 3306, 3389, 4444, 8080]);
    const udp = new Set([53, 123]);
    x.rules.forEach(r => { if (r.port !== null) (r.proto === "udp" ? udp : ports).add(r.port); });
    const probes = [...[...ports].map(p => ["tcp", p]), ...[...udp].map(p => ["udp", p]), ["icmp", null]];
    const allowed = {}, extras = [], loud = [];
    for (const [a, b] of PAIRS) {
      const key = a + ">" + b; allowed[key] = [];
      for (const [pr, po] of probes) {
        const lab = pr === "icmp" ? "icmp" : pr + "/" + po;
        const res = evalPkt(pk(a, b, pr, po));
        if (res.act === "autoriser") { allowed[key].push(lab); if (!LEGIT.has(key + ">" + lab)) extras.push({ key, lab, idx: res.idx }); }
        else if (a === "internet" && res.act === "rejeter") loud.push({ key, lab, idx: res.idx });
      }
    }
    return { allowed, extras, loud };
  }
  const openTo = (a, b, pr, list) => list.filter(p => evalPkt(pk(a, b, pr, p)).act === "autoriser");
  const natOK = () => { const n = F().nat; return n.length === 2 && n.some(e => e.port === 443 && e.host === "web" && e.proto === "tcp") && n.some(e => e.port === 25 && e.host === "courrier" && e.proto === "tcp"); };
  const natExtra = () => F().nat.filter(n => !((n.port === 443 && n.host === "web") || (n.port === 25 && n.host === "courrier")));

  function needs() {
    return {
      web: connect("internet", "dmz", "tcp", 443), courrier: connect("internet", "dmz", "tcp", 25),
      admin: connect("interne", "dmz", "tcp", 22), nav: connect("interne", "internet", "tcp", 443),
    };
  }
  const NEED = [
    ["web", "internet", "dmz", "tcp", 443, "Bob consulte le site (tcp 443 Internet → DMZ)"],
    ["courrier", "internet", "dmz", "tcp", 25, "Le courrier entre (tcp 25 Internet → DMZ)"],
    ["admin", "interne", "dmz", "tcp", 22, "Alice administre la DMZ (tcp 22 interne → DMZ)"],
    ["nav", "interne", "internet", "tcp", 443, "Les postes naviguent en HTTPS (tcp 443 interne → Internet)"],
  ];
  /* première étape non satisfaite d'un besoin : null si tout va bien */
  function needGap(n) {
    const [k, a, b, pr, po] = n;
    if (evalPkt(pk(a, b, pr, po)).act !== "autoriser") return k;
    const R = connect(a, b, pr, po);
    if (R.ok) return null;
    if (R.noredirect) return "nat" + k;
    if (R.why === "nomasq") return "masq";
    if (R.why === "blocked-ret") return "state";
    return a === "internet" ? "nat" + k : k;
  }

  function audit() {
    const x = F(), g = grid(), cs = [];
    const add = (ok, txt, fix) => cs.push({ ok, txt, fix });
    add(x.policy === "refuser", "Politique par défaut : tout refuser, en silence", x.policy === "autoriser" ? "la politique est « autoriser » : `politique refuser`" : "la politique « rejeter » répond à Mallory : `politique refuser` (abandon silencieux)");
    add(!!x.stateful, "Suivi des connexions activé (pas de règle de retour à maintenir)", "`suivi activer`");
    NEED.forEach(n => {
      const gap = needGap(n);
      const fix = { web: "`regle autoriser tcp 443 de internet vers dmz`", courrier: "règle `autoriser tcp 25 de internet vers dmz` et `nat rediriger tcp 25 vers courrier`", admin: "`regle autoriser tcp 22 de interne vers dmz`", nav: "`regle autoriser tcp 443 de interne vers internet`" }[n[0]];
      add(!gap, n[5], gap === "state" ? "la réponse est bloquée : `suivi activer`" : gap === "masq" ? "`nat masquerade interne` (au comptoir des traductions)" : (gap || "").startsWith("nat") ? "il manque la redirection NAT (comptoir des traductions)" : fix);
    });
    const ex = g.extras;
    add(!ex.length, "Rien d'autre n'est autorisé (aucun flux superflu)", ex.length ? `${ex[0].lab} ${ex[0].key.replace(">", " → ")} passe${ex[0].idx ? " (règle " + ex[0].idx + ")" : " (politique par défaut)"} : resserre (${ex.length} flux en trop)` : "");
    const piv = openTo("dmz", "interne", "tcp", [22, 445, 3306, 3389]);
    add(!piv.length, "Le serveur web compromis ne peut pas rebondir vers l'interne (segmentation)", "tcp/" + piv.join(", ") + " passe de la DMZ vers l'interne : retire la règle trop large");
    const eg = [...openTo("dmz", "internet", "tcp", [4444, 443]), ...openTo("interne", "internet", "tcp", [4444])];
    add(!eg.length, "Aucun appel sortant vers Mallory (tcp 4444, ou 443 depuis la DMZ)", "une sortie reste ouverte (tcp " + eg.join(", ") + ") : filtre ce qui sort aussi");
    add(!g.loud.length, "Face à Internet, les paquets refusés sont abandonnés sans réponse", "une règle `rejeter` répond à Mallory : utilise `refuser` côté Internet");
    add(natOK(), "NAT minimal : seulement 443 → web et 25 → courrier", "`nat` pour voir la table ; retire les redirections superflues avec `nat supprimer ‹port›`");
    return cs;
  }

  /* ---------- entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle a obtenu un audit autorisé de la muraille de Port-443. Tout est simulé, rien ne sort de la cité." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", vis: () => true, desc: () => "Mallory, capuche baissée, un carnet de ports sous le bras. Dans cet audit autorisé, elle joue l'attaquante : `balayer`, `exploiter web`, `pivoter`, `rappeler`." },
    greffier: { npc: true, names: ["greffier", "clerc"], label: "le Greffier des règles", desc: () => "Le Greffier, qui range les règles de la muraille dans un registre et ne tolère pas l'à-peu-près." },
    registre: { names: ["registre", "liste", "livre"], label: "le registre des règles", desc: () => "Le registre où sont inscrites les règles dans l'ordre : c'est ce que la commande `regles` affiche. La première règle qui correspond à un paquet décide ; si aucune ne correspond, la politique par défaut s'applique." },
    banc: { names: ["banc", "banc d essai", "essai"], label: "le banc d'essai", desc: () => "Le banc d'essai envoie de faux paquets à travers la muraille et affiche chaque décision : `tester tcp 443 de internet vers dmz`. Il joue aussi la réponse du serveur, pour que tu voies si elle repasse." },
    tablenat: { names: ["table", "table nat", "traductions", "comptoir"], label: "la table des traductions", desc: () => "La table de traduction d'adresses : `nat` l'affiche. Ève, qui écoute la ligne côté Internet, n'en voit que l'adresse publique " + PUB + "." },
    web: { names: ["serveur web", "web", "site"], label: "le serveur web", desc: () => "Le serveur web de la cité (10.0.2.10) : le site public que Bob consulte. Il écoute sur les ports 22 (ssh), 80, 443 et 8080 (une console d'administration oubliée). Beaucoup de visiteurs, donc beaucoup de risques : c'est lui que Mallory visera." },
    courrier: { names: ["serveur de courrier", "courrier", "mail", "smtp"], label: "le serveur de courrier", desc: () => "Le serveur de courrier (10.0.2.20). Il reçoit les messages d'autres serveurs sur le port 25 (SMTP). Il est lui aussi exposé : il est donc dans la DMZ." },
    comptes: { names: ["serveur des comptes", "comptes", "base"], label: "le serveur des comptes", desc: () => "Le serveur des comptes (10.0.3.5) : la base des habitants (mysql, port 3306) et un accès ssh (22) pour les administrateurs. Il ne doit jamais être joignable d'en dehors." },
    sauvegardes: { names: ["sauvegardes", "coffre", "sauvegarde"], label: "le coffre des sauvegardes", desc: () => "Les sauvegardes de la cité (10.0.3.6), partagées en SMB (port 445). Si Mallory les atteint, elle chiffre ou vole tout." },
    poste: { names: ["poste", "poste d alice", "alice"], label: "le poste d'Alice", desc: () => "Le poste d'Alice (10.0.3.25), qui administre les serveurs et surfe sur le web. Le bureau à distance (RDP, port 3389) est activé : un ancien réglage pour le télétravail." },
  };

  const rooms = {
    place: { name: "La place du Rempart", short: "Place", alias: ["place", "rempart"], ents: ["ada"], exits: { nord: "controle", est: "porte", sud: "dmz", ouest: "interne" },
      desc: () => "Au centre de Port-443, la place d'où l'on voit toute la muraille. À l'est, la porte d'Internet, où arrivent voyageurs et curieux. Au sud, la DMZ : le quartier public, avec le serveur web et celui du courrier. À l'ouest, le réseau interne : comptes, sauvegardes, postes. Au nord, la salle des règles où siège le pare-feu." },
    controle: { name: "La salle des règles", short: "Salle des règles", alias: ["controle", "regles", "salle", "salle des regles"], ents: ["greffier", "registre", "banc"], exits: { sud: "place", est: "passerelle" },
      desc: () => "Une salle de pupitres où chaque paquet est jugé. Le registre des règles est ouvert sur le pupitre central ; à côté, le banc d'essai. À l'est, le comptoir des traductions." },
    passerelle: { name: "Le comptoir des traductions", short: "Comptoir NAT", alias: ["passerelle", "comptoir", "nat", "traductions"], ents: ["tablenat"], exits: { ouest: "controle" },
      desc: () => "Un comptoir où des clercs réécrivent les adresses des paquets qui entrent et sortent. Au mur, la table des traductions. C'est ici que se règle le NAT." },
    porte: { name: "La porte d'Internet", short: "Porte d'Internet", alias: ["porte", "internet"], ents: ["mallory"], exits: { ouest: "place" },
      desc: () => "La grande porte vers l'extérieur. Mallory s'y tient, du côté d'Internet, carnet en main : pour cet audit, c'est elle qui sonde la muraille. Tout ce qu'elle fait ici est simulé et autorisé." },
    dmz: { name: "La DMZ", short: "DMZ", alias: ["dmz"], ents: ["web", "courrier"], exits: { nord: "place" },
      desc: () => "Le quartier public, entre la porte et le réseau interne : ici vivent les services que tout le monde peut interroger. Le serveur web et le serveur de courrier y sont installés." },
    interne: { name: "Le réseau interne", short: "Interne", alias: ["interne", "reseau"], ents: ["comptes", "sauvegardes", "poste"], exits: { est: "place" },
      desc: () => "Le cœur de la cité : le serveur des comptes, le coffre des sauvegardes, et le poste d'Alice. Personne de l'extérieur n'a de raison d'y entrer." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.scan0) return "scan0";
    if (!x.test0) return "test0";
    if (x.policy === "autoriser") return "policy";
    if (x.rules.some(r => r.legacy)) return "legacy";
    for (const n of NEED) { const g = needGap(n); if (g) return g; }
    if (natExtra().length) return "natclean";
    if (!x.scan2) return "scan2";
    if (!x.exploited) return "exploit";
    if (!x.pivotBlk) return "pivot";
    if (!x.egressBlk) return "egress";
    if (!x.audit) return "audit";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend sur la place du Rempart.", "`parler ada`"],
    scan0: () => ["Avant de réparer, regarde la muraille comme Mallory. Elle est à la porte d'Internet (à l'est de la place).", "`aller est`, puis `balayer`."],
    test0: () => ["Retourne à la salle des règles (au nord de la place) et envoie un paquet de test : Mallory peut-elle atteindre le réseau interne ?", "`aller ouest`, `aller nord`, puis `tester tcp 3389 de internet vers interne` (le bureau à distance du poste d'Alice). `regles` affiche la liste."],
    policy: () => ["La politique par défaut est « autoriser » : on ne bloque que ce qu'on pense à interdire. Inverse : tout refuser sauf le nécessaire.", "`politique refuser` (à la salle des règles)."],
    legacy: () => ["Rien n'a changé pour Mallory : une règle héritée décide avant la politique. Regarde la liste, dans l'ordre.", "`regles`, puis `supprimer regle 1` (la règle « autoriser tout » de la migration)."],
    web: () => ["Tout est fermé : rouvre uniquement ce dont Bob a besoin, c'est-à-dire l'accès HTTPS au serveur web de la DMZ.", "`regle autoriser tcp 443 de internet vers dmz`, puis `tester tcp 443 de internet vers dmz`."],
    state: () => ["Le test montre que la requête passe mais que la réponse du serveur est jugée comme un nouveau paquet et jetée. Fais en sorte que le pare-feu suive les connexions.", "`suivi activer`, puis refais le test."],
    natweb: () => ["La règle est là, mais le port 443 n'est redirigé vers aucune machine : regarde la table des traductions (comptoir, à l'est de la salle des règles).", "`nat rediriger tcp 443 vers web`"],
    courrier: () => ["Le courrier doit entrer par le port 25 (SMTP), vers la DMZ.", "`regle autoriser tcp 25 de internet vers dmz`, puis `tester tcp 25 de internet vers dmz`."],
    natcourrier: () => ["Le filtre laisse passer le courrier, mais personne ne reçoit le port 25 : il manque une redirection NAT. Va au comptoir des traductions (est de la salle des règles).", "`aller est`, `nat rediriger tcp 25 vers courrier`."],
    admin: () => ["Alice administre les serveurs de la DMZ en SSH depuis le réseau interne : l'interne a le droit de parler à la DMZ, pas l'inverse.", "`regle autoriser tcp 22 de interne vers dmz`, puis `tester tcp 22 de interne vers dmz`."],
    nav: () => ["Les postes internes doivent pouvoir naviguer en HTTPS : c'est un flux SORTANT, de l'interne vers Internet.", "`regle autoriser tcp 443 de interne vers internet`, puis `tester tcp 443 de interne vers internet`."],
    masq: () => ["Les postes ont des adresses privées : sans traduction de l'adresse source, leurs paquets ne reviennent jamais. Va au comptoir des traductions.", "`aller est` (depuis la salle des règles), `nat masquerade interne`."],
    natclean: () => ["Le comptoir garde des redirections oubliées (ssh, http, 8080, et même le bureau à distance du poste d'Alice). Même si le filtre les bloque aujourd'hui, ce sont des portes prêtes à s'ouvrir : retire celles qui ne servent plus. Il ne doit rester que 443 → web et 25 → courrier.", "Au comptoir : `nat`, puis `nat supprimer 3389`, `nat supprimer 22`, `nat supprimer 80`, `nat supprimer 8080`."],
    scan2: () => ["Mallory refait un balayage : que voit-elle maintenant ? Rends-toi à la porte d'Internet (à l'est de la place).", "`balayer` à la porte d'Internet."],
    exploit: () => ["Le balayage ne montre que 443 et 25. Mais le port 443 est ouvert à tous : si l'application web a une faille, que se passe-t-il ? Mallory va le simuler.", "À la porte d'Internet : `exploiter web`."],
    pivot: () => {
      const op = openTo("dmz", "interne", "tcp", [22, 445, 3306, 3389]);
      return op.length ? ["Il reste un chemin de la DMZ vers l'interne : regarde ta liste de règles et resserre ce qui laisse passer la DMZ.", "`regles`, puis supprime ou corrige la règle qui autorise tcp " + op.join(", ") + " de dmz vers interne (`supprimer regle ‹n›`), puis relance `pivoter`."]
        : ["Le serveur web est compromis. Mallory essaie de rebondir vers l'interne : où est ta segmentation ?", "À la porte d'Internet : `pivoter`."];
    },
    egress: () => {
      const eg = [...openTo("dmz", "internet", "tcp", [4444, 443]), ...openTo("interne", "internet", "tcp", [4444])];
      return eg.length ? ["Une machine compromise peut encore appeler Mallory : regarde ce qui sort de la DMZ et de l'interne.", "`regles` : seul `autoriser tcp 443 de interne vers internet` doit permettre une sortie. Corrige, puis `rappeler`."]
        : ["Dernière étape de Mallory : faire appeler son serveur depuis les machines compromises.", "À la porte d'Internet : `rappeler`."];
    },
    audit: () => {
      const bad = audit().find(c => !c.ok);
      return bad ? ["L'audit final a encore un point à corriger : « " + bad.txt + " ».", bad.fix] : ["Tout est en place : demande l'audit final à la salle des règles.", "`auditer` (à la salle des règles)."];
    },
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
          say("Maître Ada", "Bienvenue à Port-443. La cité a trois zones : Internet, dehors ; la DMZ, le quartier public avec le serveur web et celui du courrier ; et le réseau interne, avec les comptes, les sauvegardes et les postes. Entre les trois, la muraille : un pare-feu, qui juge chaque paquet d'après des règles. Tout ceci est un audit autorisé, et tout est simulé.");
          say("Maître Ada", "Aujourd'hui, la muraille est grande ouverte : une règle de « migration » laisse tout passer. Voici ce qui est LÉGITIME, et rien d'autre : Bob consulte le site en HTTPS ; le courrier entre par le port 25 ; Alice administre la DMZ en SSH depuis l'interne ; les postes naviguent en HTTPS. Le reste doit être bloqué, y compris si le serveur web tombe : il ne doit pas pouvoir rebondir vers l'interne, ni appeler Mallory.");
          say("Maître Ada", "Commence par regarder la muraille avec les yeux de Mallory, à la porte d'Internet (à l'est). Puis la salle des règles, au nord, pour la réécrire. Quand tu penses avoir fini, `auditer` vérifiera tout automatiquement.");
          note("filtrage"); out("Va voir Mallory : `aller est`, puis `balayer`.", "sys");
        } else if (objective() === "end") ending();
        else if (x.end) say("Maître Ada", "La muraille tient. Merci !");
        else say("Maître Ada", "Ce n'est pas fini. `indice` si tu bloques.");
        break;
      case "greffier":
        say("Greffier", "Je n'inscris qu'une règle à la fois : `regle autoriser tcp 443 de internet vers dmz`. Les actions sont `autoriser`, `refuser` (abandon silencieux) et `rejeter` (refus annoncé). La première règle qui correspond l'emporte, de haut en bas. `regle 2 ...` insère en position 2, `supprimer regle ‹n›` retire, `deplacer regle ‹n› ‹m›` change l'ordre, `politique ...` fixe ce qui se passe quand aucune règle ne correspond. `suivi activer` active le suivi des connexions.");
        break;
      case "mallory":
        if (!x.scan0) say("Mallory", "Alors, c'est toi, l'auditeur·rice ? Je balaie les ports de la cité quand tu veux : `balayer`. Je te dirai ce que je vois d'ici.");
        else say("Mallory", "Mes tours : `balayer` (je sonde les ports de l'adresse publique, comme nmap), `exploiter web` (je tente une faille de l'application web), `pivoter` (je rebondis du serveur web vers l'interne), `rappeler` (les machines compromises m'appellent). Tout est simulé, et tout se joue sur ta muraille.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes : règles ---------- */
  const needRoom = (room, msg) => { if (S.room !== room) { out(msg, "sys"); return true; } return false; };
  const touch = () => { F().audit = false; };
  function listRules(withHelp) {
    const x = F();
    const L = [`POLITIQUE PAR DÉFAUT : ${x.policy}      SUIVI DES CONNEXIONS : ${x.stateful ? "oui" : "non"}`, ""];
    if (!x.rules.length) L.push("(aucune règle)");
    x.rules.forEach((r, i) => {
      const sh = x.rules.findIndex((e, j) => j < i && covers(e, r));
      L.push(`${String(i + 1).padStart(2)}. ${rtxt(r)}${r.legacy ? "   ← héritée de la migration" : ""}${sh >= 0 ? `   (masquée par la règle ${sh + 1})` : ""}`);
    });
    L.push(`${String(x.rules.length + 1).padStart(2)}. (sinon) ${x.policy}`);
    out("Le registre des règles, de haut en bas :", "sys"); code(L.join("\n"));
    if (withHelp) out("Syntaxe : `regle ‹autoriser|refuser|rejeter› ‹tcp|udp|icmp|tout› ‹port|tout› de ‹zone› vers ‹zone›`. Zones : internet, dmz, interne, tout.", "sys");
  }
  function ruleCmd(c) {
    if (needRoom("controle", "Les règles se gèrent à la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), tk = toks(c.rawArg);
    if (!tk.length) { listRules(true); return; }
    const p = parseFlow(tk, true);
    if (p.err) { out(p.err, "err"); return; }
    const rule = { act: p.act, proto: p.proto, port: p.port, pm: p.pm, src: p.src, dst: p.dst };
    const pos = p.pos === undefined ? x.rules.length + 1 : p.pos;
    if (pos < 1 || pos > x.rules.length + 1) { out(`Position invalide : il y a ${x.rules.length} règle(s), choisis entre 1 et ${x.rules.length + 1}.`, "err"); return; }
    const cover = x.rules.slice(0, pos - 1).findIndex(e => covers(e, rule));
    const hides = x.rules.slice(pos - 1).findIndex(e => covers(rule, e));
    x.rules.splice(pos - 1, 0, rule); touch();
    out(`Règle ${pos} ajoutée : ${rtxt(rule)}`, "ok");
    if (cover >= 0) {
      out(`⚠ Cette règle ne sera jamais atteinte : la règle ${cover + 1} (${rtxt(x.rules[cover])}) correspond avant elle à tous les paquets qu'elle viserait. Le pare-feu s'arrête à la PREMIÈRE règle qui correspond. Déplace ta règle plus haut (\`deplacer regle ${pos} 1\`) ou retire la règle qui la masque.`, "err");
      note("ordre"); if (!x.shownOrdre) { x.shownOrdre = true; fig("ordre", samplePkt(rule)); }
    } else if (hides >= 0) {
      out(`Attention : cette règle masque désormais la règle ${pos + hides + 1} (${rtxt(x.rules[pos + hides])}), placée plus bas : elle ne sera plus jamais lue.`, "sys");
    }
    if (rule.act === "autoriser" && rule.proto === "tout" && rule.port === null && rule.src === "tout" && rule.dst === "tout") out("Une règle « autoriser tout » est une porte grande ouverte : c'est exactement ce que cet audit cherche à supprimer.", "sys");
  }
  function removeCmd(c) {
    if (needRoom("controle", "Les règles se retirent à la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), tk = toks(c.rawArg).filter(t => t !== "regle" && t !== "regles");
    if (tk[0] === "tout" || tk[0] === "toutes") { x.rules = []; touch(); out("Toutes les règles sont retirées. Il ne reste que la politique par défaut.", "ok"); return; }
    if (!/^\d+$/.test(tk[0] || "")) { out("Quelle règle ? `supprimer regle ‹numéro›` (le numéro figure dans `regles`).", "err"); return; }
    const n = +tk[0];
    if (n < 1 || n > x.rules.length) { out(`Il n'y a pas de règle ${n} (il y en a ${x.rules.length}).`, "err"); return; }
    const [r] = x.rules.splice(n - 1, 1); touch();
    out(`Règle retirée : ${rtxt(r)}`, "ok");
    if (r.legacy) {
      out("La règle héritée « autoriser tout » est partie : les règles suivantes et la politique par défaut décident enfin. Elle était en tête : tant qu'elle était là, rien de ce qui la suivait n'était lu.", "ok");
      note("ordre"); if (!x.shownOrdre) { x.shownOrdre = true; fig("ordre", x.last || undefined); }
    }
  }
  function moveCmd(c) {
    if (needRoom("controle", "Les règles se déplacent à la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), tk = toks(c.rawArg).filter(t => t !== "regle" && t !== "regles" && t !== "a" && t !== "vers" && t !== "en");
    if (tk.length < 2 || !/^\d+$/.test(tk[0]) || !/^\d+$/.test(tk[1])) { out("`deplacer regle ‹de› ‹vers›` : par exemple `deplacer regle 3 1` met la règle 3 en tête.", "err"); return; }
    const a = +tk[0], b = +tk[1], n = x.rules.length;
    if (a < 1 || a > n || b < 1 || b > n) { out(`Les positions vont de 1 à ${n}.`, "err"); return; }
    const [r] = x.rules.splice(a - 1, 1); x.rules.splice(b - 1, 0, r); touch();
    out(`La règle « ${rtxt(r)} » passe en position ${b}.`, "ok");
    note("ordre"); listRules(false);
  }
  function policyCmd(c) {
    if (needRoom("controle", "La politique par défaut se règle à la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), a = ACT[toks(c.rawArg)[0]];
    if (!a) { out(`Politique par défaut actuelle : ${x.policy}. Pour la changer : \`politique autoriser\`, \`politique refuser\` (abandon silencieux) ou \`politique rejeter\`.`, "sys"); return; }
    x.policy = a; touch();
    if (a === "autoriser") out("Politique par défaut : AUTORISER. Tout paquet qui ne correspond à aucune règle passe : c'est une liste noire, qu'il faut compléter à chaque nouvelle menace.", "err");
    else {
      out(`Politique par défaut : ${a === "refuser" ? "REFUSER (abandon silencieux)" : "REJETER (l'expéditeur reçoit un message « interdit »)"}. Tout paquet qui ne correspond à aucune règle est bloqué : c'est le « default deny ». Il faudra désormais autoriser explicitement chaque flux utile.`, "ok");
      note("defaut");
      if (x.rules.some(r => r.legacy)) out("Mais attention : la règle 1 « autoriser tout » est lue AVANT la politique. Elle laisse encore tout passer. Teste : `tester tcp 3389 de internet vers interne`.", "sys");
    }
  }
  function stateCmd(c) {
    if (needRoom("controle", "Le suivi des connexions se règle à la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), t = toks(c.rawArg)[0] || "";
    if (/^(activer|oui|on|actif|avec)/.test(t)) {
      if (x.stateful) { out("Le suivi des connexions est déjà actif.", "sys"); return; }
      x.stateful = true; touch();
      out("Suivi des connexions ACTIVÉ : le pare-feu mémorise chaque connexion autorisée et accepte automatiquement les réponses qui lui appartiennent. Teste à nouveau : `tester tcp 443 de internet vers dmz`.", "ok");
      note("etat"); fig("etat", true);
    } else if (/^(desactiver|non|off|inactif|sans)/.test(t)) {
      if (!x.stateful) { out("Le suivi des connexions est déjà désactivé (filtre sans état).", "sys"); return; }
      x.stateful = false; touch();
      out("Suivi des connexions DÉSACTIVÉ : chaque paquet est maintenant jugé isolément, réponses comprises.", "sys");
    } else out(`Suivi des connexions : ${x.stateful ? "activé (avec état)" : "désactivé (sans état)"}. \`suivi activer\` ou \`suivi desactiver\`.`, "sys");
  }
  function testCmd(c) {
    if (needRoom("controle", "Le banc d'essai est dans la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), p = parseFlow(toks(c.rawArg), false);
    if (p.err) { out(p.err, "err"); return; }
    const r = connect(p.src, p.dst, p.proto, p.port, true);
    x.last = r.pkt; x.test0 = true;
    out(`Banc d'essai : ${p.proto}${p.port ? "/" + p.port : ""} de ${p.src} vers ${p.dst}`, "sys");
    code(r.log.map((l, i) => l).join("\n"));
    const act = r.fwd && r.fwd.act;
    if (r.ok) out("Résultat : la connexion ABOUTIT (aller autorisé, service présent, réponse revenue).", "ok");
    else if (r.why === "blocked-fwd") out(act === "refuser" ? "Résultat : le paquet est ABANDONNÉ en silence. L'expéditeur attend, sans savoir s'il y a quelqu'un." : "Résultat : le paquet est REJETÉ : l'expéditeur reçoit tout de suite « interdit » (il sait qu'un pare-feu filtre).", "err");
    else if (r.why === "blocked-ret") {
      out("Résultat : la requête passe et le serveur répond, mais la RÉPONSE est bloquée à son tour (filtre sans état : le retour est un paquet comme un autre). Côté client, la connexion n'aboutit jamais.", "err");
      out("Deux solutions : une règle de retour par service (lourde, et elle laisse aussi passer des paquets non sollicités), ou le suivi des connexions : `suivi activer`.", "sys");
      if (!x.sawRet) { x.sawRet = true; fig("etat", false); }
    } else if (r.why === "nomasq") out("Résultat : la connexion échoue : l'adresse privée de la source n'est pas traduite. Il faut un NAT sortant (`nat masquerade interne`, au comptoir des traductions).", "err");
    else if (r.noredirect) out(p.proto === "icmp" ? "Résultat : un ping vise l'adresse publique, donc le pare-feu lui-même : aucune machine de " + p.dst + " ne le reçoit." : r.pkt.dst === "pare-feu" ? "Résultat : la connexion n'atteint pas " + p.dst + " : aucune redirection NAT ne mène du port " + p.port + " de l'adresse publique vers cette zone. Le filtre n'y peut rien : c'est au comptoir des traductions qu'il faut la créer (`nat rediriger ...`)." : "Résultat : le port " + p.port + " de l'adresse publique est redirigé vers la zone " + r.pkt.dst + ", pas vers " + p.dst + " : la connexion n'atteint pas la destination visée.", "err");
    else out("Résultat : le filtre laisse passer, mais la machine répond « fermé » : aucun service n'écoute sur ce port.", "sys");
    if (r.fwd && r.fwd.later.length) { note("ordre"); if (!x.shownOrdre) { x.shownOrdre = true; fig("ordre", r.pkt); } }
    if (p.src === "internet" && r.pkt && r.pkt.dst === "interne" && r.fwd && r.fwd.act === "autoriser") out("Le réseau interne est exposé à Internet : ce n'est jamais voulu.", "err");
    if (!x.shownTopo) { x.shownTopo = true; note("filtrage"); fig("topo"); }
    else if (r.fwd && r.fwd.idx === 1 && x.rules[0] && x.rules[0].legacy) out("C'est la règle 1 (héritée) qui décide : tout ce qui est écrit plus bas n'est même pas lu. `regles` pour la voir.", "sys");
  }

  /* ---------- commandes : NAT ---------- */
  function natCmd(c) {
    if (needRoom("passerelle", "Le NAT se règle au comptoir des traductions (à l'est de la salle des règles).")) return;
    const x = F(), tk = toks(c.rawArg), v = tk[0] || "";
    if (!v) { showNat(); return; }
    if (/^(rediriger|redirection|rediriger|ajouter|forward|dnat|transferer)/.test(v)) {
      const rest = tk.slice(1).filter(t => !["le", "la", "les", "l", "port"].includes(t));
      const pr = PROTO[rest[0]], po = /^\d+$/.test(rest[1] || "") ? +rest[1] : 0, h = rest[3] || rest[2] || "";
      if (!(pr === "tcp" || pr === "udp") || po < 1 || po > 65535 || !["vers", "sur", "a", "au", "dans"].includes(rest[2] || "")) { out("`nat rediriger tcp 25 vers courrier` : protocole, port de l'adresse publique, puis la machine (" + Object.keys(HOSTS).join(", ") + ").", "err"); return; }
      const host = Object.keys(HOSTS).find(k => k === h);
      if (!host) { out(`Machine inconnue : « ${h} ». Les machines sont : ${Object.keys(HOSTS).join(", ")}.`, "err"); return; }
      const old = x.nat.find(n => n.proto === pr && n.port === po);
      if (old) { out(`Le port ${pr}/${po} est déjà redirigé vers ${old.host}. Retire-le d'abord : \`nat supprimer ${po}\`.`, "err"); return; }
      x.nat.push({ proto: pr, port: po, host }); touch();
      out(`Redirection ajoutée : ${PUB}:${po} → ${HOSTS[host].ip}:${po} (${host}). Les paquets du port ${po} de l'adresse publique sont maintenant réécrits vers ${host}.`, "ok");
      out("Rappelle-toi : le NAT ne fait qu'ACHEMINER. Que le paquet ait le droit de passer, c'est le filtre qui en décide, après la traduction.", "sys");
      note("nat"); if (!x.shownNat) { x.shownNat = true; fig("nat"); }
    } else if (/^(supprimer|retirer|effacer|enlever)/.test(v)) {
      const po = /^\d+$/.test(tk[1] || "") ? +tk[1] : 0;
      const i = x.nat.findIndex(n => n.port === po);
      if (i < 0) { out("Quelle redirection ? `nat supprimer ‹port›` (voir `nat`).", "err"); return; }
      const [n] = x.nat.splice(i, 1); touch();
      out(`Redirection retirée : ${n.proto}/${n.port} → ${n.host}. Le port ${n.port} de l'adresse publique ne mène plus nulle part.`, "ok");
      if (n.host === "poste") out("Le bureau à distance du poste d'Alice n'est plus exposé : une porte oubliée de moins.", "ok");
      note("nat");
    } else if (/^(masquerade|masquer|snat|sortant)/.test(v)) {
      const z = ZMAP[tk[1] || ""], off = /^(non|off|desactiver|retirer)/.test(tk[2] || "");
      if (z !== "interne" && z !== "dmz") { out("`nat masquerade interne` (ou `dmz`) ; ajoute `non` pour le retirer.", "err"); return; }
      x.masq[z] = !off; touch();
      out(off ? `Masquerade retiré pour ${z} : ses paquets sortent avec une adresse privée et seront jetés par le fournisseur d'accès.` : `Masquerade activé pour ${z} : à la sortie, l'adresse source (10.x) est remplacée par l'adresse publique ${PUB}, avec un port distinct par connexion ; la réponse est ré-aiguillée grâce à la table.`, off ? "sys" : "ok");
      note("nat");
    } else out("Au comptoir : `nat` (la table), `nat rediriger tcp ‹port› vers ‹machine›`, `nat supprimer ‹port›`, `nat masquerade ‹interne|dmz›`.", "err");
  }
  function showNat() {
    const x = F();
    const L = [`NAT ENTRANT (redirections de ports), adresse publique ${PUB}`];
    if (!x.nat.length) L.push("  (aucune redirection)");
    x.nat.forEach((n, i) => L.push(`  ${i + 1}. ${n.proto}/${String(n.port).padEnd(5)} → ${HOSTS[n.host].ip}:${n.port}  ${n.host} (${HOSTS[n.host].zone})`));
    L.push("", "NAT SORTANT (masquerade)", `  interne : ${x.masq.interne ? "oui (10.0.3.0/24 → " + PUB + ")" : "non"}`, `  dmz     : ${x.masq.dmz ? "oui (10.0.2.0/24 → " + PUB + ")" : "non"}`);
    L.push("", "TRADUCTIONS RÉCENTES (connexions testées)");
    if (!(x.xlat || []).length) L.push("  (aucune pour l'instant : fais un `tester` à la salle des règles)");
    (x.xlat || []).forEach(s => L.push("  " + s));
    out("La table des traductions :", "sys"); code(L.join("\n"));
    note("nat"); if (!x.shownNat) { x.shownNat = true; fig("nat"); }
    if (natExtra().length) out("Des redirections datent d'un ancien réglage. Une redirection est une porte : chaque port redirigé est un service exposé de plus.", "sys");
  }

  /* ---------- commandes : Mallory ---------- */
  function scan() {
    if (needRoom("porte", "Mallory est à la porte d'Internet (à l'est de la place).")) return;
    const x = F(), rows = []; let t = 0; const open = []; let nC = 0, nF = 0, nRej = 0;
    out("Mallory lance un balayage de ports (SYN) sur l'adresse publique " + PUB + " :", "sys");
    for (const po of SCAN) {
      const r = connect("internet", null, "tcp", po, false, "192.0.2.66");
      let st, dl;
      if (r.state === "open") { st = "ouvert"; dl = 0.04; open.push(po); }
      else if (r.state === "closed") { st = "fermé"; dl = 0.04; nC++; }
      else if (r.state === "filtered-rej") { st = "filtré (rejet)"; dl = 0.04; nF++; nRej++; }
      else { st = "filtré"; dl = 1.5; nF++; }
      t += dl;
      rows.push(`${(po + "/tcp").padEnd(10)}${st.padEnd(16)}${(SERV[po] || "").padEnd(10)}${dl.toFixed(2).replace(".", ",")} s${r.state === "filtered-drop" || r.state === "filtered-ret" ? "  (délai dépassé)" : r.state === "filtered-rej" ? "  (ICMP « interdit »)" : ""}`);
    }
    code("PORT      ÉTAT            SERVICE   DURÉE\n" + rows.join("\n") + `\n\n${SCAN.length} ports sondés en ${t.toFixed(1).replace(".", ",")} s : ${open.length} ouvert(s), ${nC} fermé(s), ${nF} filtré(s).`);
    const bad = open.filter(p => ![25, 443].includes(p));
    x.scan0 = true;
    if (open.length === SCAN.length - nC - nF && nC + nF === 0) out("Tout répond. Mallory sait exactement ce qui tourne derrière la muraille.", "err");
    if (bad.length) out(`Mallory voit des services qui n'ont rien à faire sur Internet : ${bad.map(p => p + " (" + SERV[p] + ")").join(", ")}. Le 3389 (bureau à distance) mène même à un poste du réseau interne.`, "err");
    if (nC) out("FERMÉ = la machine répond « personne ici » : Mallory sait qu'il y a une machine derrière, et que seul le service manque.", "sys");
    if (nF) out(`FILTRÉ = rien d'utile ne revient : un pare-feu cache l'état du port. ${nRej ? "Un REJET renvoie immédiatement « interdit » (rapide)" : "Un ABANDON laisse le scanner patienter (ici 1,5 s par port, soit lent à grande échelle)"}.`, "sys");
    if (!x.shownPorts) { x.shownPorts = true; fig("ports"); }
    if (nF) note("ports");
    if (open.length === 2 && open.includes(25) && open.includes(443) && !nC) { x.scan2 = true; out("Il ne reste que 25 et 443 : exactement les deux services publics. Tout le reste est filtré, et Mallory ne distingue même pas un port « fermé » d'un port « bloqué ».", "ok"); }
    else if (x.scan0 && !bad.length && !x.scan2 && x.policy !== "autoriser" && !x.rules.some(r => r.legacy)) out("Ce balayage n'est pas encore celui d'une muraille minimale : les deux services publics sont 25 (courrier) et 443 (web). Reviens après avoir fini les règles et le NAT.", "sys");
  }
  function exploit(c) {
    if (needRoom("porte", "Mallory est à la porte d'Internet (à l'est de la place).")) return;
    const x = F();
    if (!/web|site|serveur/.test(norm(c.rawArg))) { out("`exploiter web` : Mallory tente une faille de l'application web.", "err"); return; }
    const r = connect("internet", "dmz", "tcp", 443, false, "192.0.2.66");
    out("Mallory envoie une requête HTTPS piégée au serveur web (une faille connue, jamais corrigée) :", "sys");
    code(r.log.join("\n"));
    if (!r.ok) { out("La requête n'arrive pas jusqu'au serveur web : c'est aussi le cas pour Bob ! Répare d'abord le flux légitime (indice).", "err"); return; }
    x.exploited = true;
    out("La requête traverse la muraille : le port 443 est légitime, le filtre ne voit qu'un paquet tcp/443 vers la DMZ, pas la faille cachée dedans. Le serveur web est COMPROMIS.", "err");
    out("Aucun pare-feu de ce type ne l'aurait empêché : la vraie parade ici est la mise à jour de l'application. La muraille doit maintenant LIMITER les dégâts : `pivoter` puis `rappeler` montreront jusqu'où Mallory va.", "sys");
    note("limites");
  }
  function pivot() {
    if (needRoom("porte", "Mallory est à la porte d'Internet (à l'est de la place).")) return;
    const x = F();
    if (!x.exploited) { say("Mallory", "Je n'ai pas encore de pied dans la DMZ : `exploiter web` d'abord."); return; }
    out("Depuis le serveur web compromis (DMZ), Mallory tente d'atteindre l'interne :", "sys");
    const L = []; let breach = 0, pass = 0;
    for (const po of [22, 445, 3306, 3389]) {
      const r = connect("dmz", "interne", "tcp", po);
      const h = Object.keys(HOSTS).find(k => HOSTS[k].zone === "interne" && HOSTS[k].ports.includes(po));
      const lab = `tcp/${String(po).padEnd(5)} dmz → interne (${h})`;
      if (r.ok) { breach++; L.push(`${lab} : CONNEXION ÉTABLIE !`); }
      else if (r.why === "blocked-fwd") L.push(`${lab} : bloqué (${r.fwd.idx ? "règle " + r.fwd.idx : "politique par défaut"}, ${r.fwd.act === "refuser" ? "silence" : "rejet"})`);
      else if (r.why === "blocked-ret") { pass++; L.push(`${lab} : l'aller passe, mais le retour est bloqué`); }
      else L.push(`${lab} : passe le filtre (rien n'écoute)`);
    }
    code(L.join("\n"));
    if (breach || pass) {
      x.pivotBlk = false;
      out("Mallory est dans le réseau interne : elle atteint " + (breach ? "les comptes, les sauvegardes ou le poste d'Alice. " : "le filtre, et ne s'arrête que grâce au retour bloqué. ") + "Mouvement latéral réussi : la DMZ ne devrait avoir AUCUN chemin vers l'interne. Resserre tes règles : `regles`.", "err");
    } else {
      x.pivotBlk = true;
      out("Tout est bloqué : le serveur web compromis est enfermé dans la DMZ. C'est la segmentation : même compromis, il ne voit pas les comptes ni les sauvegardes.", "ok");
      note("dmz"); fig("topo");
    }
  }
  function callBack() {
    if (needRoom("porte", "Mallory est à la porte d'Internet (à l'est de la place).")) return;
    const x = F();
    if (!x.exploited) { say("Mallory", "Aucune machine compromise ne m'appelle encore : `exploiter web` d'abord."); return; }
    out("Les machines compromises (le serveur web, et le poste d'Alice qui a ouvert une pièce jointe piégée) appellent le serveur de Mallory :", "sys");
    const L = []; let leak = 0, viaHttps = false;
    const tries = [["dmz", 4444, "le serveur web, port « shell inversé »"], ["dmz", 443, "le serveur web, déguisé en HTTPS"], ["interne", 4444, "le poste d'Alice, port « shell inversé »"], ["interne", 443, "le poste d'Alice, en HTTPS"]];
    for (const [a, po, who] of tries) {
      const r = connect(a, "internet", "tcp", po, false);
      const lab = `${a.padEnd(7)} → internet tcp/${String(po).padEnd(4)} ${who}`;
      if (r.ok) { if (po === 443 && a === "interne") { viaHttps = true; L.push(`${lab} : PASSE`); } else { leak++; L.push(`${lab} : PASSE`); } }
      else if (r.why === "nomasq") L.push(`${lab} : filtre ouvert, mais adresse privée non traduite`);
      else L.push(`${lab} : bloqué (${r.fwd && r.fwd.idx ? "règle " + r.fwd.idx : "politique par défaut"})`);
    }
    code(L.join("\n"));
    if (leak) { x.egressBlk = false; out("Une machine compromise parvient à joindre Mallory : elle peut recevoir ses ordres et sortir des données. Filtre aussi ce qui SORT (`regles`).", "err"); }
    else {
      x.egressBlk = true;
      out("Les appels de la DMZ et les ports inhabituels sont tous bloqués : sans canal de retour, la machine compromise est sourde et muette. C'est le filtrage sortant.", "ok");
      if (viaHttps) out("Reste un trou que tu ne peux pas boucher sans casser la navigation d'Alice : le HTTPS sortant de l'interne. Un logiciel malveillant s'y cache facilement (un proxy filtrant ou une inspection serait l'étape suivante : hors du périmètre d'un simple pare-feu de paquets).", "sys");
      note("egress");
    }
  }
  function auditCmd() {
    if (needRoom("controle", "L'audit se demande à la salle des règles (nord de la place du Rempart).")) return;
    const x = F(), cs = audit();
    out("Audit de la muraille : la politique est évaluée par le vrai moteur de filtrage.", "sys");
    code(cs.map(c => (c.ok ? "[OK]  " : "[ÉCHEC] ") + c.txt).join("\n"));
    const bad = cs.filter(c => !c.ok);
    if (bad.length) {
      out(`${bad.length} point(s) à corriger. Le premier : « ${bad[0].txt} » → ${bad[0].fix}.`, "err");
      x.audit = false;
    } else if (!x.exploited || !x.pivotBlk || !x.egressBlk) {
      out("La politique est irréprochable, mais Mallory n'a pas encore joué tous ses scénarios (`exploiter web`, `pivoter`, `rappeler`, à la porte d'Internet) : fais-les d'abord, pour voir la muraille à l'œuvre.", "sys");
    } else {
      x.audit = true;
      out("Tous les points sont validés : la muraille laisse passer EXACTEMENT le trafic légitime et bloque les scénarios d'attaque. Va rendre compte à Maître Ada.", "ok");
    }
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Port-443 a maintenant une muraille digne de ce nom : tout est refusé par défaut, quatre flux seulement sont autorisés, les connexions sont suivies, le NAT ne livre que deux services, la DMZ est enfermée et ce qui sort est surveillé. Mallory est repartie bredouille. Mais souviens-toi : la faille du site, elle, n'est toujours pas corrigée. La muraille a limité les dégâts, elle ne les a pas évités.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La muraille = un pare-feu de filtrage de paquets.** Les trois zones sont des segments de réseau reliés par un même pare-feu : **Internet**, la **DMZ** (zone démilitarisée, qui héberge les serveurs exposés) et le **réseau interne**. Chaque paquet qui passe d'une zone à une autre est comparé à une liste de règles (protocole, zones, port de destination ou de source).");
    out("**La règle héritée et l'ordre.** Un pare-feu lit les règles de haut en bas et applique la première qui correspond (Linux : iptables et nftables, comme la plupart des pare-feux). Une règle « autoriser tout » en tête rendait toute la liste inutile. Les règles précises vont avant les règles générales, et on contrôle les règles « masquées ».");
    out("**La politique par défaut.** « Autoriser tout sauf… » (liste noire) est fragile ; « refuser tout sauf… » (liste blanche, default deny) est le principe du moindre privilège appliqué au réseau. **Drop** (abandon silencieux) ne renseigne pas l'attaquant et ralentit les balayages ; **reject** renvoie un refus explicite, plus commode à l'intérieur.");
    out("**Sans état et avec état.** Une connexion TCP est bidirectionnelle : sans état, il faut autoriser l'aller ET le retour (port source = port du service, port de destination éphémère), ce qui ouvre aussi des paquets non sollicités. Avec suivi de connexions (conntrack), la réponse à une connexion autorisée est acceptée d'office.");
    out("**Le balayage de Mallory = nmap.** Un port est **ouvert** (un service répond), **fermé** (RST : la machine répond, rien n'écoute) ou **filtré** (aucune réponse utile : pare-feu). Moins on répond, moins on renseigne : mais un port filtré peut quand même cacher un service autorisé pour d'autres.");
    out("**Le comptoir des traductions = le NAT.** Le NAT entrant (DNAT, « port forwarding ») redirige un port de l'adresse publique vers une machine privée ; le NAT sortant (masquerade, SNAT) remplace l'adresse source privée par la publique. Sur Linux, le DNAT a lieu AVANT le filtrage (les règles voient l'adresse interne) et le SNAT APRÈS. **Le NAT n'est pas un pare-feu** : il masque des adresses, pas des services ; chaque redirection oubliée est une porte.");
    out("**La DMZ et la segmentation.** Le serveur web est le plus exposé : on le place dans une zone isolée, d'où rien ne va vers l'interne. Quand il est compromis (par une faille applicative que le pare-feu ne voit pas), le mouvement latéral échoue. **Le filtrage sortant** (egress) coupe l'appel de la machine compromise vers son serveur de commande et contrôle (C2).");
    out("**Les simplifications du jeu.** (1) Le filtre ne connaît que des zones, un protocole et un seul port par règle : pas d'adresses IP précises, pas de plages de ports, pas d'IPv6, pas de trafic intra-zone. (2) Un seul pare-feu et une seule table de règles ; en vrai : plusieurs chaînes (entrée, transfert, sortie), des pare-feux sur chaque machine, et le NAT impose en réalité un suivi de connexions : « NAT sans état » n'existe pas. (3) UDP et ICMP sont très simplifiés. En vrai, bloquer tout ICMP est une erreur (découverte de la taille de paquet, ICMPv6 indispensable en IPv6). (4) Selon sa configuration, un rejet peut renvoyer un RST, et le scanner le verrait « fermé ». (5) Un pare-feu de paquets ne lit pas le contenu : il laisse passer une attaque dans un flux autorisé (443 : site vulnérable) ou un C2 qui se cache dans du HTTPS. Il ne remplace donc ni la mise à jour des services, ni une application codée correctement, ni un proxy filtrant, une inspection ou la détection d'intrusion.");
    out("Rappel utile : **tout refuser par défaut, n'autoriser que le nécessaire, dans le bon ordre ; séparer ce qui est exposé de ce qui est précieux ; filtrer aussi ce qui sort. Et ne jamais compter sur le pare-feu pour réparer un service vulnérable.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    topo: () => {
      const x = F(), g = grid();
      const nm = { internet: "Internet", dmz: "DMZ", interne: "Interne" };
      const pairs = [["internet", "dmz"], ["internet", "interne"], ["dmz", "interne"], ["interne", "dmz"], ["interne", "internet"], ["dmz", "internet"]];
      let rows = T(8, 168, "Ce que le filtre laisse réellement passer (aller) :", "f-b f-s", "start");
      pairs.forEach(([a, b], i) => {
        const key = a + ">" + b, al = g.allowed[key] || [], bad = al.filter(l => !LEGIT.has(key + ">" + l)).length;
        const lab = !al.length ? "rien ne passe" : al.length > 4 ? `${al.length} flux dont ${bad} non prévus  ✗` : al.map(l => LEGIT.has(key + ">" + l) ? l + " ✔" : l + " ✗").join("   ");
        const y = 190 + i * 17;
        rows += T(8, y, `${nm[a]} → ${nm[b]}`, "f-s", "start") + T(136, y, lab, "f-s " + (bad ? "ft-bad" : al.length ? "ft-ok" : ""), "start");
      });
      return {
        cap: "Les trois zones de Port-443 reliées par un pare-feu. La liste du bas est calculée à partir de tes règles actuelles : en vert, les flux légitimes ; en rouge, ce qui passe sans qu'on l'ait voulu.",
        svg: SVG(300, "Topologie des trois zones",
          R(8, 8, 112, 60) + T(64, 28, "Internet", "f-b") + T(64, 46, "Bob, Ève, Mallory", "f-s") +
          R(154, 8, 112, 60, "f-pub") + T(210, 28, "DMZ", "f-b") + T(210, 46, "web · courrier", "f-s") +
          R(300, 8, 112, 60, "f-priv") + T(356, 28, "Interne", "f-b") + T(356, 46, "comptes · postes", "f-s") +
          LN(64, 68, 150, 100) + LN(210, 68, 210, 100) + LN(356, 68, 270, 100) +
          R(100, 100, 220, 48, "f-ok") + T(210, 120, "PARE-FEU", "f-b") + T(210, 138, `défaut : ${x.policy} · suivi : ${x.stateful ? "oui" : "non"}`, "f-s") + rows)
      };
    },
    ordre: (p) => {
      const x = F(); p = p || pk("internet", "dmz", "tcp", 443);
      const res = evalPkt(p), n = Math.min(x.rules.length, 7);
      let body = T(8, 16, `Paquet : ${pdesc(p)}`, "f-b f-s", "start");
      for (let i = 0; i < n; i++) {
        const y = 52 + i * 26, r = x.rules[i], hit = res.idx === i + 1, unread = res.idx && i + 1 > res.idx;
        const cls = hit ? (res.act === "autoriser" ? "f-ok" : "f-bad") : unread ? "f-dash" : "";
        const st = hit ? "CORRESPOND → " + res.act : unread ? "jamais lue" : "ne correspond pas";
        body += R(8, y - 16, 404, 22, cls) + T(14, y, `${i + 1}. ${rtxt(r)}`, "f-s", "start") + T(406, y, st, "f-s " + (hit ? (res.act === "autoriser" ? "ft-ok" : "ft-bad") : ""), "end");
      }
      let y = 52 + n * 26;
      if (x.rules.length > 7) { body += T(14, y - 2, `… et ${x.rules.length - 7} autre(s) règle(s)${res.idx > 7 ? ` (la règle ${res.idx} décide)` : ""}`, "f-s", "start"); y += 22; }
      body += R(8, y - 16, 404, 22, res.idx ? "f-dash" : (res.act === "autoriser" ? "f-ok" : "f-bad")) + T(14, y, `(sinon) politique par défaut : ${x.policy}`, "f-s", "start") + T(406, y, res.idx ? "jamais lue" : "DÉCIDE", "f-s " + (res.idx ? "" : res.act === "autoriser" ? "ft-ok" : "ft-bad"), "end");
      body += T(210, y + 34, `Décision : ${res.act === "autoriser" ? "AUTORISÉ" : res.act === "refuser" ? "ABANDONNÉ" : "REJETÉ"}${res.idx ? " par la règle " + res.idx : " par la politique"}`, "f-b " + (res.act === "autoriser" ? "ft-ok" : "ft-bad"));
      return { cap: "Les règles sont lues de haut en bas ; la première qui correspond décide et les suivantes ne sont pas lues. Le schéma rejoue ton dernier paquet de test sur tes règles actuelles.", svg: SVG(y + 48, "Évaluation des règles dans l'ordre", body) };
    },
    etat: (st) => ({
      cap: st ? "Avec suivi des connexions : le pare-feu note la connexion autorisée ; la réponse en fait partie et passe automatiquement."
        : "Sans état : chaque paquet est jugé seul. La requête passe, mais la réponse (port source 443, port de destination éphémère) n'a aucune règle qui l'autorise.",
      svg: SVG(250, "Pare-feu sans état et avec état",
        R(8, 8, 404, 108, st ? "f-dash" : "f-bad") + T(16, 28, "SANS ÉTAT : chaque paquet est jugé seul", "f-b f-s", "start") +
        T(16, 50, "aller   tcp 51514→443 internet→dmz : règle « autoriser 443 »  ✔", "f-s ft-ok", "start") +
        T(16, 68, "retour  tcp 443→51514 dmz→internet : aucune règle  ✘ jeté", "f-s ft-bad", "start") +
        T(16, 90, "il faudrait une règle de retour par service, qui laisse aussi", "f-s", "start") + T(16, 104, "passer des paquets que personne n'a demandés", "f-s", "start") +
        R(8, 128, 404, 114, st ? "f-ok" : "f-dash") + T(16, 148, "AVEC ÉTAT : le pare-feu mémorise les connexions", "f-b f-s", "start") +
        T(16, 170, "table : internet:51514 ↔ dmz:443   ÉTABLIE", "f-s", "start") +
        T(16, 188, "retour  tcp 443→51514 : fait partie de la connexion  ✔ auto", "f-s ft-ok", "start") +
        T(16, 210, "paquet non sollicité dmz→internet : absent de la table,", "f-s", "start") + T(16, 224, "il est jugé comme un nouveau paquet par les règles", "f-s", "start"))
    }),
    nat: () => {
      const x = F(); let tb = "";
      const rows = x.nat.slice(0, 5);
      rows.forEach((n, i) => { tb += T(16, 190 + i * 16, `${n.proto}/${n.port}  →  ${HOSTS[n.host].ip}:${n.port}  (${n.host})`, "f-s " + (n.port === 443 || n.port === 25 ? "ft-ok" : "ft-bad"), "start"); });
      if (x.nat.length > 5) tb += T(16, 190 + 5 * 16, `… et ${x.nat.length - 5} autre(s)`, "f-s", "start");
      if (!x.nat.length) tb += T(16, 190, "(aucune redirection)", "f-s", "start");
      const yb = 190 + Math.max(1, Math.min(6, x.nat.length + (x.nat.length > 5 ? 1 : 0))) * 16 + 6;
      return {
        cap: "Le NAT entrant redirige un port de l'adresse publique vers une machine privée ; le NAT sortant remplace l'adresse privée par la publique. La table du bas est celle de ton comptoir : en rouge, les redirections superflues.",
        svg: SVG(yb + 22, "Traduction d'adresses",
          R(8, 10, 100, 48) + T(58, 30, "Bob", "f-b") + T(58, 46, "198.51.100.7", "f-s") +
          R(150, 10, 120, 48, "f-ok") + T(210, 30, "pare-feu / NAT", "f-b") + T(210, 46, PUB, "f-s") +
          R(312, 10, 100, 48, "f-pub") + T(362, 30, "web", "f-b") + T(362, 46, "10.0.2.10", "f-s") +
          AR(108, 34, 150, 34) + AR(270, 34, 312, 34) +
          T(210, 82, "entrant : 203.0.113.10:443  ⇒  10.0.2.10:443 (DNAT)", "f-s") +
          T(210, 98, "puis le filtre juge le paquet DÉJÀ traduit", "f-s ft-pub") +
          T(210, 124, "sortant : 10.0.3.25:51514  ⇒  203.0.113.10:40001", "f-s") +
          T(210, 140, "(masquerade : le port distingue chaque connexion)", "f-s") +
          T(8, 170, "Table de redirection actuelle :", "f-b f-s", "start") + tb +
          T(8, yb + 10, `masquerade interne : ${x.masq.interne ? "oui" : "non"} · dmz : ${x.masq.dmz ? "oui" : "non"}`, "f-s", "start"))
      };
    },
    ports: () => ({
      cap: "Ce que le scanner de Mallory observe. « Fermé » prouve qu'une machine répond ; « filtré » ne prouve rien : c'est ce que cherche un bon pare-feu.",
      svg: SVG(200, "États d'un port",
        R(8, 8, 84, 26, "f-ok") + T(50, 26, "OUVERT", "f-b ft-ok") + T(104, 26, "SYN →  ← SYN/ACK : un service écoute", "f-s", "start") +
        R(8, 48, 84, 26, "f-priv") + T(50, 66, "FERMÉ", "f-b") + T(104, 66, "SYN →  ← RST : la machine répond, personne n'écoute", "f-s", "start") +
        R(8, 88, 84, 26, "f-bad") + T(50, 106, "FILTRÉ", "f-b ft-bad") + T(104, 106, "SYN →  … silence : abandon (drop), lent", "f-s", "start") +
        R(8, 128, 84, 26, "f-bad") + T(50, 146, "FILTRÉ", "f-b ft-bad") + T(104, 146, "SYN →  ← ICMP « interdit » : rejet (reject), rapide", "f-s", "start") +
        T(210, 184, "plus un port est filtré, moins l'attaquant apprend", "f-s"))
    }),
  };

  GAMES.firewall = {
    id: "firewall", order: 10, title: "La Muraille de Port-443", pageTitle: "Firewall Quest", subtitle: "aventure textuelle · pare-feu, NAT, segmentation",
    blurb: "Écris les règles de la muraille : default deny, ordre, suivi des connexions, NAT, DMZ et filtrage sortant, testés par un vrai moteur de filtrage.",
    concept: "Pare-feu, NAT, segmentation",
    start: "place", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      x.policy = "autoriser"; x.stateful = false;
      x.rules = [{ act: "autoriser", proto: "tout", port: null, pm: "dport", src: "tout", dst: "tout", legacy: true }];
      x.nat = [{ proto: "tcp", port: 22, host: "web" }, { proto: "tcp", port: 80, host: "web" }, { proto: "tcp", port: 443, host: "web" }, { proto: "tcp", port: 8080, host: "web" }, { proto: "tcp", port: 3389, host: "poste" }];
      x.masq = { interne: true, dmz: false }; x.xlat = [];
    },
    refig(name) { fig(name, name === "ordre" ? F().last || undefined : name === "etat" ? !!F().stateful : undefined); },
    figAlias: { topo: ["zones", "topologie", "dmz"], ordre: ["regles", "evaluation", "premiere"], etat: ["stateful", "stateless", "connexion", "suivi"], nat: ["traduction", "adresses"], ports: ["scan", "nmap", "balayage"] },
    help: "Spécifiques : `regle ‹autoriser|refuser|rejeter› ‹tcp|udp|icmp|tout› ‹port|tout› de ‹zone› vers ‹zone›` · `regles` · `supprimer regle ‹n›` · `deplacer regle ‹n› ‹m›` · `politique ‹autoriser|refuser|rejeter›` · `suivi activer` · `tester tcp ‹port› de ‹zone› vers ‹zone›` · `nat` · `nat rediriger tcp ‹port› vers ‹machine›` · `nat supprimer ‹port›` · `nat masquerade interne` · `balayer` · `exploiter web` · `pivoter` · `rappeler` · `auditer`",
    verbs: {
      rule: { words: ["regle", "regles"], run: ruleCmd },
      remove: { words: ["supprimer", "retirer", "effacer", "enlever"], run: removeCmd },
      move: { words: ["deplacer"], run: moveCmd },
      policy: { words: ["politique", "defaut"], run: policyCmd },
      state: { words: ["suivi", "stateful"], run: stateCmd },
      test: { words: ["tester", "envoyer", "sonder"], run: testCmd },
      nat: { words: ["nat"], run: natCmd },
      scan: { words: ["balayer", "scanner", "nmap"], run: scan },
      exploit: { words: ["exploiter", "compromettre"], run: exploit },
      pivot: { words: ["pivoter", "rebondir"], run: pivot },
      callback: { words: ["rappeler", "appeler"], run: callBack },
      audit: { words: ["auditer", "audit", "valider", "controler"], run: auditCmd },
    },
    intro() {
      out("La Muraille de Port-443", "title");
      out("La cité de Port-443 a trois quartiers : Internet, dehors ; la DMZ, avec le serveur web et celui du courrier ; et le réseau interne, avec les comptes et les sauvegardes. Entre eux, une muraille : un pare-feu, dont les règles décident de ce qui passe. Depuis la dernière migration, elle laisse tout passer.\nMaître Ada t'engage pour un audit autorisé : réécris la politique de la muraille, avec un banc d'essai qui évalue vraiment tes règles. Mallory, qui sonde la porte, jouera l'attaquante. Tout est simulé.", "");
    },
  };
})();
