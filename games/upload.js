"use strict";
/* La Réception des Colis : téléversement de fichiers et désérialisation non fiable, dans un serveur fictif.
   Contexte : audit autorisé de notre propre guichet (mandat écrit). Tout est jouet : aucun code réel. */
(function () {
  const F = () => f();
  const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const trunc = (s, n) => s.length > n ? s.slice(0, n - 1) + "…" : s;

  /* ---------- octets, en-têtes magiques, SHA-256 et HMAC (réels) ---------- */
  const bytesOf = s => Array.from(s).map(c => c.charCodeAt(0) & 255);
  const hexs = (b, n) => b.slice(0, n).map(v => v.toString(16).padStart(2, "0").toUpperCase()).join(" ");
  const ascii = b => b.map(v => String.fromCharCode(v)).join("");
  const MAGIC = { png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], jpeg: [0xFF, 0xD8, 0xFF], pdf: [0x25, 0x50, 0x44, 0x46, 0x2D], zip: [0x50, 0x4B, 0x03, 0x04] };
  function sniff(b) {
    for (const [k, m] of Object.entries(MAGIC)) if (m.every((v, i) => b[i] === v)) return k;
    return b.every(v => v === 9 || v === 10 || (v >= 32 && v < 127)) ? "texte" : "inconnu";
  }
  const DESC = { png: "une image PNG", jpeg: "une image JPEG", pdf: "un PDF", zip: "une archive ZIP", texte: "du texte (aucun en-tête magique)", inconnu: "des données inconnues" };
  const MIME = { png: "image/png", jpeg: "image/jpeg", pdf: "application/pdf", zip: "application/zip" };

  const PR = []; for (let n = 2; PR.length < 64; n++) if (isPrime(n)) PR.push(n);
  const frac = v => Math.floor((v - Math.floor(v)) * 4294967296);
  const K256 = PR.map(p => frac(Math.cbrt(p))), H256 = PR.slice(0, 8).map(p => frac(Math.sqrt(p)));
  function sha256b(m) {
    const b = m.slice(), bits = b.length * 8;
    b.push(0x80); while (b.length % 64 !== 56) b.push(0);
    const hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
    b.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255, (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
    let H = H256.slice(); const w = new Array(64), rr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let i = 0; i < b.length; i += 64) {
      for (let t = 0; t < 16; t++) w[t] = (b[i + 4 * t] << 24) | (b[i + 4 * t + 1] << 16) | (b[i + 4 * t + 2] << 8) | b[i + 4 * t + 3];
      for (let t = 16; t < 64; t++) w[t] = (w[t - 16] + (rr(w[t - 15], 7) ^ rr(w[t - 15], 18) ^ (w[t - 15] >>> 3)) + w[t - 7] + (rr(w[t - 2], 17) ^ rr(w[t - 2], 19) ^ (w[t - 2] >>> 10))) | 0;
      let [a, c, d, e, g, h, j, k] = H;
      for (let t = 0; t < 64; t++) {
        const t1 = (k + (rr(g, 6) ^ rr(g, 11) ^ rr(g, 25)) + ((g & h) ^ (~g & j)) + K256[t] + w[t]) | 0;
        const t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & c) ^ (a & d) ^ (c & d))) | 0;
        k = j; j = h; h = g; g = (e + t1) | 0; e = d; d = c; c = a; a = (t1 + t2) | 0;
      }
      H = H.map((x, n) => (x + [a, c, d, e, g, h, j, k][n]) | 0);
    }
    return H.flatMap(v => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
  }
  const toHex = b => b.map(v => v.toString(16).padStart(2, "0")).join("");
  function hmacHex(key, msg) {
    const kb = Array.from(new TextEncoder().encode(key)); while (kb.length < 64) kb.push(0);
    const inner = sha256b([...kb.map(v => v ^ 0x36), ...new TextEncoder().encode(msg)]);
    return toHex(sha256b([...kb.map(v => v ^ 0x5c), ...inner]));
  }
  const SECRET = "cle-du-guichet-fictive";

  /* ---------- vrai normaliseur de chemins ---------- */
  function normTrace(p) {
    const st = [], tr = [];
    p.replace(/\\/g, "/").split("/").forEach(seg => {
      if (seg === "" || seg === ".") return;
      if (seg === "..") { const gone = st.pop(); tr.push({ seg, st: "/" + st.join("/"), why: gone ? "remonte" : "déjà à la racine" }); }
      else { st.push(seg); tr.push({ seg, st: "/" + st.join("/"), why: "descend" }); }
    });
    return { res: "/" + st.join("/"), tr };
  }

  /* ---------- colis de test ---------- */
  const IHDR = [0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52];
  const TOYCODE = "<?toy lire /var/www/app/config.toy ?>";
  const KINDS = {
    texte: { b: bytesOf("Bonjour la Guilde, voici mon colis."), kb: 1, d: "un simple fichier texte" },
    png: { b: [...MAGIC.png, ...IHDR, 0, 0, 1, 0, 0, 0, 1, 0], kb: 180, d: "une vraie image PNG" },
    jpeg: { b: [0xFF, 0xD8, 0xFF, 0xE0, 0, 16, ...bytesOf("JFIF"), 0], kb: 240, d: "une vraie image JPEG" },
    pdf: { b: bytesOf("%PDF-1.7\n1 0 obj<<>>endobj\n"), kb: 310, d: "un vrai PDF" },
    zip: { b: [...MAGIC.zip, 20, 0, 0, 0, 8, 0, ...bytesOf("notes.txt")], kb: 12, comp: 12, unc: 30, d: "une archive ZIP ordinaire (12 Ko, 30 Ko une fois ouverte)" },
    script: { b: bytesOf(TOYCODE), kb: 1, d: "un script « toy » de Mallory, sans en-tête d'image" },
    polyglot: { b: [...MAGIC.png, ...IHDR, ...bytesOf(TOYCODE)], kb: 2, d: "un PNG valide avec un script « toy » collé à la suite (polyglotte)" },
    jpeghtml: { b: [0xFF, 0xD8, 0xFF, 0xE0, ...bytesOf("<script>voler(document.cookie)</script>")], kb: 2, d: "un JPEG qui cache une page HTML piégée" },
    bombe: { b: [...MAGIC.zip, 20, 0, 0, 0, 8, 0, ...bytesOf("zeros.bin")], kb: 42, comp: 42, unc: 4000000, d: "une archive ZIP de 42 Ko qui se déploie en 4 Go de zéros" },
    gros: { b: [...MAGIC.png, ...IHDR], kb: 25000, d: "une image PNG de 25 Mo" },
    gps: { b: [0xFF, 0xD8, 0xFF, 0xE1, ...bytesOf("Exif\0\0|Make=Camera-Guilde|Artist=Bob|Date=2026-07-14|GPS=43.1234N,5.4321E")], kb: 2400, d: "une photo JPEG de vacances de Bob, avec ses métadonnées" },
    suspect: { b: bytesOf("%PDF-1.7\n% TEST-MALWARE-GUILDE\n"), kb: 20, d: "un PDF portant la signature de test « TEST-MALWARE-GUILDE »" },
    suspect2: { b: bytesOf("%PDF-1.7\n% TEST-MALWARE-GU1LDE\n"), kb: 20, d: "le même PDF, signature légèrement modifiée (« GU1LDE »)" },
  };
  const ALLOWED = { png: "png", jpg: "jpeg", jpeg: "jpeg", pdf: "pdf", zip: "zip" };
  const SIGS = ["TEST-MALWARE-GUILDE"];
  const FSMAP = { "/var/www/app/config.toy": "secret_api = CLE-FICTIVE-4242\nbase = guilde.db" };
  const MAXKB = 5000, QUOTA = 100000, LOGO = "/var/www/public/img/logo.png";
  const kb = n => (n >= 1000000 ? (n / 1000000) + " Go" : n >= 1000 ? (n / 1000) + " Mo" : n + " Ko").replace(".", ",");

  /* ---------- contrôles ---------- */
  const CTRL = [
    ["limites", "Limites de taille et de nombre", /limite|taille|quota/],
    ["contenu", "Vérification du contenu (en-têtes magiques)", /contenu|magique|en tete/],
    ["decompression", "Taux d'expansion des archives", /decompress|ratio|bombe|expansion/],
    ["antivirus", "Antivirus et quarantaine", /antivir|quarantaine|\bav\b/],
    ["metadonnees", "Ré-encodage des images (métadonnées)", /metadonn|exif|encod/],
    ["nom", "Nom de fichier généré par le serveur", /nom|genere|nommage/],
    ["stockage", "Stockage hors racine web, droits sans exécution", /stockage|hors|noexec|racine|execution|droits/],
    ["domaine", "Domaine séparé, téléchargement forcé, nosniff", /domaine|download|telecharg|nosniff/],
    ["json", "Bons en JSON pur (aucun type)", /json|donnees pures|pur/],
    ["liste", "Liste blanche de classes", /liste|blanche|classes/],
    ["signature", "Signature HMAC avant lecture", /hmac|signature|signe/],
    ["privilege", "Compte du chargeur à privilège minimal", /privilege|minim|moindre/],
  ];
  const CTRL_ORDER = ["privilege", "liste", "signature", "json", "decompression", "limites", "antivirus", "metadonnees", "domaine", "stockage", "contenu", "nom"];
  const ctrlName = id => CTRL.find(c => c[0] === id)[1];
  function ctrlList() {
    const c = F().c;
    return CTRL.map(([id, n]) => `${c[id] ? "✔ actif  " : "✘ absent "} ${id.padEnd(14)} ${n}`).join("\n");
  }

  /* ---------- notes ---------- */
  const notes = {
    contenu: ["Types et contenu", "Le nom du fichier et le « type » envoyé par le navigateur sont écrits par l'envoyeur : ils ne prouvent rien. On lit le contenu : la plupart des formats commencent par des octets fixes, les en-têtes magiques (PNG : 89 50 4E 47 0D 0A 1A 0A, JPEG : FF D8 FF, PDF : %PDF-, ZIP : PK 03 04). Mais un fichier peut être à la fois une vraie image ET autre chose (polyglotte) : le contrôle d'en-tête ne suffit pas seul."],
    double: ["Double extension", "Un contrôle qui ne regarde que la dernière extension laisse passer rapport.toy.png, alors que certains serveurs reconnaissent n'importe laquelle des extensions du nom (ici .toy) et exécutent le fichier. Une liste blanche d'extensions est nécessaire, jamais suffisante."],
    chemin: ["Traversée de chemin", "Si le serveur colle le nom envoyé au dossier de dépôt, un nom comme ../../x écrit où il veut. Un normaliseur de chemin résout les « .. » : on compare ensuite le résultat au dossier prévu. La meilleure parade : ne jamais utiliser le nom fourni, en fabriquer un côté serveur (hasard ou empreinte) avec une extension déduite du contenu."],
    stockage: ["Stockage et exécution", "Un fichier téléversé est une donnée, jamais un programme. On le range hors de la racine web, avec des droits sans exécution (0640), et on le sert par une route dédiée, de préférence depuis un domaine séparé sans cookies, avec Content-Disposition: attachment (téléchargement forcé) et X-Content-Type-Options: nosniff (le navigateur ne devine pas un autre type)."],
    taille: ["Taille et décompression", "Sans limite de taille, de nombre et de quota, un seul visiteur remplit le disque (déni de service). Une bombe de décompression est minuscule compressée et gigantesque une fois ouverte : on calcule le taux d'expansion (taille décompressée ÷ taille compressée) et on refuse au-delà d'un seuil, avant d'extraire."],
    av: ["Antivirus et quarantaine", "L'analyse par signatures isole en quarantaine (dossier sans droits) ce qu'elle reconnaît. Elle ne voit que le connu : une variante modifiée passe. C'est une couche de plus, pas une garantie."],
    meta: ["Métadonnées (EXIF)", "Une photo contient souvent date, appareil, auteur et position GPS. Publiée telle quelle, elle révèle où son auteur habite. On ré-encode les images côté serveur : seuls les pixels sont conservés, métadonnées et données greffées à la suite disparaissent."],
    deser: ["Désérialisation non fiable", "Certains formats d'objets sérialisés contiennent le nom d'une classe à instancier et déclenchent du code au chargement. Qui contrôle l'octet d'entrée contrôle ce qui s'exécute : c'est une exécution de code à distance en puissance. Règle : ne jamais désérialiser des données non fiables avec un format qui instancie des types."],
    liste: ["Liste blanche et signature", "Défenses, de la plus forte à la moins forte : format de données pur (JSON sans types, validé par un schéma) ; liste blanche des classes autorisées ; signature HMAC vérifiée AVANT toute lecture (seul qui connaît la clé fabrique un objet valide) ; compte de service à privilège minimal pour limiter les dégâts si tout cède."],
  };

  /* ---------- entités et lieux ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, commanditaire de l'audit." },
    mandat: { names: ["mandat", "autorisation"], label: "ton mandat d'audit", desc: () => "« L'apprenti·e est autorisé·e à tester le guichet de réception de la Guilde (colis et bons de commande), sur ce serveur fictif et aux dates convenues. Signé : Maître Ada. » Sans ce papier, ce serait illégal." },
    tableau: { names: ["tableau", "controles", "tableau de controles", "panneau"], label: "le tableau de contrôles", desc: () => "Le tableau de contrôles du serveur (commande `activer ‹contrôle›`, par exemple `activer contenu`) :\n" + ctrlList() },
    bob: { npc: true, names: ["bob", "guichetier", "prepose"], label: "Bob, préposé au guichet", desc: () => "Bob tamponne les colis sans les ouvrir. Ce n'est pas son rôle, dit-il." },
    sac: { names: ["sac", "sac de mallory", "colis de test", "fichiers de test"], label: "le sac de colis de test", desc: () => "Ton sac de fichiers de test (tout est fictif). Syntaxe : `deposer ‹nom› ‹type› ‹contenu›`, avec un contenu parmi :\n" + Object.entries(KINDS).map(([k, v]) => `  · ${k} : ${v.d}`).join("\n") + "\nOption : un suffixe xN envoie N copies d'un coup (`deposer a.png image/png png x20`). `visiter` ouvre le dernier colis accepté." },
    alice: { npc: true, names: ["alice", "magasiniere"], label: "Alice, magasinière", desc: () => "Alice range les colis dans l'entrepôt et connaît chaque dossier du serveur." },
    arbo: { names: ["arborescence", "arbo", "dossiers", "serveur"], label: "le plan des dossiers du serveur", desc: () => treeText() },
    lovelace: { npc: true, names: ["lovelace", "dame lovelace", "ingenieure"], label: "Dame Lovelace, ingénieure", desc: () => "Dame Lovelace, ingénieure de sécurité, tablier plein de câbles." },
    scanner: { names: ["scanner", "analyseur", "machine"], label: "le scanner à signatures", desc: () => `Le scanner compare chaque fichier à une liste de signatures connues (ici : ${SIGS.join(", ")}). État : ${F().c.antivirus ? "ACTIF" : "éteint"}. Les fichiers repérés vont dans /srv/quarantaine, un dossier sans aucun droit.` },
    eve: { npc: true, names: ["eve", "greffiere"], label: "Ève, greffière", desc: () => "Ève trie les bons de commande qui arrivent par la pneumatique. Elle écoute tout ce qui passe." },
    registre: { names: ["registre", "registre des commandes"], label: "le registre des commandes", desc: () => "Le registre des commandes de la Guilde (fictif) :\n" + (F().reg.length ? F().reg.map(r => `  · ${r.k} : ${r.t}`).join("\n") : "  (VIDE : tout a été effacé)") + "\nSi besoin : `restaurer registre`." },
    modele: { names: ["modele", "bon", "modele de bon", "formulaire"], label: "le modèle de bon de commande", desc: () => "Format jouet des objets sérialisés de la Guilde : des champs `clé=valeur` séparés par `;`. Le champ **type** désigne la classe à instancier ; ses méthodes de chargement s'exécutent aussitôt.\nExemple : `type=Commande;article=ancre;quantite=3`\nTu envoies un bon avec `soumettre ‹bon›`. Le service d'émission signe un bon avec `emettre ‹bon›`." },
  };
  const rooms = {
    hall: { name: "Le hall de la Réception", short: "Hall", alias: ["hall", "reception"], ents: ["ada", "mandat", "tableau"], exits: { est: "guichet", sud: "entrepot", ouest: "labo", nord: "bons" },
      desc: () => "Un hall en bois où s'empilent des colis. À l'est, le guichet de dépôt. Au sud, l'entrepôt. À l'ouest, le laboratoire d'analyse. Au nord, la salle des bons de commande. Au mur, le tableau de contrôles du serveur." },
    guichet: { name: "Le guichet de dépôt", short: "Guichet", alias: ["guichet", "depot"], ents: ["bob", "sac"], exits: { ouest: "hall" },
      desc: () => "Un comptoir où l'on glisse ses fichiers dans une fente. Derrière, Bob tamponne. Le serveur fictif décide si le colis est accepté, où le ranger, et comment le servir ensuite." },
    entrepot: { name: "L'entrepôt", short: "Entrepôt", alias: ["entrepot", "stock"], ents: ["alice", "arbo"], exits: { nord: "hall" },
      desc: () => "Des étagères sont étiquetées avec les vrais chemins du serveur : racine web, dossier des colis, quarantaine. Alice y range ce que le guichet accepte." },
    labo: { name: "Le laboratoire d'analyse", short: "Laboratoire", alias: ["labo", "laboratoire"], ents: ["lovelace", "scanner"], exits: { est: "hall" },
      desc: () => "Un laboratoire de cuivre et de verre. Un scanner à signatures bourdonne dans un coin." },
    bons: { name: "La salle des bons de commande", short: "Bons", alias: ["bons", "commandes", "greffe"], ents: ["eve", "registre", "modele"], exits: { sud: "hall" },
      desc: () => "Une pneumatique crache des bons de commande : des objets sérialisés, que le serveur recharge pour les exécuter. Ève trie. Sur un pupitre, le registre des commandes de la Guilde." },
  };

  function treeText() {
    const x = F(), c = x.c;
    const inWeb = x.files.filter(z => z.path.startsWith("/var/www/public/uploads/")), out_ = x.files.filter(z => z.path.startsWith("/srv/colis/")), other = x.files.filter(z => !z.path.startsWith("/var/www/public/uploads/") && !z.path.startsWith("/srv/colis/") && z.path !== LOGO);
    const L = ["/var/www/public/        (RACINE WEB : servi tel quel)", "  index.toy", `  img/logo.png          ${x.logo === "original" ? "(logo de la Guilde)" : "(REMPLACÉ par un colis !)"}`, "  uploads/              (dépôts" + (c.stockage ? ", plus utilisé)" : ", droits 0755 exécutable)")];
    inWeb.forEach(z => L.push("    " + z.stored + "  " + z.perm.split(" ")[0]));
    L.push("/var/www/app/config.toy   (secrets, hors racine web)", "/srv/colis/              (HORS racine web, " + (c.stockage ? "droits 0640 : en service" : "pas encore utilisé") + ")");
    out_.forEach(z => L.push("    " + z.stored + "  " + z.perm.split(" ")[0]));
    L.push("/srv/quarantaine/        (droits 0000)");
    x.files.filter(z => z.q).forEach(z => L.push("    " + z.stored));
    other.forEach(z => L.push("  ! " + z.path + "  (hors dossier prévu)"));
    return "Plan du serveur fictif :\n" + L.join("\n");
  }

  /* ---------- partie 1 : le guichet ---------- */
  function deposit(name, declared, key, n, auto) {
    const x = F(), c = x.c, K = KINDS[key], sn = sniff(K.b), tr = [];
    const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
    const line = (ok, t) => tr.push((ok ? "✔ " : "✘ ") + t), dot = t => tr.push("· " + t);
    out(`${auto ? "Rejeu : " : ""}Colis « ${name} », type déclaré « ${declared} », contenu réel : ${DESC[sn]}${n > 1 ? ` (×${n})` : ""}.`, "sys");
    code("octets de tête : " + hexs(K.b, 12));
    let ok = true, why = "";
    const stop = (t, t2) => { line(false, t); ok = false; why = t2 || t; };
    // 1. limites
    if (c.limites) {
      if (K.kb > MAXKB) { stop(`taille ${kb(K.kb)} supérieure à la limite de ${kb(MAXKB)} (refus 413)`); x.limBlock = true; }
      else if (n > 10) { stop(`${n} fichiers dans une requête : limite de 10 (refus 429)`); x.limBlock = true; }
      else line(true, `taille (${kb(K.kb)}) et nombre (${n}) dans les limites`);
    } else dot("taille et nombre : non limités");
    // 2. extension
    if (ok) {
      if (ALLOWED[ext]) line(true, `extension .${ext} dans la liste blanche (png, jpg, pdf, zip). Type déclaré : non vérifié`);
      else stop(`extension « .${ext || "(aucune)"} » refusée (seules png, jpg, pdf, zip passent). Le type déclaré n'est même pas regardé`);
      if (ok && !/[\/\\]/.test(name) && name.split(".").length > 2) dot(`le nom contient d'autres extensions : .${name.split(".").slice(1, -1).join(" .")}`);
    }
    // 3. contenu
    if (ok) {
      if (c.contenu) {
        if (sn === ALLOWED[ext]) line(true, `en-tête magique : ${sn.toUpperCase()}, conforme à l'extension .${ext}`);
        else { stop(`en-tête magique : ${sn}, mais l'extension annonce ${ALLOWED[ext]}`); x.extBlock = true; }
      } else dot("contenu : non vérifié");
    }
    // 4. décompression
    if (ok && sn === "zip") {
      const ratio = (K.unc || 1) / (K.comp || 1);
      if (c.decompression) {
        if (ratio > 100) { stop(`taux d'expansion ${Math.round(ratio).toLocaleString("fr-FR")}:1 (${kb(K.unc)} ÷ ${kb(K.comp)}), seuil 100:1 : refusé avant extraction`); x.bombBlock = true; }
        else line(true, `taux d'expansion ${String(Math.round(ratio * 10) / 10).replace(".", ",")}:1, sous le seuil de 100:1`);
      } else dot(`taux d'expansion non contrôlé (${Math.round(ratio).toLocaleString("fr-FR")}:1)`);
    }
    // 5. antivirus
    const text = ascii(K.b);
    if (ok) {
      if (c.antivirus) {
        const sig = SIGS.find(s => text.includes(s));
        if (sig) { stop(`signature « ${sig} » reconnue : mise en quarantaine`); x.avBlock = true; }
        else { line(true, "aucune signature connue"); if (text.includes("TEST-MALWARE")) { x.avMiss = true; tr.push("  (… mais le fichier contient une variante : l'analyse par signatures ne voit que le connu)"); } }
      } else dot("antivirus : aucun");
    }
    if (!ok) {
      code(tr.join("\n"));
      if (x.c.antivirus && x.avBlock && /signature/.test(why)) { x.files.push({ name, stored: "q-" + (x.files.length + 1) + ".bin", path: "/srv/quarantaine/q-" + (x.files.length + 1) + ".bin", perm: "0000", q: true, key, sn }); }
      out("Colis REFUSÉ : " + why + ".", "err");
      return null;
    }
    // 6. ré-encodage
    const hadExif = text.includes("Exif");
    let reenc = false;
    if (c.metadonnees && (sn === "png" || sn === "jpeg")) { reenc = true; line(true, "image ré-encodée : métadonnées et octets greffés supprimés"); } else dot("ré-encodage : aucun");
    // 7. nom et chemin
    const e2 = ext === "jpeg" ? "jpg" : ext;
    let sname = name;
    if (c.nom) { sname = sha256(toHex(K.b) + ":" + (x.seq = (x.seq || 0) + 1)).slice(0, 12) + "." + e2; line(true, `nom généré par le serveur : ${sname} (le nom envoyé est ignoré)`); }
    else dot("nom conservé tel quel : " + name);
    const dir = c.stockage ? "/srv/colis" : "/var/www/public/uploads";
    const nt = normTrace(dir + "/" + sname), inside = nt.res.startsWith(dir + "/");
    x.pf = { base: dir, name: sname, res: nt.res, tr: nt.tr, inside };
    if (inside) line(true, `chemin résolu : ${nt.res} (dans ${dir})`);
    else { line(false, `chemin résolu : ${nt.res} : HORS de ${dir} !`); x.trav = true; }
    const perm = c.stockage ? "0640 (sans exécution)" : "0755 (exécutable)";
    tr.push(`→ rangé : ${nt.res}, droits ${perm}`);
    code(tr.join("\n"));
    const payload = reenc ? null : text.includes("<?toy") ? "toy" : text.includes("<script>") ? "html" : null;
    const fl = { name, stored: sname, path: nt.res, perm, declared, key, sn, exif: hadExif && !reenc, hadExif, reenc, payload, web: nt.res.startsWith("/var/www/public/"), n };
    x.files.push(fl); x.last = x.files.length - 1;
    out(`Colis ACCEPTÉ : ${nt.res}`, "ok");
    if (!inside) {
      out("Le nom envoyé contenait des « ../ » : le serveur a écrit le fichier à un endroit qu'il ne prévoyait pas.", "err");
      if (nt.res === LOGO) { x.logo = "mallory"; out("Le logo de la Guilde (/var/www/public/img/logo.png) est maintenant TON fichier : tout le monde le voit sur le site.", "err"); }
      note("chemin"); fig("chemin");
    }
    if (n > 1 || K.kb >= 1000) {
      if (!c.limites) {
        x.disk = (x.disk || 0) + K.kb * n;
        if (x.disk > QUOTA) { x.dos = true; out(`${n} × ${kb(K.kb)} = ${kb(K.kb * n)} : le disque de 100 Mo est PLEIN. Plus aucun colis n'entre : déni de service.`, "err"); x.disk = 0; note("taille"); }
        else out(`Espace disque consommé : ${kb(x.disk)} sur ${kb(QUOTA)}.`, "sys");
      }
    }
    if (sn === "zip" && !c.decompression && K.unc >= 1000000) {
      x.bomb = true; out(`Le serveur ouvre l'archive pour en lister le contenu : ${kb(K.unc)} à écrire en mémoire et sur disque. Le serveur ralentit puis tombe : bombe de décompression réussie.`, "err"); note("taille"); fig("ratio");
    }
    if (!c.antivirus && /TEST-MALWARE/.test(text)) { x.avAttack = true; out("Personne n'a analysé le colis : il est livré tel quel aux employés. (Simulation : un poste serait compromis.)", "err"); }
    if (!hadExif && !payload && ["png", "jpeg", "pdf", "zip"].includes(sn) && K.kb < 1000 && !/TEST/.test(text)) { if (!x.saw) { x.saw = true; fig("chaine"); } }
    return fl;
  }

  function visit(fl, auto) {
    const x = F(), c = x.c;
    if (fl.q) { out("Ce colis est en quarantaine : personne ne peut l'ouvrir.", "sys"); return; }
    const exts = fl.stored.split(".").slice(1);
    const url = fl.web ? "https://guilde.port443.example" + fl.path.replace("/var/www/public", "") : c.domaine ? "https://colis-guilde.example/dl/" + fl.stored : "https://guilde.port443.example/fichier/" + fl.stored;
    out(`${auto ? "Rejeu : " : ""}Un visiteur ouvre ${url}`, "sys");
    if (fl.web && fl.perm.startsWith("0755") && exts.includes("toy")) {
      const m = KINDS[fl.key] && ascii(KINDS[fl.key].b).match(/<\?toy lire (\S+) \?>/);
      if (m) {
        x.rce = true; if (fl.sn !== "texte") x.rcePoly = true;
        out("Le serveur reconnaît l'extension .toy dans le nom, voit le bit d'exécution, et EXÉCUTE le fichier au lieu de le servir :", "err");
        code("[toy] lire " + m[1] + "\n" + (FSMAP[m[1]] || "(fichier introuvable)").split("\n").map(s => "  → " + s).join("\n") + "\n(données fictives du jeu)");
        out("Un fichier téléversé vient de lire la configuration secrète du serveur. Exécution de code à distance.", "err");
        note("double"); if (fl.sn !== "texte") out("Et ce colis avait passé la vérification d'en-tête : c'est un PNG valide ET un script (polyglotte).", "err");
      } else out("Le serveur tente d'exécuter le fichier mais n'y trouve pas de code. Rien ne se passe.", "sys");
      return;
    }
    const sniffed = MIME[fl.sn] || "application/octet-stream";
    const ct = fl.web || !c.domaine ? fl.declared : sniffed;
    const dl = !fl.web && c.domaine;
    code(`HTTP/1.1 200 OK\nContent-Type: ${ct}\nContent-Disposition: ${dl ? 'attachment; filename="' + fl.stored + '"' : "(absent : affichage dans la page)"}\nX-Content-Type-Options: ${dl ? "nosniff" : "(absent)"}\nOrigine : ${dl ? "colis-guilde.example (sans cookies de la Guilde)" : "guilde.port443.example (celle du site et des sessions)"}`);
    if (!dl && /text\/html/.test(ct) && fl.payload === "html") {
      x.xss = true;
      out("Le navigateur d'Ada reçoit « text/html » et affiche le fichier comme une page : le script s'exécute DANS l'origine du site.", "err");
      code("document.cookie  →  « session=ada-7f3c91 »   (fictif)\nenvoi vers mallory.example/collect");
      out("Le cookie de session d'Ada est parti. Le fichier était bien un JPEG pour le contrôle de contenu, mais le serveur l'a servi avec le type choisi par l'envoyeur, depuis l'origine du site.", "err");
      note("stockage");
      if (fl.web && c.stockage) out("(Ce fichier est resté dans la racine web : le domaine séparé ne sert que les fichiers rangés hors racine.)", "sys");
    } else if (dl) out(`Le navigateur télécharge le fichier sans l'ouvrir (attachment), sans deviner un autre type (nosniff), depuis un domaine qui n'a aucun cookie de la Guilde. Rien ne s'exécute.`, "ok");
    else out(fl.payload === "toy" ? "Le script est bien dans le fichier, mais le serveur ne l'exécute pas : rangé hors racine web, sans droit d'exécution, c'est une simple donnée." : "Le fichier s'affiche normalement.", "sys");
    if (fl.exif) {
      x.leak = true;
      out("Mais la photo contient toujours ses métadonnées, lisibles par tous :", "err");
      code("Make    : Camera-Guilde\nArtist  : Bob\nDate    : 2026-07-14\nGPS     : 43.1234 N, 5.4321 E   (fictif : le domicile de Bob)");
      out("N'importe qui peut télécharger la photo et lire où habite Bob.", "err"); note("meta");
    } else if (fl.hadExif && fl.reenc) { x.metaOk = true; out("Aucune métadonnée dans le fichier servi : l'image a été ré-encodée, seuls les pixels restent.", "ok"); }
  }

  /* ---------- partie 2 : les bons ---------- */
  const REG0 = () => [{ k: "commande", t: "ancre ×2 (alice)" }, { k: "commande", t: "voile ×1 (bob)" }, { k: "commande", t: "corde ×5 (ada)" }, { k: "facture", t: "F-001" }];
  const ALLOW = ["Commande", "Facture"];
  const CLASSES = {
    Commande: o => {
      const q = parseInt(o.quantite, 10);
      if (!o.article || !(q >= 1 && q <= 999)) throw new Error("Commande.on_load : article ou quantité invalide");
      F().reg.push({ k: "commande", t: `${o.article} ×${q} (${o.client || "?"})` }); return `Commande.on_load() : commande de ${o.article} ×${q} enregistrée.`;
    },
    Facture: o => { F().reg.push({ k: "facture", t: o.numero || "F-?" }); return `Facture.on_load() : facture ${o.numero || "?"} enregistrée.`; },
    Purge: (o, c) => {
      if (c.privilege) { F().privBlock = true; throw new Error("Purge.on_load → effacer(" + o.cible + ") : permission refusée. Le compte du chargeur (svc-bons) n'a que lecture + insertion, pas la suppression"); }
      const n = F().reg.length; F().reg = []; F().purged = true;
      return `Purge.on_load() a été EXÉCUTÉE AU CHARGEMENT : le registre fictif est effacé (${n} entrées perdues).`;
    },
  };
  function loadBon(raw, ov) {
    const x = F(), c = Object.assign({}, x.c, ov || {}), tr = [];
    let payload = raw.trim(), sig = null;
    const i = payload.lastIndexOf("#"); if (i >= 0) { sig = payload.slice(i + 1).trim(); payload = payload.slice(0, i); }
    const lb = x.lastBon = { type: "?", verdict: "", pass: false };
    let signed = false;
    const fail = (t, v, cls) => { code(tr.join("\n")); out(t, cls || "err"); lb.verdict = v; return false; };
    if (c.signature) {
      if (!sig) { tr.push("✘ signature : absente"); x.sigBlock = true; return fail("Bon REFUSÉ avant toute lecture : pas de signature.", "refusé : pas de signature", "ok"); }
      if (sig !== hmacHex(SECRET, payload)) { tr.push("✘ signature : HMAC-SHA-256 incorrect"); x.sigBlock = true; return fail("Bon REFUSÉ avant toute lecture : la signature ne correspond pas au contenu (forgé ou modifié). Rien n'a été instancié.", "refusé : signature invalide", "ok"); }
      tr.push("✔ signature HMAC-SHA-256 valide : le bon vient bien du service d'émission"); signed = true; x.sigOk = true;
    } else tr.push("· signature : non vérifiée (n'importe qui peut fabriquer un bon)");
    if (c.json) {
      let o; try { o = JSON.parse(payload); } catch (e) { tr.push("✘ format : ce n'est pas du JSON"); return fail("Bon REFUSÉ : le chargeur n'accepte plus que du JSON pur, sans types.", "refusé : pas du JSON", "ok"); }
      const bad = o && typeof o === "object" ? Object.keys(o).filter(k => !["article", "quantite", "client"].includes(k)) : ["?"];
      if (bad.length) { x.jsonBlock = true; lb.type = String(o.type || "?"); tr.push(`✘ schéma : champ inattendu « ${bad[0]} »`); return fail(`Bon REFUSÉ par le schéma : le champ « ${bad[0]} » n'existe pas. En JSON pur, « type » n'est qu'une donnée : rien n'est instancié, rien ne s'exécute.`, "refusé par le schéma JSON", "ok"); }
      const q = o.quantite; if (typeof o.article !== "string" || !Number.isInteger(q) || q < 1 || q > 999) { tr.push("✘ schéma : article (texte) ou quantite (entier 1..999) invalide"); return fail("Bon REFUSÉ : article ou quantité invalide.", "refusé par le schéma JSON", "ok"); }
      tr.push("✔ JSON pur validé par le schéma (aucune classe en jeu)"); x.reg.push({ k: "commande", t: `${o.article} ×${q} (${o.client || "?"})` }); lb.type = "(données)"; lb.verdict = "accepté comme simple donnée"; lb.pass = true;
      if (!signed && !c.signature && q >= 100) x.forged = true;
      code(tr.join("\n")); out("Bon ACCEPTÉ comme simple donnée.", "ok");
      if (x.forged && q >= 100 && !signed) out(`Mais un bon de ${q} unités fabriqué par n'importe qui est accepté : un format pur ne dit pas QUI a émis le bon.`, "err");
      return true;
    }
    const f_ = {}; payload.split(";").forEach(p => { const j = p.indexOf("="); if (j > 0) f_[p.slice(0, j).trim()] = p.slice(j + 1).trim(); });
    const type = f_.type; lb.type = type || "?";
    if (!type) { tr.push("✘ champ type manquant"); return fail("Bon illisible : il manque le champ « type ». Exemple : type=Commande;article=ancre;quantite=3", "illisible"); }
    tr.push(`· champ type = « ${type} » : le chargeur va instancier cette classe`);
    if (c.liste) {
      if (!ALLOW.includes(type)) { x.listBlock = true; tr.push(`✘ liste blanche (${ALLOW.join(", ")}) : « ${type} » absente`); return fail(`Bon REFUSÉ : la classe « ${type} » n'est pas dans la liste blanche. Rien n'a été instancié.`, "refusé : classe hors liste blanche", "ok"); }
      tr.push(`✔ liste blanche : « ${type} » autorisée`);
    } else tr.push("· liste blanche : aucune (toute classe du serveur peut être instanciée)");
    if (!Object.prototype.hasOwnProperty.call(CLASSES, type)) { tr.push("✘ classe inconnue"); return fail(`Classe « ${type} » inconnue du serveur : erreur de chargement.`, "classe inconnue"); }
    try {
      const o = Object.assign({}, f_); delete o.type;
      const q = parseInt(o.quantite, 10);
      const msg = CLASSES[type](o, c);
      tr.push("→ " + msg);
      code(tr.join("\n"));
      lb.pass = true; lb.verdict = type === "Purge" ? "EXÉCUTÉ : registre effacé" : "accepté";
      if (type === "Purge") { out("Un simple texte venu de l'extérieur a fait exécuter une action destructrice sur le serveur. Le bon n'était pas une donnée : c'était un ordre.", "err"); note("deser"); fig("bon"); }
      else { out("Bon accepté.", "ok"); if (type === "Commande" && !signed && q >= 100) { x.forged = true; out(`Un bon de ${q} unités, fabriqué par n'importe qui, est accepté : la liste blanche limite les classes, pas les auteurs. Qui a émis ce bon ?`, "err"); } }
      return true;
    } catch (e) { return fail(e.message + ".", "refusé : " + (c.privilege ? "privilège insuffisant" : "erreur"), c.privilege ? "ok" : "err"); }
  }

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F(), c = x.c;
    if (!x.quest) return "quest";
    if (!x.saw) return "see";
    if (!(x.rce || c.contenu)) return "ext";
    if (!c.contenu) return "magic";
    if (!(x.rcePoly || c.stockage)) return "poly";
    if (!c.stockage) return "store";
    if (!(x.trav || c.nom)) return "trav";
    if (!c.nom) return "name";
    if (!(x.xss || c.domaine)) return "sniff";
    if (!c.domaine) return "domain";
    if (!(x.dos || c.limites)) return "dos";
    if (!c.limites) return "limites";
    if (!(x.bomb || c.decompression)) return "bomb";
    if (!c.decompression) return "decomp";
    if (!(x.avAttack || c.antivirus)) return "avatk";
    if (!c.antivirus) return "av";
    if (!(x.leak || c.metadonnees)) return "exifatk";
    if (!c.metadonnees) return "meta";
    if (!(x.purged || c.liste || c.json || c.signature)) return "purge";
    if (!c.liste) return "liste";
    if (!(x.forged || c.signature)) return "forge";
    if (!c.signature) return "sig";
    if (!c.json) return "json";
    if (!c.privilege) return "priv";
    if (!x.end) return "end";
    return "fin";
  };
  const goHall = "(au tableau de contrôles du hall)";
  const hints = {
    quest: () => ["Maître Ada attend dans le hall.", "`parler ada`"],
    see: () => ["Commence par un dépôt tout à fait honnête au guichet (est du hall), pour voir la chaîne de contrôles.", "`aller est`, `examiner sac`, puis `deposer photo.png image/png png`"],
    ext: () => ["Le guichet semble ne regarder que l'extension. Essaie un fichier .toy (un script de Mallory), puis cache-le derrière une extension autorisée.", "`deposer rapport.toy text/plain script` (refusé), puis `deposer rapport.toy.png image/png script` et `visiter`."],
    magic: () => ["Il faut que le serveur lise le contenu du fichier. Le tableau de contrôles est dans le hall.", "`aller ouest`, `activer contenu` (le rejeu est automatique). Puis `schema magiques`."],
    poly: () => ["Le contrôle d'en-tête est-il suffisant ? Fabrique un fichier qui commence comme un vrai PNG mais contient aussi un script.", "`aller est`, `deposer poly.toy.png image/png polyglot`, puis `visiter`."],
    store: () => ["Un fichier téléversé ne doit jamais pouvoir s'exécuter : change l'endroit et les droits. Tableau du hall.", `\`activer stockage\` ${goHall}.`],
    trav: () => F().c.stockage
      ? ["Même rangé ailleurs, le nom envoyé reste dangereux. Le chemin résolu sort-il du dossier /srv/colis ? Utilise le normaliseur de chemins pour compter les « .. » nécessaires, puis vise le logo du site (/var/www/public/img/logo.png).", "`resoudre /srv/colis ../../var/www/public/img/logo.png`, puis `deposer ../../var/www/public/img/logo.png image/png png` au guichet."]
      : ["Le serveur colle ton nom de fichier au dossier de dépôt. Que se passe-t-il avec des « ../ » dans le nom ? Vise le logo du site : /var/www/public/img/logo.png.", "`resoudre /var/www/public/uploads ../img/logo.png`, puis `deposer ../img/logo.png image/png png` au guichet."],
    name: () => ["Ne jamais se servir du nom envoyé : le serveur doit en fabriquer un.", `\`activer nom\` ${goHall}.`],
    sniff: () => ["Un dernier piège au guichet : un fichier qui est bien une image pour le serveur, mais qu'un navigateur affichera comme une page web si on le sert avec un type mensonger.", "`deposer carte.jpg text/html jpeghtml`, puis `visiter`."],
    domain: () => ["Il faut servir les colis depuis un autre domaine, en téléchargement forcé, sans que le navigateur devine le type.", `\`activer domaine\` ${goHall}.`],
    dos: () => ["Que se passe-t-il si on envoie des colis très gros, ou très nombreux ? Le disque du serveur fait 100 Mo.", "`deposer gros.png image/png gros x5` (5 × 25 Mo)."],
    limites: () => ["Il faut des limites de taille et de nombre.", `\`activer limites\` ${goHall}.`],
    bomb: () => ["Les limites de taille regardent la taille du fichier envoyé. Et une archive minuscule qui se déploie en gigantesques ?", "`deposer archive.zip application/zip bombe`."],
    decomp: () => ["Calcule le taux d'expansion avant d'ouvrir une archive.", `\`activer decompression\` ${goHall}.`],
    avatk: () => ["Un colis contient un logiciel piégé connu (signature de test fictive). Que devient-il ?", "`deposer facture.pdf application/pdf suspect`."],
    av: () => ["Il faut un analyseur et une quarantaine.", `\`activer antivirus\` ${goHall}. Optionnel : \`deposer facture2.pdf application/pdf suspect2\` pour voir ses limites.`],
    exifatk: () => ["Une photo de vacances de Bob risque de raconter plus que ce qu'on voit. Dépose-la puis ouvre-la.", "`deposer vacances.jpg image/jpeg gps`, puis `visiter`."],
    meta: () => ["Ré-encode les images pour ne garder que les pixels.", `\`activer metadonnees\` ${goHall}. Puis rejoue : \`deposer vacances.jpg image/jpeg gps\` et \`visiter\`.`],
    purge: () => ["Partie 2 : la salle des bons de commande (nord du hall). Envoie d'abord un bon normal, puis un bon dont le type est une classe interne.", "`aller nord`, `examiner modele`, `soumettre type=Commande;article=ancre;quantite=3`, puis `soumettre type=Purge;cible=registre`."],
    liste: () => ["Le chargeur n'a aucune raison d'instancier n'importe quelle classe.", `\`activer liste\` ${goHall}. Puis \`schema bon\`.`],
    forge: () => ["La liste blanche arrête les classes dangereuses. Mais qui peut fabriquer un bon « Commande » ? Essaie un bon énorme au nom d'Ada.", "`soumettre type=Commande;article=ancre;quantite=500;client=ada` (dans la salle des bons)."],
    sig: () => ["Il faut que seul le service d'émission puisse fabriquer des bons valides : signe-les.", `\`activer signature\` ${goHall}. Puis, dans la salle des bons : \`emettre type=Commande;article=ancre;quantite=3\` et \`soumettre\` le résultat, signature comprise.`],
    json: () => ["Mieux que filtrer les types : ne plus en avoir.", `\`activer json\` ${goHall}.`],
    priv: () => ["Dernière couche : si tout le reste cède, que le chargeur ne puisse rien détruire.", `\`activer privilege\` ${goHall}.`],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true; give("mandat");
          say("Maître Ada", "Notre guichet de réception accepte des colis, des fichiers, et des bons de commande, des objets sérialisés. Mallory y envoie depuis des semaines des choses qui n'ont rien d'un colis. J'ai besoin que tu comprennes comment elle passe, avec ce mandat écrit.");
          say("Maître Ada", "Tu auras un sac de fichiers de test au guichet (est), un plan du serveur à l'entrepôt (sud), un scanner au laboratoire (ouest), les bons de commande au nord. Et ici, le tableau de contrôles : c'est là que tu durcis, une fois la faille montrée. Tout est fictif. Mais on ne teste que ce qu'on a le droit de tester.");
          out("Tu as reçu un mandat d'audit (`examiner mandat`).", "sys");
        } else if (x.end) say("Maître Ada", "Le guichet est enfin à l'épreuve de Mallory. Merci.");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas terminé. `indice` si tu bloques, `controles` pour voir où tu en es.");
        break;
      case "bob": say("Bob", "Je tamponne, je range, je ne regarde pas dedans : c'est pas mon travail. Si c'est écrit .png, pour moi c'est une image. Et si le fichier dit lui-même ce qu'il est, pourquoi je ne le croirais pas ?"); break;
      case "alice": say("Alice", `Regarde le plan avec \`examiner arborescence\`. Tout ce qui est dans la racine web est servi tel quel à n'importe qui. Un fichier téléversé ne devrait jamais y atterrir. ${x.c.stockage ? "Depuis ton réglage, mes colis sont dans /srv/colis, droits 0640." : "Pour l'instant, je range dans uploads/, avec les droits 0755."}`); break;
      case "lovelace": say("Dame Lovelace", `Un antivirus reconnaît ce qu'il connaît : un fichier modifié d'un seul caractère peut lui échapper. Ré-encoder les images règle autre chose : les métadonnées et les octets greffés disparaissent. Compare sur \`examiner scanner\`. (Antivirus : ${x.c.antivirus ? "actif" : "éteint"}.)`); break;
      case "eve": say("Ève", "J'écoute tout ce qui passe dans la pneumatique. Ces bons, on dirait des objets qu'on recharge sans les relire : si le type dit « Purge », le serveur instancie Purge. Qui vérifie que c'est bien nous qui l'avons écrit ? " + (x.purged || (x.reg.length === 0) ? "Le registre est vide : `restaurer registre`." : "")); break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function cmdDeposit(c) {
    if (S.room !== "guichet") { out("Le guichet de dépôt est à l'est du hall.", "sys"); return; }
    const t = c.rawArg.trim().split(/\s+/).filter(Boolean);
    let n = 1; if (t.length && /^x\d+$/i.test(t[t.length - 1])) n = Math.min(+t.pop().slice(1), 1000);
    if (t.length < 3) { out("Syntaxe : `deposer ‹nom› ‹type› ‹contenu›` (ex. `deposer photo.png image/png png`). `examiner sac` liste les contenus.", "err"); return; }
    if (!KINDS[t[2].toLowerCase()]) { out(`Je n'ai pas de contenu « ${t[2]} » dans ton sac. Choisis parmi : ${Object.keys(KINDS).join(", ")}.`, "err"); return; }
    if (n < 1) n = 1;
    deposit(t[0], t[1], t[2].toLowerCase(), n);
  }
  function cmdVisit(c) {
    const x = F();
    if (S.room !== "guichet") { out("Les colis s'ouvrent depuis le guichet (est du hall).", "sys"); return; }
    const acc = x.files.filter(z => !z.q);
    if (!acc.length) { out("Aucun colis accepté pour l'instant : `deposer ‹nom› ‹type› ‹contenu›`.", "sys"); return; }
    const a = c.rawArg.trim();
    let fl = x.files[x.last];
    if (a) { fl = [...acc].reverse().find(z => z.name === a || z.stored === a || z.name.includes(a)); if (!fl) { out("Colis introuvables. Acceptés : " + acc.map(z => z.name).join(", ") + ".", "err"); return; } }
    visit(fl);
  }
  function cmdResolve(c) {
    const x = F(), t = c.rawArg.trim().split(/\s+/).filter(Boolean);
    if (!t.length || t.length > 2) { out("Syntaxe : `resoudre ‹chemin›` ou `resoudre ‹dossier› ‹nom›` (ex. `resoudre /var/www/public/uploads ../img/logo.png`).", "err"); return; }
    const full = t.length === 2 ? t[0] + "/" + t[1] : t[0];
    const r = normTrace(full);
    out(`Normaliseur de chemins : « ${full} »`, "sys");
    code(r.tr.map(s => `${s.seg.padEnd(10)} ${s.why.padEnd(16)} → ${s.st}`).join("\n") + "\nrésultat : " + r.res);
    const inside = t.length === 2 ? r.res.startsWith(t[0].replace(/\/+$/, "") + "/") : null;
    x.pf = { base: t.length === 2 ? t[0] : "", name: t.length === 2 ? t[1] : full, res: r.res, tr: r.tr, inside };
    if (inside === false) out("Le chemin résolu SORT du dossier prévu : un serveur qui colle le nom envoyé écrira là.", "err");
    else if (inside) out("Le chemin résolu reste dans le dossier.", "ok");
    note("chemin"); fig("chemin");
  }
  function cmdActivate(c) {
    const x = F();
    if (S.room !== "hall") { out("Le tableau de contrôles est dans le hall.", "sys"); return; }
    const t = norm(c.rawArg);
    if (!t) { out("Quel contrôle ?\n" + ctrlList(), "err"); return; }
    const id = CTRL_ORDER.find(i => CTRL.find(z => z[0] === i)[2].test(t));
    if (!id) { out("Je ne connais pas ce contrôle. Liste :\n" + ctrlList(), "err"); return; }
    if (x.c[id]) { out("Déjà actif.", "sys"); return; }
    x.c[id] = true;
    out(`Clac : « ${ctrlName(id)} » est maintenant actif.`, "ok");
    if (id === "json" || id === "liste" || id === "signature" || id === "privilege") { if (x.reg.length < 4) { x.reg = REG0(); out("Ève restaure le registre depuis la sauvegarde.", "sys"); } }
    const A = {
      contenu: () => { note("contenu"); out("Le serveur lit désormais les premiers octets et les compare à l'extension annoncée.", "ok"); fig("magiques"); replay(["rapport.toy.png", "image/png", "script"], false); },
      stockage: () => { note("stockage"); out("Les colis sont rangés dans /srv/colis (hors racine web), droits 0640 : lecture et écriture pour le serveur, aucune exécution.", "ok"); replay(["poly.toy.png", "image/png", "polyglot"], true); },
      nom: () => { note("chemin"); x.logo = "original"; out("Le serveur fabrique lui-même le nom (empreinte SHA-256 du contenu + compteur) avec une extension tirée de la liste blanche. Alice remet le logo d'origine en place.", "ok"); replay([x.c.stockage ? "../../var/www/public/img/logo.png" : "../img/logo.png", "image/png", "png"], false); },
      domaine: () => { note("stockage"); out("Les colis sont servis depuis colis-guilde.example, un domaine sans cookies, avec Content-Disposition: attachment, X-Content-Type-Options: nosniff, et un type décidé par le serveur d'après le contenu vérifié.", "ok"); replay(["carte.jpg", "text/html", "jpeghtml"], true); },
      limites: () => { note("taille"); out("Limites : 5 Mo par fichier, 10 fichiers par requête.", "ok"); replay(["gros.png", "image/png", "gros", 5], false); },
      decompression: () => { note("taille"); out("Avant d'ouvrir une archive, le serveur lit sa table et calcule taille décompressée ÷ taille compressée : refus au-delà de 100:1.", "ok"); fig("ratio"); replay(["archive.zip", "application/zip", "bombe"], false); },
      antivirus: () => { note("av"); out("Chaque colis est analysé ; ce qui porte une signature connue part dans /srv/quarantaine (droits 0000).", "ok"); replay(["facture.pdf", "application/pdf", "suspect"], false); },
      metadonnees: () => { note("meta"); out("Les images sont décodées puis ré-encodées : seuls les pixels sont conservés.", "ok"); replay(["vacances.jpg", "image/jpeg", "gps"], true); },
      liste: () => { note("deser"); note("liste"); out("Le chargeur n'instancie plus que Commande et Facture.", "ok"); replayBon("type=Purge;cible=registre"); fig("bon"); },
      signature: () => { note("deser"); note("liste"); out("Chaque bon doit porter une signature HMAC-SHA-256, calculée avec une clé que seul le service d'émission possède, et vérifiée AVANT toute lecture.", "ok"); replayBon("type=Commande;article=ancre;quantite=500;client=ada"); },
      json: () => { note("deser"); out("Les bons sont désormais du JSON pur : des valeurs, jamais des types ni des méthodes. Un schéma valide les champs.", "ok"); replayBon('{"type":"Purge","cible":"registre"}'); },
      privilege: () => { note("deser"); out("Le chargeur tourne désormais avec le compte svc-bons : lire et insérer, mais pas supprimer. (Pour la démonstration, on suppose que les autres couches ont cédé.)", "ok"); replayBon("type=Purge;cible=registre", { liste: false, signature: false, json: false }); },
    };
    A[id]();
    if (CTRL.every(([i]) => x.c[i])) out("Tous les contrôles sont actifs. `parler ada` pour rendre compte, si tu as tout testé.", "sys");
  }
  function replay(a, doVisit) {
    out("Rejeu automatique de l'attaque contre la nouvelle configuration :", "sys");
    const fl = deposit(a[0], a[1], a[2], a[3] || 1, true);
    if (fl && doVisit) visit(fl, true);
  }
  function replayBon(b, ov) {
    out("Rejeu automatique de l'attaque contre la nouvelle configuration :", "sys");
    out("> " + b, "sys"); loadBon(b, ov);
    if (F().reg.length === 0) F().reg = REG0();
  }
  function cmdBon(c) {
    if (S.room !== "bons") { out("La pneumatique des bons est dans la salle des bons de commande (nord du hall).", "sys"); return; }
    if (!c.rawArg.trim()) { out("Syntaxe : `soumettre ‹bon›`, ex. `soumettre type=Commande;article=ancre;quantite=3`.", "err"); return; }
    out("Le chargeur reçoit le bon et le recharge…", "sys");
    loadBon(c.rawArg);
  }
  function cmdIssue(c) {
    if (S.room !== "bons") { out("Le service d'émission est dans la salle des bons de commande.", "sys"); return; }
    const p = c.rawArg.trim(); if (!p) { out("Syntaxe : `emettre ‹bon›`, ex. `emettre type=Commande;article=ancre;quantite=3`.", "err"); return; }
    const s = hmacHex(SECRET, p);
    out("Le service d'émission (seul à connaître la clé) signe le bon : HMAC-SHA-256(clé, bon).", "sys");
    code(p + "#" + s); out("Soumets ce texte entier avec `soumettre ‹bon›#‹signature›`. Change une seule lettre du bon : la signature ne correspondra plus.", "sys");
  }

  const ending = () => {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Un fichier qui s'exécute, un nom qui s'échappe, une page qui vole une session, un disque rempli, un colis piégé, une photo qui dit où Bob dort, et un simple texte qui efface un registre. Tout ça, sans jamais forcer une porte. Et tu as montré comment fermer chacune.");
    note("deser"); debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  };
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le guichet et Bob = un formulaire de téléversement.** Bob croit ce qui est écrit sur l'étiquette : le nom du fichier et le type annoncé par le navigateur. Les deux sont choisis par l'envoyeur. Une double extension (rapport.toy.png) passe une liste blanche qui ne lit que la fin du nom.");
    out("**Le contrôle d'en-tête = les octets magiques.** Chaque format commence par une signature fixe (PNG, JPEG, PDF, ZIP). Lire ces octets prouve plus qu'une extension, mais un polyglotte (image valide + code) les passe : on ne s'arrête jamais là.");
    out("**../ dans le nom = traversée de chemin.** Le normaliseur a montré que « .. » remonte d'un dossier. La parade la plus sûre est de fabriquer le nom côté serveur et de ne jamais utiliser celui du client.");
    out("**L'entrepôt = stockage hors racine web, sans exécution, et un domaine séparé.** Un colis est une donnée : on le range là où le serveur ne l'exécute pas, et on le sert en téléchargement forcé (Content-Disposition), avec nosniff, depuis un domaine sans cookies de session.");
    out("**Les limites et le taux d'expansion = disponibilité.** Taille, nombre et quota empêchent de remplir le disque ; le taux d'expansion (ici 4 Go ÷ 42 Ko ≈ 95 000:1) détecte une bombe avant l'extraction.");
    out("**Le scanner et le ré-encodage = deux couches de plus.** L'antivirus par signatures isole le connu et rate les variantes. Le ré-encodage retire les métadonnées (position GPS) et tout ce qui est greffé à une image.");
    out("**Le bon « Purge » = désérialisation non fiable.** Le champ type désignait une classe, dont une méthode s'exécutait au chargement : le texte était un ordre. Défenses : format de données pur (JSON validé, sans types), liste blanche de classes, signature HMAC vérifiée avant de lire, compte à privilège minimal pour limiter les dégâts.");
    out("**Les simplifications du jeu.** (1) Tout est un jouet : « toy » n'est pas un vrai langage, la classe Purge et son action sont inventées, aucune charge utile réelle n'existe ici. (2) Les en-têtes magiques, le normaliseur de chemins, le SHA-256, le HMAC et le calcul du taux d'expansion sont, eux, réels. (3) Les métadonnées EXIF sont schématisées. (4) Les vrais serveurs ont d'autres pièges (types MIME exotiques, SVG, fichiers très imbriqués, race conditions) et d'autres défenses (analyse en bac à sable, quotas par utilisateur, journalisation). (5) Un audit réel exige toujours une autorisation écrite.");
    out("Rappel utile : **un fichier ou un objet reçu est une donnée non fiable : on vérifie son contenu, on ne se sert jamais de son nom, on ne l'exécute jamais, et on ne désérialise jamais un format qui instancie des types.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    chaine: () => {
      const c = F().c;
      const rows = [["limites", "Taille et nombre"], ["", "Extension (liste blanche)"], ["contenu", "Contenu (en-têtes magiques)"], ["decompression", "Taux d'expansion"], ["antivirus", "Antivirus, quarantaine"], ["metadonnees", "Ré-encodage des images"], ["nom", "Nom généré, chemin vérifié"], ["stockage", "Hors racine web, sans exécution"], ["domaine", "Domaine séparé, nosniff"]];
      let b = T(8, 16, "Un colis traverse la chaîne dans l'ordre", "f-s", "start");
      rows.forEach(([id, label], i) => {
        const on = id === "" ? true : !!c[id], y = 26 + i * 27;
        b += R(8, y, 404, 22, on ? "f-ok" : "f-bad") + T(18, y + 15, `${i + 1}. ${label}`, "", "start") + T(402, y + 15, on ? "actif" : "absent", on ? "ft-ok f-b" : "ft-bad f-b", "end");
      });
      return { cap: "Chaîne de contrôles d'un colis : vert = actif, rouge = absent. Un seul maillon manquant peut suffire à l'attaquant.", svg: SVG(278, "Chaîne de contrôles d'un colis", b) };
    },
    chemin: () => {
      const p = F().pf || (() => { const r = normTrace("/var/www/public/uploads/../img/logo.png"); return { base: "/var/www/public/uploads", name: "../img/logo.png", res: r.res, tr: r.tr, inside: false }; })();
      let b = T(8, 16, "dossier prévu : " + trunc(p.base || "(aucun)", 44), "f-s", "start") + T(8, 34, "nom envoyé : " + trunc(p.name, 46), "f-s", "start");
      const tr = p.tr.slice(-7);
      tr.forEach((s, i) => { const y = 54 + i * 22; b += R(8, y, 404, 18) + T(16, y + 13, esc(trunc(s.seg, 14)), "f-b f-s", "start") + T(120, y + 13, s.why, "f-s", "start") + T(404, y + 13, esc(trunc(s.st, 38)), "f-s", "end"); });
      const yy = 54 + tr.length * 22 + 8;
      b += R(8, yy, 404, 34, p.inside === false ? "f-bad" : "f-ok") + T(16, yy + 14, "résultat", "f-s", "start") + T(16, yy + 28, esc(trunc(p.res, 52)), "f-b " + (p.inside === false ? "ft-bad" : "ft-ok"), "start");
      b += T(404, yy + 14, p.inside === false ? "SORT du dossier" : p.inside ? "reste dans le dossier" : "", p.inside === false ? "ft-bad f-b f-s" : "ft-ok f-b f-s", "end");
      return { cap: "Chemin normalisé : chaque « .. » retire un dossier de la pile. Dernier chemin résolu (dépôt ou commande resoudre).", svg: SVG(yy + 46, "Chemin normalisé", b) };
    },
    magiques: () => ({
      cap: "Octets de tête de quatre formats. Un fichier qui commence par ces octets est probablement de ce format, mais rien n'interdit d'y ajouter autre chose à la suite.",
      svg: SVG(222, "En-têtes magiques",
        T(8, 16, "format", "f-s", "start") + T(90, 16, "octets de tête (hexadécimal)", "f-s", "start") + T(404, 16, "texte", "f-s", "end") +
        [["PNG", "89 50 4E 47 0D 0A 1A 0A", "‰PNG····"], ["JPEG", "FF D8 FF", "ÿØÿ"], ["PDF", "25 50 44 46 2D", "%PDF-"], ["ZIP", "50 4B 03 04", "PK··"]].map((r, i) => R(8, 24 + i * 30, 404, 24) + T(18, 40 + i * 30, r[0], "f-b", "start") + T(90, 40 + i * 30, r[1], "", "start") + T(404, 40 + i * 30, r[2], "f-s", "end")).join("") +
        R(8, 150, 404, 62, "f-bad") + T(16, 168, "Polyglotte : 89 50 4E 47 … suivi de &lt;?toy lire … ?&gt;", "ft-bad f-s", "start") + T(16, 186, "L'en-tête est celui d'un vrai PNG : le contrôle passe,", "f-s", "start") + T(16, 202, "mais le serveur lit aussi la suite comme un script.", "f-s", "start"))
    }),
    ratio: () => {
      const r = Math.round(KINDS.bombe.unc / KINDS.bombe.comp).toLocaleString("fr-FR"), r2 = Math.round(KINDS.zip.unc / KINDS.zip.comp * 10) / 10;
      return { cap: "Taux d'expansion = taille décompressée ÷ taille compressée. Une archive ordinaire reste proche de quelques unités ; la bombe dépasse tout seuil raisonnable.",
        svg: SVG(190, "Taux d'expansion d'une archive",
          T(8, 16, "archive ordinaire", "f-s", "start") + R(8, 24, 24, 16, "f-ok") + AR(36, 32, 70, 32) + R(74, 24, 60, 16, "f-ok") + T(150, 36, `12 Ko → 30 Ko : ${String(r2).replace(".", ",")}:1`, "ft-ok f-s", "start") +
          T(8, 78, "bombe de décompression", "f-s", "start") + R(8, 86, 24, 16, "f-bad") + AR(36, 94, 70, 94, "f-bad") + R(74, 86, 338, 16, "f-bad") + T(150, 114, `42 Ko → 4 Go : ${r}:1`, "ft-bad f-s f-b", "start") +
          T(8, 146, "règle : refuser AVANT d'extraire si le taux dépasse 100:1,", "f-s", "start") + T(8, 166, "et limiter taille totale, nombre de fichiers, profondeur.", "f-s", "start"))
      };
    },
    bon: () => {
      const x = F(), lb = x.lastBon || { type: "?", verdict: "aucun bon soumis", pass: false };
      let b = T(8, 16, "Dernier bon : type = " + esc(trunc(lb.type, 30)), "f-s f-b", "start") + T(8, 36, "liste blanche : " + (x.c.liste ? "ACTIVE" : "absente"), x.c.liste ? "ft-ok f-s" : "ft-bad f-s", "start");
      ["Commande", "Facture", "Purge"].forEach((n, i) => {
        const ok = ALLOW.includes(n), hit = lb.type === n;
        b += R(8 + i * 138, 46, 128, 40, ok ? "f-ok" : "f-bad") + T(72 + i * 138, 64, n, "f-b" + (hit ? " ft-bad" : "")) + T(72 + i * 138, 80, ok ? "autorisée ✔" : "interdite ✘", "f-s " + (ok ? "ft-ok" : "ft-bad"));
      });
      b += R(8, 100, 404, 38, lb.pass && lb.type === "Purge" ? "f-bad" : "") + T(16, 124, esc(trunc("verdict : " + (lb.verdict || "aucun"), 58)), lb.pass && lb.type === "Purge" ? "ft-bad f-b" : "f-b", "start");
      b += T(8, 160, "sans liste : le texte choisit la classe, et la classe s'exécute", "f-s", "start") + T(8, 178, "avec liste : seule une classe prévue peut être instanciée", "f-s", "start");
      return { cap: "Objet sérialisé piégé contre liste blanche : la classe désignée par le champ type est-elle autorisée ? Dernier bon soumis.", svg: SVG(192, "Objet sérialisé piégé et liste blanche", b) };
    },
  };

  GAMES.upload = {
    id: "upload", order: 36, title: "La Réception des Colis", pageTitle: "Upload Quest", subtitle: "aventure textuelle · téléversement de fichiers et désérialisation",
    blurb: "Teste puis durcis le guichet de la Guilde : fichiers piégés, noms qui s'échappent, objets sérialisés qui s'exécutent.",
    concept: "Téléversement de fichiers, désérialisation non fiable",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name); },
    figAlias: { chaine: ["controles", "colis"], chemin: ["normalis", "path", "traversee"], magiques: ["magique", "entete", "octets"], ratio: ["expansion", "decompression", "bombe"], bon: ["liste", "objet", "serialis"] },
    help: "Spécifiques : `deposer ‹nom› ‹type› ‹contenu› [xN]` · `visiter [nom]` · `resoudre ‹chemin›` · `activer ‹contrôle›` · `controles` · `soumettre ‹bon›` · `emettre ‹bon›` · `restaurer registre`",
    setup() { const x = F(); x.c = {}; x.files = []; x.logo = "original"; x.reg = REG0(); x.disk = 0; x.seq = 0; x.last = 0; },
    verbs: {
      deposit: { words: ["deposer", "televerser", "uploader"], run: cmdDeposit },
      visit: { words: ["visiter", "ouvrir", "telecharger"], run: cmdVisit },
      resolve: { words: ["resoudre", "normaliser", "chemin"], run: cmdResolve },
      activate: { words: ["activer", "installer", "basculer"], run: cmdActivate },
      ctrls: { words: ["controles", "statut", "etat"], run: () => { out("Contrôles du serveur :", "title"); code(ctrlList()); } },
      bon: { words: ["soumettre", "charger"], run: cmdBon },
      issue: { words: ["emettre", "emission"], run: cmdIssue },
      restore: { words: ["restaurer", "retablir"], run: () => { if (S.room !== "bons") { out("Le registre est dans la salle des bons de commande.", "sys"); return; } F().reg = REG0(); out("Ève remet le registre depuis la sauvegarde (4 entrées).", "ok"); } },
    },
    intro() {
      out("La Réception des Colis", "title");
      out("À Port-443, le guichet de réception de la Guilde accepte deux sortes de choses : des **colis** (des fichiers : photos, PDF, archives) et des **bons de commande** (des objets que le serveur recharge pour les exécuter). Depuis quelques semaines, Mallory y dépose des choses qui n'ont rien d'un colis.\nMaître Ada t'engage pour un **audit autorisé** : tu vas tester le guichet de ce serveur fictif, voir comment il se fait piéger, puis le durcir. Tout est simulé.", "");
    },
  };
})();
