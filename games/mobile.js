"use strict";
/* Le Téléphone Perdu : sécurité mobile (verrouillage et chiffrement, stockage sécurisé, permissions, TLS et épinglage,
   liens profonds, sauvegardes et captures, révocation côté serveur, MDM, magasin d'applications).
   SHA-256 réel du moteur ; « coffre matériel » simulé par un chiffrement par flux construit sur SHA-256 ; tout est fictif. */
(function () {
  const F = () => f();
  const HW = sha256("element-securise:lea");                 // secret gravé dans la puce (jamais exportable dans le jeu)
  const TOK = "gb1." + sha256("jeton:lea").slice(0, 24);
  const REF = "rf1." + sha256("refresh:lea").slice(0, 24);
  const IBAN = "FR7630001007941234567890185", IBAN_M = "FR7612345678901234567890666";
  const fIban = s => s.replace(/(.{4})/g, "$1 ").trim();
  const SEC = 0.08;                                           // calcul de clé matériel : ≈ 80 ms par essai de code
  const D30 = 30 * 86400;
  const nf = n => Math.round(n).toLocaleString("fr-FR");

  /* ---------- chiffrement par flux jouet (SHA-256 en mode compteur) ---------- */
  function stream(key, n) {
    const o = [];
    for (let c = 0; o.length < n; c++) { const h = sha256(key + "|" + c); for (let i = 0; i < 64 && o.length < n; i += 2) o.push(parseInt(h.substr(i, 2), 16)); }
    return o;
  }
  const encHex = (key, s) => { const m = Array.from(new TextEncoder().encode(s)), k = stream(key, m.length); return m.map((b, i) => (b ^ k[i]).toString(16).padStart(2, "0")).join(""); };

  /* ---------- verrouillage : énumération d'un code, délais croissants, effacement ---------- */
  const LV = { aucun: { d: 0, t: "aucun verrouillage" }, "4": { d: 4, t: "code à 4 chiffres" }, "6": { d: 6, t: "code à 6 chiffres" }, "8": { d: 8, t: "code à 8 chiffres" }, bio: { d: 6, t: "biométrie + code de secours à 6 chiffres" } };
  const PO = { libre: "essais libres (aucun délai)", delai: "délai croissant entre les essais", efface: "délai croissant + effacement après 10 échecs" };
  const PO_S = { libre: "essais libres", delai: "délai croissant", efface: "délai + effacement à 10" };
  const DELAYS = [0, 0, 0, 0, 60, 300, 900, 900, 3600];       // attente imposée après l'échec n°1 à 9, puis 3600 s ensuite
  function elapsed(N, pol) {                                  // temps nécessaire pour faire N essais
    let t = N * SEC; if (pol === "libre") return t;
    const fails = N - 1;
    for (let i = 1; i <= Math.min(fails, 9); i++) t += DELAYS[i - 1];
    if (fails > 9) t += (fails - 9) * 3600;
    return t;
  }
  function triesIn(T, pol) {
    if (pol === "libre") return Math.floor(T / SEC);
    let n = 1; while (n < 10 && elapsed(n + 1, pol) <= T) n++;
    if (n < 10) return n;
    return 10 + Math.floor((T - elapsed(10, pol)) / (3600 + SEC));
  }
  const maxTries = (T, pol) => pol === "efface" ? Math.min(triesIn(T, pol), 10) : triesIn(T, pol);
  const p30 = (d, pol) => Math.min(1, maxTries(D30, pol) / Math.pow(10, d));
  function worst(d, pol) { const N = Math.pow(10, d); if (pol === "efface") return N <= 10 ? elapsed(N, "delai") : Infinity; return elapsed(N, pol); }
  function dur(s) {
    if (!isFinite(s)) return "jamais";
    if (s < 1) return "moins d'une seconde";
    if (s < 120) return Math.round(s) + " s";
    if (s < 7200) return Math.round(s / 60) + " min";
    if (s < 172800) return Math.round(s / 3600) + " h";
    if (s < 86400 * 730) return nf(s / 86400) + " jours";
    return nf(s / 31557600) + " ans";
  }
  function pct(p) {
    if (p >= 0.01) return (p * 100).toFixed(1).replace(".", ",") + " %";
    if (p >= 0.001) return (p * 100).toFixed(2).replace(".", ",") + " %";
    return "1 chance sur " + nf(1 / p);
  }
  const col = p => p < 1e-4 ? "ok" : p < 1e-2 ? "mid" : "bad";

  /* ---------- stockage de l'appli ---------- */
  const exposed = () => {
    const x = F(), a = [];
    if (!x.stTok) a.push("le jeton de session et le jeton de rafraîchissement, en clair (session.xml)");
    if (!x.stDb) a.push("la base comptes.db : IBAN, soldes, opérations");
    if (!x.stLog) a.push("le journal debug.log, où le jeton est recopié à chaque requête");
    if (!x.stCache) a.push("le relevé de septembre laissé en cache");
    return a;
  };
  const sessionTxt = () => F().stTok
    ? "<map>\n  <string name=\"auth_token_enc\">keystore:gb_token_key:" + encHex(HW, TOK).slice(0, 36) + "…</string>\n  <string name=\"user\">lea.courriere</string>\n</map>"
    : "<map>\n  <string name=\"auth_token\">" + TOK + "</string>\n  <string name=\"refresh_token\">" + REF + "</string>\n  <string name=\"user\">lea.courriere</string>\n</map>";
  function dbTxt() {
    if (!F().stDb) return "SQLite format 3\ntable comptes     : id=1 · iban=" + fIban(IBAN) + " · solde=12480.00\ntable operations  : 2026-09-29 · -42.10 · BOULANGERIE DU PORT\n                    2026-09-27 · -1250.00 · LOYER 12 RUE DES TANNEURS";
    const h = encHex(HW + "|db", "SQLite format 3 comptes iban solde operations loyer".padEnd(48, ".")), L = [];
    for (let i = 0; i < 3; i++) L.push(("000" + (i * 16).toString(16)).slice(-4) + "  " + h.slice(i * 32, i * 32 + 32).replace(/(..)/g, "$1 ").trim());
    return L.join("\n") + "\n(aucune chaîne lisible : même l'en-tête SQLite est chiffré)";
  }
  const logTxt = () => F().stLog
    ? "09-30 13:41:07 I/Http: GET /v2/comptes 200 (118 ms)\n09-30 13:41:09 I/Http: GET /v2/operations 200 (96 ms)"
    : "09-30 13:41:07 D/Http: --> GET /v2/comptes\n09-30 13:41:07 D/Http: Authorization: Bearer " + TOK + "\n09-30 13:41:07 D/Http: <-- 200 {\"iban\":\"" + IBAN + "\"}";
  function treeTxt() {
    const x = F();
    return ["/data/data/fr.guilde.banque/",
      " ├─ shared_prefs/session.xml    " + (x.stTok ? "[chiffré, clé dans le coffre]" : "[JETON EN CLAIR]"),
      " ├─ databases/comptes.db        " + (x.stDb ? "[chiffrée]" : "[NON CHIFFRÉE]"),
      " ├─ files/debug.log             " + (x.stLog ? "[sans secret]" : "[CONTIENT LE JETON]"),
      " └─ cache/releve_09.pdf         " + (x.stCache ? "[purgé]" : "[relevé en cache]")].join("\n");
  }

  /* ---------- permissions ---------- */
  const TRACE = [[1, "12 rue des Tanneurs", 0], [3, "12 rue des Tanneurs", 0], [6, "12 rue des Tanneurs", 0], [7, "Gare de Port-443", 1], [9, "Guilde, rue des Coffres", 1], [12, "Café du Quai", 0], [15, "Clinique des Remparts", 0], [17, "Guilde, rue des Coffres", 1], [19, "Gare de Port-443", 1], [21, "12 rue des Tanneurs", 0], [23, "12 rue des Tanneurs", 0]];
  const CONTACTS = [["Ada", "Guilde"], ["Bob", "Guilde"], ["Maman", "famille"], ["Dr Perrin", "santé : cardiologue"], ["Me Duval", "juridique : avocat"], ["Alice", "amie"]];
  const SMS = ["Boulangerie du Port : votre commande est prête.", "BanqueGuilde : votre code de connexion est 482913 (valable 5 min). Ne le communiquez jamais.", "Ada : rendez-vous à 14 h, quai 4."];
  const mode = arr => { const c = {}; arr.forEach(a => c[a] = (c[a] || 0) + 1); const e = Object.entries(c).sort((a, b) => b[1] - a[1]); return e.length ? e[0] : null; };
  const permKey = t => /micro|audio|record/.test(t) ? "micro" : /contact/.test(t) ? "contacts" : /sms|message/.test(t) ? "sms" : /local|gps|position|location/.test(t) ? "loc" : /camera|photo/.test(t) ? "camera" : /internet|reseau/.test(t) ? "internet" : /bio/.test(t) ? "biometrie" : null;
  const permsOK = () => { const p = F().pm; return !p.micro && !p.contacts && !p.sms && p.loc !== "always"; };
  function manifestTxt() {
    const p = F().pm, st = v => v ? "accordée" : "RETIRÉE";
    return ["AndroidManifest.xml (fictif) · fr.guilde.banque",
      " INTERNET              " + st(p.internet).padEnd(14) + "API de la banque",
      " USE_BIOMETRIC         " + st(p.biometrie).padEnd(14) + "déverrouiller l'appli",
      " CAMERA                " + st(p.camera).padEnd(14) + "dépôt de chèque par photo",
      " RECORD_AUDIO          " + st(p.micro).padEnd(14) + "(aucune fonction ne l'utilise)",
      " READ_CONTACTS         " + st(p.contacts).padEnd(14) + "(aucune fonction ne l'utilise)",
      " READ_SMS              " + st(p.sms).padEnd(14) + "remplir le code de connexion",
      " ACCESS_FINE_LOCATION  " + (p.loc === "always" ? "en permanence" : p.loc === "use" ? "à l'usage, approx." : "RETIRÉE").padEnd(14) + "trouver une agence"].join("\n");
  }

  /* ---------- communications : certificats, validation, épinglage ---------- */
  const CERTS = {
    legitime: { n: "1", t: "le certificat légitime du serveur (2026)", cn: "api.banque.guilde", iss: "AC Port-443", key: "cle-banque-2026", mitm: false },
    inconnu: { n: "2", t: "un certificat signé par une AC inconnue", cn: "api.banque.guilde", iss: "AC Inconnue SARL", key: "cle-inconnue", mitm: true },
    autre: { n: "3", t: "un vrai certificat, mais pour un autre domaine", cn: "portail.cafegare.example", iss: "AC Port-443", key: "cle-cafe", mitm: true },
    boutique: { n: "4", t: "un certificat signé par l'AC « Boutique-WiFi », installée par le portail captif", cn: "api.banque.guilde", iss: "AC Boutique-WiFi", key: "cle-mallory", mitm: true },
    renouvele: { n: "5", t: "le certificat légitime renouvelé (2027, nouvelle clé)", cn: "api.banque.guilde", iss: "AC Port-443", key: "cle-banque-2027", mitm: false },
  };
  const TRUST = { "AC Port-443": true, "AC Boutique-WiFi": true, "AC Inconnue SARL": false };
  const spki = k => sha256("spki:" + k).slice(0, 12);
  const pinSet = () => { const p = F().net.pin; return p === "cle" ? [spki("cle-banque-2026")] : p === "secours" ? [spki("cle-banque-2026"), spki("cle-banque-2027")] : []; };
  const REQ = () => "GET /v2/comptes HTTP/1.1\nHost: api.banque.guilde\nAuthorization: Bearer " + TOK;
  const RESP = () => "{\"iban\":\"" + IBAN + "\",\"solde\":\"12480.00\"}";
  function checks(c) {
    const x = F(), r = [];
    r.push(["chaîne : l'émetteur « " + c.iss + " » est dans le magasin de confiance", TRUST[c.iss] === true]);
    r.push(["nom : le certificat est pour " + c.cn + " (attendu : api.banque.guilde)", c.cn === "api.banque.guilde"]);
    r.push(["validité : dates correctes", true]);
    if (x.net.pin !== "aucun") r.push(["épinglage : empreinte de clé " + spki(c.key) + " parmi " + pinSet().join(", "), pinSet().includes(spki(c.key))]);
    return r;
  }

  /* ---------- liens profonds ---------- */
  function parseLink(u) {
    const m = u.trim().match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#.*)?$/i);
    if (!m) return null;
    const q = {};
    (m[4] || "").split("&").filter(Boolean).forEach(p => { const i = p.indexOf("="), k = i < 0 ? p : p.slice(0, i), v = i < 0 ? "" : p.slice(i + 1); try { q[k] = decodeURIComponent(v); } catch (e) { q[k] = v; } });
    return { scheme: m[1].toLowerCase(), host: m[2].toLowerCase(), path: m[3], q };
  }
  const LINKS = [
    "guildebank://solde",
    "guildebank://virement?to=" + IBAN_M + "&montant=900&auto=1",
    "guildebank://web?url=https://portail-guilde.example/connexion",
    "https://banque.guilde/app/solde",
  ];
  function handleLink(raw) {
    const x = F(), L = x.lk, p = parseLink(raw);
    if (!p) return { r: "bad", t: "Ce n'est pas une URL (forme attendue : schéma://hôte/chemin?paramètres)." };
    let action;
    if (p.scheme === "guildebank") {
      if (L.verified) return { r: "blocked", t: "Schéma privé refusé : n'importe quelle appli installée peut déclarer « guildebank:// », donc l'appli n'accepte plus que les liens https vérifiés (fichier assetlinks.json prouvant que banque.guilde appartient à cette appli). Le lien légitime existe en https." };
      action = p.host;
    } else if (p.scheme === "https" && p.host === "banque.guilde" && p.path.indexOf("/app/") === 0) action = p.path.slice(5);
    else return { r: "ignored", t: "Ce lien ne vise pas l'application : le système l'ouvre ailleurs (navigateur)." };
    if (action === "solde") return { r: "safe", t: "L'appli ouvre l'écran Solde (après déverrouillage biométrique). Aucune action, aucun effet de bord : c'est le bon usage d'un lien profond." };
    if (action === "virement") {
      const to = p.q.to || "", mt = p.q.montant || "", auto = p.q.auto === "1";
      if (L.list) {
        if (!/^FR\d{2}[0-9A-Z]{23}$/.test(to)) return { r: "blocked", t: "Validation : « to » n'est pas un IBAN français valide (FR + 25 caractères). Lien rejeté." };
        if (!/^\d{1,5}(\.\d{1,2})?$/.test(mt) || Number(mt) <= 0 || Number(mt) > 5000) return { r: "blocked", t: "Validation : montant absent, non numérique ou au-delà du plafond. Lien rejeté." };
      }
      if (!L.confirm && auto) return { r: "vuln", t: "Le paramètre auto=1 est obéi : le virement de " + mt + " € vers " + fIban(to) + " est EXÉCUTÉ sans aucun écran de confirmation. Un simple lien (QR, SMS, page web) a suffi." };
      if (!L.confirm) return { r: "prefill", t: "L'écran de virement s'ouvre prérempli : rien n'est envoyé tant que Léa ne valide pas (mais le bénéficiaire prérempli peut passer inaperçu)." };
      return { r: "safe", t: "Écran de confirmation : « Virer " + mt + " € vers " + fIban(to) + " ? », bénéficiaire en clair, paramètre auto ignoré, validation par biométrie. Rien ne part sans le geste de Léa." };
    }
    if (action === "web") {
      const u = p.q.url || "";
      if (L.list) {
        const ok = /^https:\/\/banque\.guilde(\/|$)/.test(u);
        return ok ? { r: "safe", t: "Hôte autorisé (banque.guilde) : la page s'ouvre dans l'appli." } : { r: "blocked", t: "L'hôte n'est pas dans la liste autorisée (banque.guilde) : l'URL est refusée. Au mieux, elle serait ouverte dans le navigateur, hors de l'appli." };
      }
      return { r: "vuln", t: "L'appli charge n'importe quelle URL dans sa WebView : une fausse page de connexion s'affiche DANS l'appli de la banque, avec son cadre de confiance et ses ponts internes. Hameçonnage parfait." };
    }
    return L.list ? { r: "blocked", t: "Action « " + action + " » absente de la liste autorisée : ignorée." } : { r: "ignored", t: "Action inconnue : l'appli la transmet à un gestionnaire générique (comportement non prévu)." };
  }

  /* ---------- flotte (MDM) ---------- */
  const DEV = [["tel-bob", { d: 6, enc: true, patch: "2026-08", root: false }], ["tel-ada", { d: 8, enc: true, patch: "2026-09", root: false }],
    ["tel-ellie", { d: 4, enc: true, patch: "2025-11", root: false }], ["tel-max", { d: 6, enc: false, patch: "2026-07", root: true }], ["tel-sam", { d: 0, enc: false, patch: "2026-02", root: false }]];
  function fleet() {
    const x = F();
    return [["tel-lea", { d: LV[x.lvl].d, enc: x.enc, patch: x.st.upd ? "2026-09" : "2026-05", root: false }]].concat(DEV);
  }
  const RULES = { code: ["code ≥ 6 chiffres", d => d.d >= 6], chiffrement: ["stockage chiffré", d => d.enc], patch: ["correctifs ≥ 2026-06", d => d.patch >= "2026-06"], integrite: ["appareil non modifié", d => !d.root] };

  /* ---------- magasin ---------- */
  const OFFICIAL = sha256("cert:Guilde de Port-443").slice(0, 16);
  const STORE = [
    { id: 1, nom: "BanqueGuilde", ed: "Guilde de Port-443", inst: "1,2 million", src: "magasin officiel", age: "4 ans", perms: "caméra, biométrie, réseau", fp: OFFICIAL },
    { id: 2, nom: "BanqueGuilde Mobile", ed: "Guilde Bank Mobile Ltd", inst: "212", src: "magasin officiel", age: "6 jours", perms: "SMS, accessibilité, superposition d'écran, contacts", fp: sha256("cert:Guilde Bank Mobile Ltd").slice(0, 16) },
    { id: 3, nom: "BanqueGuilde-Pro.apk", ed: "inconnu (lien raccourci reçu par message)", inst: "?", src: "hors magasin (sources inconnues)", age: "hier", perms: "accessibilité, SMS, administrateur de l'appareil", fp: sha256("cert:inconnu").slice(0, 16) },
  ];

  /* ---------- carnet ---------- */
  const notes = {
    verrou: ["Verrouillage et chiffrement", "Un écran verrouillé ne protège rien si le stockage n'est pas chiffré : un outil de laboratoire lit la mémoire sans jamais demander le code. Avec le chiffrement, la clé dépend du code ET d'un secret de la puce : les essais se font sur l'appareil, au rythme du calcul de clé (ici ≈ 80 ms). Un code à 4 chiffres (10 000 possibilités) tombe en quelques minutes sans limite d'essais ; un délai croissant et surtout l'effacement après 10 échecs changent tout. La biométrie est une commodité : c'est le code de secours qui protège après un redémarrage."],
    stockage: ["Stockage sécurisé", "Jetons, clés et secrets ne vont pas en clair dans les préférences, une base ou un journal : n'importe quel accès aux fichiers (appareil modifié, malware, sauvegarde, trouveur) les lit. On les confie au coffre de clés (Android Keystore, iOS Keychain), idéalement matériel : la clé n'est jamais exportable, seule l'appli peut demander un déchiffrement, éventuellement après biométrie. Chiffrer aussi la base, ne jamais journaliser de secret. Ça protège contre la lecture des fichiers, pas contre une copie du jeton faite avant."],
    perms: ["Permissions : moindre privilège", "Chaque permission est une fenêtre sur la vie de l'utilisateur : micro (conversations), contacts (entourage, santé, justice), localisation continue (domicile, habitudes), SMS (codes à usage unique donc contournement du second facteur). On ne demande que ce qu'une fonction visible utilise, au moment de l'usage, avec la précision minimale. Les bibliothèques tierces héritent des permissions de l'appli."],
    tls: ["TLS et épinglage de certificat", "En clair, tout Wi-Fi public lit le jeton. Avec TLS, l'écoute passive ne voit que le nom du serveur et des tailles. Mais TLS fait confiance à toutes les autorités installées : un certificat d'une AC ajoutée par un portail captif, ou mal émise, est accepté. L'épinglage compare la clé publique du serveur à une empreinte prévue : le faux est refusé. Limites : un renouvellement avec une nouvelle clé coupe l'appli si aucune clé de secours n'est épinglée ; il faut épingler la clé (pas le certificat), prévoir clé de secours et rotation, et ne pas y voir une défense contre un appareil modifié."],
    liens: ["Liens profonds et intents", "Un lien profond (schéma privé ou lien https vérifié) déclenche une action dans l'appli, depuis une page, un QR, un SMS ou une autre appli. Ne jamais exécuter une action sensible sans confirmation explicite (et biométrie), valider chaque paramètre (format, plafond, liste d'hôtes autorisés), ignorer les paramètres inconnus, et préférer les liens vérifiés (App Links, Universal Links) aux schémas privés que n'importe quelle appli peut revendiquer."],
    sauvegardes: ["Sauvegardes et captures d'écran", "Les données sensibles fuient aussi par le côté : miniature de la tâche dans le sélecteur d'applications, captures d'écran et enregistrements, notifications lisibles sur l'écran verrouillé, sauvegardes cloud ou transferts d'appareil qui emportent bases et jetons. On masque les écrans sensibles (FLAG_SECURE, couverture à la mise en arrière-plan), on masque le contenu des notifications et on exclut les secrets de la sauvegarde."],
    revoc: ["Révocation côté serveur et liaison appareil/jeton", "Le téléphone n'est pas le seul endroit où vit un jeton : copies, sauvegardes, journaux. Quand l'appareil est perdu, l'effacement à distance est incertain (mode avion, éteint). Ce qui compte, c'est le serveur : révoquer les jetons de la session, imposer une nouvelle connexion avec second facteur, et lier chaque jeton à une clé non exportable de l'appareil (preuve de possession) pour qu'un jeton volé seul ne serve plus à rien."],
    mdm: ["Gestion de flotte (MDM) et intégrité", "Un MDM impose une base commune (code minimal, chiffrement, correctifs), localise, verrouille, efface (entièrement, ou seulement le conteneur professionnel sur un appareil personnel) et met en quarantaine l'appareil non conforme. L'attestation d'intégrité (appareil non modifié, système vérifié, signée par le matériel) détecte root ou jailbreak : c'est un signal que le serveur pèse, pas une preuve, et la détection s'use avec le temps."],
    magasin: ["Magasin d'applications et mises à jour", "Installe depuis le magasin officiel et vérifie l'éditeur, l'ancienneté, le nombre d'installations et les permissions demandées : les clones imitent le nom et l'icône, les APK hors magasin n'ont aucun contrôle. La signature de l'appli prouve l'éditeur. Les mises à jour (appli et système) corrigent des failles connues : les repousser, c'est rester vulnérable, et un serveur peut exiger une version minimale."],
  };

  /* ---------- objets ---------- */
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde. Elle tient une tablette où s'affiche le dossier « téléphone de Léa »." },
    lea: { npc: true, names: ["lea", "courriere"], label: "Léa, la courrière", desc: () => "Léa, courrière de la Guilde, mortifiée : son téléphone est resté sur la banquette du train de 14 h 07." },
    telephone: { names: ["telephone", "tel", "portable", "appareil"], label: "la copie d'analyse du téléphone de Léa", vis: () => S.room === "atelier",
      desc: () => { const x = F(); return "Une copie fictive de l'appareil de Léa, posée sur le banc.\n  Verrouillage : " + LV[x.lvl].t + "\n  Chiffrement du stockage : " + (x.enc ? "oui" : "non") + "\n  Essais de code : " + PO[x.pol] + "\n  Appli BanqueGuilde (fr.guilde.banque) installée.\n`trouveur` simule ce qu'obtient quelqu'un qui le ramasse ; `arbre` montre les fichiers de l'appli."; } },
    banc: { names: ["banc", "banc d analyse", "analyse"], label: "le banc d'analyse", vis: () => S.room === "atelier",
      desc: () => "Le banc d'analyse. Commandes : `verrou ‹aucun|4|6|8|bio›` · `chiffrer` · `essais ‹libre|delai|efface›` · `trouveur` · `arbre` · `ouvrir ‹fichier›` · `migrer ‹jeton|base›` · `purger ‹journal|cache›`." },
    manifeste: { names: ["manifeste", "manifest", "permissions"], label: "le manifeste de l'appli", vis: () => S.room === "comptoir",
      desc: () => manifestTxt() + "\n`reveler ‹permission›` · `retirer ‹permission›` · `limiter localisation`." },
    nuage: { names: ["nuage", "ecran", "tableau", "sauvegarde"], label: "le tableau des fuites latérales", vis: () => S.room === "comptoir",
      desc: () => "Trois commandes pour les fuites « par le côté » : `apercu` (miniature de la tâche), `sauvegarde` (contenu de la sauvegarde cloud), `proteger ‹apercu|sauvegarde|notifications›`." },
    borne: { names: ["borne", "wifi", "reseau", "point d acces"], label: "la borne « CafeGare-Gratuit »", vis: () => S.room === "cafe",
      desc: () => "La borne Wi-Fi ouverte du café. Mallory y a ajouté son propre point d'accès, de même nom. Commandes : `transport ‹http|tls›` · `ecouter` · `presenter ‹certificat›` · `epingler ‹cle|secours|aucun›`." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory", vis: () => S.room === "cafe", desc: () => "Mallory, capuche sur les yeux, un portable posé près de sa tasse. Son faux point d'accès clignote." },
    eve: { npc: true, names: ["eve"], label: "Ève", vis: () => S.room === "cafe", desc: () => "Ève, qui « écoute » (passivement) tout ce qui traverse le Wi-Fi du café." },
    affiche: { names: ["affiche", "qr", "liens"], label: "l'affiche aux QR codes", vis: () => S.room === "portail",
      desc: () => "Une affiche de QR codes collée par des inconnus. Chacun mène à un lien :\n  1 · " + LINKS[0] + "\n  2 · " + LINKS[1] + "\n  3 · " + LINKS[2] + "\n  4 · " + LINKS[3] + "\n`lien ‹numéro ou URL›` simule le clic dans l'appli ; `durcir ‹confirmation|liste|verifie›` la protège." },
    vitrine: { names: ["vitrine", "magasin", "boutique"], label: "la vitrine du magasin d'applications", vis: () => S.room === "portail",
      desc: () => "`magasin` liste les résultats d'une recherche « BanqueGuilde ». `comparer ‹n›` inspecte une fiche, `installer ‹n›` l'installe, `maj` applique les mises à jour en attente." },
    console: { names: ["console", "mdm", "tablette"], label: "la console de gestion de flotte", vis: () => S.room === "guichet",
      desc: () => "La console MDM de la Guilde. Commandes : `declarer perte` · `localiser` · `effacer` · `rejouer` · `lier` · `revoquer` · `integrite ‹sain|modifie›` · `flotte` · `exiger ‹code|chiffrement|patch|integrite›`." },
    bob: { npc: true, names: ["bob"], label: "Bob, administrateur du parc", vis: () => S.room === "guichet", desc: () => "Bob, qui gère les 6 téléphones de la Guilde et leurs mots de passe oubliés." },
  };

  const rooms = {
    quai: { name: "Le quai 4 de la gare de Port-443", short: "Quai", alias: ["quai", "gare"], ents: ["ada", "lea"], exits: { nord: "atelier", est: "cafe", ouest: "guichet", sud: "portail" },
      desc: () => "Le train de 14 h 07 est reparti sans le téléphone de Léa. Au nord, l'atelier d'analyse ; à l'est, le café de la gare et son Wi-Fi ; à l'ouest, le guichet de la flotte ; au sud, le portail des liens et du magasin d'applications." },
    atelier: { name: "L'atelier d'analyse de l'appareil", short: "Atelier", alias: ["atelier", "analyse"], ents: ["telephone", "banc"], exits: { sud: "quai", est: "comptoir" },
      desc: () => "Un banc d'établi, des câbles et la copie d'analyse du téléphone de Léa. À l'est, le comptoir des permissions." },
    comptoir: { name: "Le comptoir des permissions", short: "Comptoir", alias: ["comptoir", "permissions"], ents: ["manifeste", "nuage"], exits: { ouest: "atelier" },
      desc: () => "Un comptoir où s'étale le manifeste de l'appli : la liste de tout ce qu'elle a le droit de faire. Sur le côté, un tableau pour les fuites par les aperçus, les notifications et les sauvegardes." },
    cafe: { name: "Le café de la gare", short: "Café", alias: ["cafe"], ents: ["borne", "mallory", "eve"], exits: { ouest: "quai" },
      desc: () => "Odeur de café et Wi-Fi gratuit. Deux réseaux portent le même nom : la borne du patron et un petit boîtier posé par Mallory. Ève, à côté, écoute." },
    portail: { name: "Le portail des liens et du magasin", short: "Portail", alias: ["portail", "magasin"], ents: ["affiche", "vitrine"], exits: { nord: "quai" },
      desc: () => "Une arche de pierre : sur un mur une affiche de QR codes, sur l'autre une vitrine imitant un magasin d'applications." },
    guichet: { name: "Le guichet de la flotte", short: "Guichet", alias: ["guichet", "flotte"], ents: ["console", "bob"], exits: { est: "quai" },
      desc: () => "Le guichet où Bob gère les téléphones de la Guilde. Sa console de gestion s'allume en rouge dès qu'un appareil disparaît." },
  };

  /* ---------- objectifs et indices ---------- */
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.seenNone) return "look";
    if (!x.lockOK) return "lock";
    if (!(x.stTok && x.stDb && x.stLog)) return "store";
    if (!permsOK()) return "perm";
    if (!(x.pvApercu && x.pvSauv && x.pvNotif)) return "shots";
    if (!x.net.seen.http) return "net_a";
    if (x.net.mode !== "tls") return "net_b";
    if (!x.net.seen.rogue) return "net_c";
    if (x.net.pin === "aucun") return "net_d";
    if (!x.net.seen.refused) return "net_e";
    if (!x.net.seen.renewOk) return "net_f";
    if (!x.lk.seen.attack) return "lk_a";
    if (!(x.lk.confirm && x.lk.list && x.lk.verified)) return "lk_b";
    if (!x.lk.seen.retest) return "lk_c";
    if (!x.ls.declared) return "ls_a";
    if (!x.ls.r1) return "ls_b";
    if (!x.ls.wipeTried) return "ls_c";
    if (!x.srv.bound) return "ls_d";
    if (!x.srv.revoked) return "ls_e";
    if (!x.ls.rAfter) return "ls_f";
    if (!(x.md.seen.sain && x.md.seen.modifie)) return "md_a";
    if (!x.md.ok) return "md_b";
    if (!(x.st.seen.clone && x.st.seen.apk)) return "st_a";
    if (!x.st.upd) return "st_b";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend sur le quai.", "`parler ada`"],
    look: () => ["Va à l'atelier (nord) et regarde ce que le trouveur du téléphone obtient dans l'état actuel.", "`aller nord`, puis `trouveur`."],
    lock: () => ["Un verrou seul ne suffit pas : pense au chiffrement du stockage, à la longueur du code et à la limite d'essais. Relance `trouveur` après chaque réglage et compare la probabilité sur 30 jours.", "Par exemple `verrou 6`, `chiffrer`, `essais efface`, `trouveur`. Ou `verrou 8`, `chiffrer`, `essais delai`. Essaie aussi `verrou 4` pour voir la différence."],
    store: () => ["À l'atelier : regarde les fichiers de l'appli. Ce qui est en clair doit disparaître ou aller dans le coffre de clés.", "`arbre`, `ouvrir session.xml`, puis `migrer jeton`, `migrer base`, `purger journal`."],
    perm: () => ["Au comptoir des permissions (est de l'atelier) : qu'est-ce qu'aucune fonction n'utilise ? Et la localisation doit-elle être permanente ?", "`aller est`, `manifeste`, `reveler micro`, `retirer micro`, `retirer contacts`, `retirer sms`, `limiter localisation`."],
    shots: () => ["Toujours au comptoir : l'aperçu de la tâche, la sauvegarde cloud et les notifications laissent fuir des données.", "`apercu`, `sauvegarde`, puis `proteger apercu`, `proteger sauvegarde`, `proteger notifications`."],
    net_a: () => ["Va au café (est du quai) et regarde ce que voit Ève quand l'appli parle en HTTP.", "Depuis le comptoir : `aller ouest`, `aller sud`, `aller est`, puis `ecouter`."],
    net_b: () => ["Passe l'appli en TLS.", "`transport tls`"],
    net_c: () => ["Mallory présente un certificat signé par une AC installée sur le téléphone. Teste-le sans épinglage.", "`presenter boutique` (essaie aussi `presenter inconnu` et `presenter autre`)."],
    net_d: () => ["Épingle la clé du serveur dans l'appli.", "`epingler cle`"],
    net_e: () => ["Rejoue l'attaque de Mallory.", "`presenter boutique`"],
    net_f: () => ["Le serveur renouvelle son certificat avec une nouvelle clé. Que se passe-t-il ? Prévois une clé de secours.", "`presenter renouvele`, puis `epingler secours`, puis `presenter renouvele`."],
    lk_a: () => ["Va au portail (sud du quai) : un lien de l'affiche déclenche une action sans confirmation.", "`aller sud`, `examiner affiche`, `lien 2`."],
    lk_b: () => ["Protège l'appli de trois façons : confirmation, liste de valeurs autorisées et liens vérifiés.", "`durcir confirmation`, `durcir liste`, `durcir verifie`."],
    lk_c: () => ["Rejoue le lien malveillant.", "`lien 2` (et `lien 3`, `lien 4` pour comparer)."],
    ls_a: () => ["Va au guichet de la flotte (ouest du quai) et déclare la perte.", "`aller ouest`, `declarer perte`."],
    ls_b: () => ["Vois ce que Mallory peut faire avec le jeton qu'elle a copié avant le durcissement.", "`rejouer`"],
    ls_c: () => ["Tente l'effacement à distance : est-ce fiable ?", "`localiser`, `effacer`"],
    ls_d: () => ["Lie les jetons à l'appareil : un jeton volé seul ne doit plus suffire.", "`lier`"],
    ls_e: () => ["Invalide côté serveur tout ce qui existait.", "`revoquer`"],
    ls_f: () => ["Vérifie que le rejeu de Mallory échoue maintenant.", "`rejouer`"],
    md_a: () => ["Teste l'attestation d'intégrité sur un appareil sain puis sur un appareil modifié.", "`integrite sain`, `integrite modifie`."],
    md_b: () => ["Impose une base commune à toute la flotte, puis regarde qui est conforme.", "`exiger code`, `exiger chiffrement`, `exiger patch`, `exiger integrite`, puis `flotte`."],
    st_a: () => ["Va au portail et compare les fiches de la vitrine à la vraie appli.", "`aller est` (jusqu'au quai), `aller sud`, `magasin`, `comparer 2`, `comparer 3`."],
    st_b: () => ["Applique les mises à jour en attente.", "`maj`"],
    end: () => ["Rends compte à Maître Ada.", "`aller nord` (jusqu'au quai si besoin), `parler ada`"],
    fin: () => ["Audit terminé : relis ton carnet et les schémas.", "`carnet`, `analogies`"],
  };

  /* ---------- utilitaires de commandes ---------- */
  const need = (room, where) => { if (S.room === room) return true; out(where, "sys"); return false; };
  const NEED = { atelier: "Cela se fait à l'atelier (au nord du quai).", comptoir: "Cela se fait au comptoir des permissions (à l'est de l'atelier).", cafe: "Cela se fait au café de la gare (à l'est du quai).", portail: "Cela se fait au portail des liens et du magasin (au sud du quai).", guichet: "Cela se fait au guichet de la flotte (à l'ouest du quai)." };

  /* ---------- verrou, chiffrement, essais, trouveur ---------- */
  function lockCmd(c) {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), t = norm(c.rawArg);
    let k = null;
    if (!t) { out("Quel verrouillage ? `verrou aucun` · `verrou 4` · `verrou 6` · `verrou 8` · `verrou bio`", "err"); return; }
    if (/aucun|rien|sans/.test(t)) k = "aucun"; else if (/bio|empreinte|visage|doigt/.test(t)) k = "bio";
    else if (/\b4\b|court/.test(t)) k = "4"; else if (/\b6\b|moyen/.test(t)) k = "6"; else if (/\b8\b|long/.test(t)) k = "8";
    if (!k) { out("Je ne connais pas ce niveau. `verrou aucun`, `verrou 4`, `verrou 6`, `verrou 8` ou `verrou bio`.", "err"); return; }
    x.lvl = k;
    out("Verrouillage réglé sur : **" + LV[k].t + "**." + (k === "bio" ? " (La biométrie ouvre vite, mais le code de secours reste la vraie barrière.)" : ""), "ok");
    out("`trouveur` pour voir ce que cela change.", "sys");
  }
  function encCmd(c) {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), t = norm(c.rawArg);
    if (/non|desactiv|off/.test(t)) { x.enc = false; out("Chiffrement du stockage désactivé (vieux modèle, sans chiffrement intégré).", "err"); return; }
    x.enc = true;
    out("Chiffrement du stockage activé : les fichiers sont chiffrés avec une clé dérivée du code ET d'un secret gravé dans la puce.", "ok");
    if (x.lvl === "aucun") out("Attention : sans code, la clé est libérée automatiquement au démarrage. Le chiffrement existe, mais n'arrête personne : il faut aussi un code.", "err");
  }
  function polCmd(c) {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), t = norm(c.rawArg);
    const k = /libre|aucun|rien/.test(t) ? "libre" : /efface|wipe|dix|10/.test(t) ? "efface" : /delai|attente|croissant/.test(t) ? "delai" : null;
    if (!k) { out("Quelle politique d'essais ? `essais libre` · `essais delai` · `essais efface`", "err"); return; }
    x.pol = k;
    out("Politique d'essais : **" + PO[k] + "**.", "ok");
    if (k === "efface") out("Piège à connaître : un enfant qui s'amuse peut effacer l'appareil. Il faut des sauvegardes (chiffrées, sans secret) pour que l'effacement reste supportable.", "sys");
  }
  function finderCmd() {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), L = LV[x.lvl];
    out("Un trouveur ramasse le téléphone dans le train. Ce qu'il obtient :", "title");
    out("Réglages : **" + L.t + "** · chiffrement : **" + (x.enc ? "oui" : "non") + "** · essais : **" + PO[x.pol] + "**.");
    if (x.lvl !== "aucun") out(x.pvNotif ? "Écran verrouillé : le contenu des notifications est masqué." : "Écran verrouillé : les notifications affichent quand même leur contenu (« BanqueGuilde : votre code de connexion est 482913 »). Un code à usage unique lisible sans déverrouiller.", x.pvNotif ? "ok" : "err");
    if (x.lvl === "aucun") {
      x.seen.aucun = true; x.seenNone = true;
      out("Aucun verrou : l'écran s'ouvre d'un geste, l'appli bancaire est déjà connectée (jeton de session valide). Le trouveur peut tout lire et même tout dépenser dans la limite des plafonds.", "err");
      out("Et par câble, il lit : " + (exposed().join(" ; ") || "seulement des données chiffrées") + ".", "err");
    } else if (!x.enc) {
      x.seen.noenc = true;
      out("L'écran est verrouillé, mais le stockage n'est PAS chiffré : avec un outil de laboratoire qui lit directement la mémoire flash, le code n'est jamais demandé. Le verrou d'écran n'est qu'une porte posée dans un mur absent.", "err");
      out("Il lit : " + (exposed().join(" ; ") || "seulement des données chiffrées") + ".", "err");
    } else if (x.lvl !== "aucun") {
      x.seen.enc = true;
      out("Le stockage est chiffré avec une clé qui dépend de ton code ET d'un secret de la puce : impossible de deviner le code ailleurs que sur le téléphone, à environ 12,5 essais par seconde (calcul de clé ≈ " + Math.round(SEC * 1000) + " ms par essai).");
      if (x.pol !== "libre") out("Délais imposés après échecs : 1 à 4 échecs : aucun · 5 : 1 min · 6 : 5 min · 7 et 8 : 15 min · 9 : 1 h · ensuite 1 h par essai" + (x.pol === "efface" ? " · et à 10 échecs, effacement." : "."), "sys");
      [4, 6, 8].forEach(d => {
        const p = p30(d, x.pol), w = worst(d, x.pol);
        out("**" + d + " chiffres** (" + nf(Math.pow(10, d)) + " codes) · tout énumérer : " + (x.pol === "efface" ? "impossible (effacement après 10 essais)" : dur(w)) + " · réussite en 30 jours : " + pct(p) + (d === L.d ? "   ◀ ton code" : ""), d === L.d ? (col(p) === "ok" ? "ok" : "err") : "");
      });
      if (x.lvl === "bio") out("La biométrie : le trouveur ne peut pas la rejouer sans la personne. Mais après un redémarrage ou quelques échecs, seul le code de secours (6 chiffres ici) protège : c'est lui qu'on compare.", "sys");
      const p = p30(L.d, x.pol);
      if (col(p) === "ok") {
        out("Verdict : réussite en 30 jours de l'ordre de " + pct(p) + ". C'est un bon niveau : le trouveur n'obtient pas le contenu.", "ok");
        if (!x.lockOK) { x.lockOK = true; note("verrou"); fig("finder"); }
      } else out("Verdict : " + pct(p) + " de chances en 30 jours : " + (col(p) === "mid" ? "mieux, mais pas encore assez." : "bien trop pour un téléphone qui contient une appli bancaire.") + " (Chiffres du pire cas ; en moyenne, la moitié du temps.)", "err");
    }
    if (!S.figs.includes("finder")) fig("finder");
  }

  /* ---------- stockage ---------- */
  function treeCmd() {
    if (!need("atelier", NEED.atelier)) return;
    out("Arborescence de l'appli, telle que la voit quelqu'un qui peut lire les fichiers (trouveur sans verrou, appareil modifié, malware, sauvegarde) :", "sys");
    code(treeTxt());
    const e = exposed();
    out(e.length ? "Exposé : " + e.join(" ; ") + "." : "Plus rien d'exploitable en clair : données chiffrées, jeton dans le coffre.", e.length ? "err" : "ok");
  }
  function openCmd(c) {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), t = norm(c.rawArg);
    if (!t) { out("Quel fichier ? `ouvrir session.xml` · `ouvrir comptes.db` · `ouvrir debug.log` · `ouvrir releve.pdf` · `ouvrir cle`", "err"); return; }
    if (/session|pref|jeton|token|xml/.test(t)) { out("shared_prefs/session.xml, vu par un trouveur qui lit les fichiers :", "sys"); code(sessionTxt()); out(x.stTok ? "Du texte chiffré : sans la clé du coffre, rien d'exploitable." : "Le jeton est lisible tel quel : il suffit de le copier.", x.stTok ? "ok" : "err"); }
    else if (/compte|base|db|sql/.test(t)) { out("databases/comptes.db :", "sys"); code(dbTxt()); out(x.stDb ? "Base chiffrée." : "Base lisible par n'importe quel lecteur SQLite.", x.stDb ? "ok" : "err"); }
    else if (/log|journal|debug/.test(t)) { out("files/debug.log :", "sys"); code(logTxt()); out(x.stLog ? "Plus de secret dans le journal." : "Le jeton est recopié dans le journal (lisible via un rapport de bogue, par ADB en version de débogage, par une autre appli selon les versions).", x.stLog ? "ok" : "err"); }
    else if (/cache|releve|pdf/.test(t)) { out("cache/releve_09.pdf :", "sys"); code(x.stCache ? "(absent : purgé)" : "releve_09.pdf · 214 Ko · opérations de septembre, IBAN, nom du titulaire, en clair"); }
    else if (/cle|coffre|keystore|alias/.test(t)) { out("La clé n'est pas un fichier :", "sys"); code("Alias : gb_token_key\nAlgorithme : AES-256-GCM\nExportable : non\nUtilisation : authentification de l'utilisateur requise\nMatériel : élément sécurisé (StrongBox / Secure Enclave)"); out("On peut demander au coffre de déchiffrer, jamais de lui rendre la clé. " + (x.stTok ? "Le jeton de Léa est chiffré avec elle." : "Pour l'instant, rien n'est confié à cette clé : le jeton est resté en clair."), "sys"); }
    else out("Je ne trouve pas ce fichier. (session.xml, comptes.db, debug.log, releve.pdf, cle)", "err");
  }
  function migrateCmd(c) {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), t = norm(c.rawArg);
    if (/jeton|token|session|cle/.test(t)) {
      if (x.stTok) { out("Déjà fait.", "sys"); return; }
      out("Avant :", "sys"); code(sessionTxt());
      x.stTok = true;
      out("Après : l'appli demande au coffre matériel de chiffrer le jeton (clé non exportable, déverrouillée par la biométrie) et ne conserve que le texte chiffré :", "ok"); code(sessionTxt());
      out("Une copie du fichier ne sert plus à rien sans le coffre de CE téléphone. Mais attention : tout jeton copié AVANT reste valable côté serveur. On y reviendra au guichet.", "sys");
      note("stockage"); if (!S.figs.includes("arbre")) fig("arbre");
    } else if (/base|db|compte|sql/.test(t)) {
      if (x.stDb) { out("Déjà fait.", "sys"); return; }
      x.stDb = true;
      out("La base est ré-encapsulée avec un chiffrement intégral (type SQLCipher) dont la clé est gardée dans le coffre :", "ok"); code(dbTxt());
      if (!S.figs.includes("arbre")) fig("arbre");
    } else out("Que migrer ? `migrer jeton` ou `migrer base`. (Le journal se règle avec `purger journal`.)", "err");
    afterStore();
  }
  function purgeCmd(c) {
    if (!need("atelier", NEED.atelier)) return;
    const x = F(), t = norm(c.rawArg);
    if (/journal|log|debug/.test(t)) {
      if (x.stLog) { out("Déjà fait.", "sys"); return; }
      x.stLog = true; out("La journalisation ne recopie plus les en-têtes ni les corps de requête (et le niveau DEBUG est coupé dans la version publiée) :", "ok"); code(logTxt());
    } else if (/cache|releve|pdf/.test(t)) {
      if (x.stCache) { out("Déjà fait.", "sys"); return; }
      x.stCache = true; out("Le relevé n'est plus mis en cache en clair (il est vidé à la déconnexion). Bonne pratique : tout ce qui est sensible passe par le stockage chiffré.", "ok");
    } else { out("Que purger ? `purger journal` ou `purger cache`.", "err"); return; }
    afterStore();
  }
  function afterStore() { const x = F(); if (x.stTok && x.stDb && x.stLog && !x.stDone) { x.stDone = true; out("Dans le coffre, rien de lisible : l'arbre est propre. (`arbre` pour vérifier, `schema arbre` pour le comparatif.)", "ok"); fig("arbre"); } }

  /* ---------- permissions, aperçus, sauvegardes ---------- */
  function afterPerm() { const x = F(); if (permsOK() && !x.permDone) { x.permDone = true; note("perms"); fig("perms"); out("Moindre privilège respecté : il reste internet, la biométrie et la caméra (dépôt de chèque).", "ok"); } }
  function manifestCmd() { if (!need("comptoir", NEED.comptoir)) return; code(manifestTxt()); out("Pour chaque ligne : une fonction visible l'utilise-t-elle ? `reveler ‹permission›` montre ce qu'elle exposerait.", "sys"); }
  function revealCmd(c) {
    if (!need("comptoir", NEED.comptoir)) return;
    const x = F(), k = permKey(norm(c.rawArg));
    if (!k) { out("Quelle permission ? micro, contacts, sms, localisation, camera, internet ou biometrie : `reveler micro`", "err"); return; }
    x.rev[k] = true;
    if (k === "loc") {
      if (x.pm.loc === "off") { out("Permission retirée : l'appli ne reçoit aucune position (la recherche d'agence se fait par code postal).", "ok"); return; }
      const pts = x.pm.loc === "always" ? TRACE : TRACE.filter(t => t[2]);
      out(x.pm.loc === "always" ? "Localisation en continu : voici ce que reçoit l'appli (et tout composant tiers qui s'y trouve) sur une journée :" : "Localisation à l'usage, approximative (~3 km) : seuls les moments où l'appli est ouverte :", "sys");
      code(pts.map(p => String(p[0]).padStart(2, "0") + " h  " + (x.pm.loc === "always" ? p[1] : "secteur de Port-443")).join("\n"));
      const nuit = mode(pts.filter(p => p[0] >= 22 || p[0] < 6).map(p => p[1])), travail = mode(pts.filter(p => p[0] >= 9 && p[0] <= 17).map(p => p[1])), sens = pts.filter(p => p[1] === "Clinique des Remparts");
      if (x.pm.loc === "always") {
        out("Déduit sans effort : domicile = **" + nuit[0] + "** (" + nuit[1] + " relevés de nuit) ; travail = **" + travail[0] + "** ; trajets quotidiens ; lieu sensible : " + (sens.length ? "**Clinique des Remparts** à 15 h (santé)." : "aucun.") + " Pour une appli de banque qui veut juste « l'agence la plus proche ».", "err");
      } else out("Déduit : aucun domicile identifiable (aucun relevé nocturne), aucun lieu sensible, une journée réduite à 4 points flous. C'est suffisant pour « l'agence la plus proche ».", "ok");
    } else if (k === "micro") {
      const mo = 16000 * 2 * 3600 / 1e6;
      out("RECORD_AUDIO : un code malveillant (ou une bibliothèque publicitaire) pourrait capter l'ambiance : des réunions de la Guilde, des appels. Un échantillonnage 16 kHz sur 16 bits fait 32 Ko/s, soit " + mo.toFixed(1).replace(".", ",") + " Mo par heure d'écoute à envoyer discrètement. Aucune fonction de l'appli bancaire n'en a besoin.", x.pm.micro ? "err" : "ok");
    } else if (k === "contacts") {
      const sens = CONTACTS.filter(c => /santé|juridique/.test(c[1]));
      out("READ_CONTACTS : l'appli lit " + CONTACTS.length + " contacts : " + CONTACTS.map(c => c[0] + " (" + c[1] + ")").join(", ") + ". Dont " + sens.length + " révélant santé ou justice, et tous utilisables pour des messages d'hameçonnage crédibles envoyés à ses proches.", x.pm.contacts ? "err" : "ok");
    } else if (k === "sms") {
      const otp = SMS.map(s => s.match(/\b(\d{6})\b/)).filter(Boolean)[0];
      out("READ_SMS : l'appli lit toute la boîte de réception :", "sys"); code(SMS.map(s => "· " + s).join("\n"));
      out("Elle y trouve le code **" + (otp ? otp[1] : "?") + "**. Quiconque obtient cette permission lit les codes à usage unique de TOUS les services : le second facteur par SMS devient inutile. Mieux : l'API de récupération de SMS ou le collage assisté, sans permission large.", x.pm.sms ? "err" : "ok");
    } else if (k === "camera") out("CAMERA : nécessaire pour photographier un chèque, uniquement pendant l'utilisation (le système affiche un indicateur). À garder, mais jamais « en arrière-plan ».", "ok");
    else if (k === "internet") out("INTERNET : l'appli parle à la banque. Nécessaire. (Mais c'est aussi par là que sortirait tout ce qu'une permission excessive aurait collecté.)", "ok");
    else out("USE_BIOMETRIC : demande au système de vérifier l'utilisateur ; l'appli ne reçoit jamais l'empreinte, seulement un « oui » ou « non ». Nécessaire.", "ok");
  }
  function retireCmd(c) {
    if (!need("comptoir", NEED.comptoir)) return;
    const x = F(), k = permKey(norm(c.rawArg));
    if (!k) { out("Quelle permission retirer ? `retirer micro`, `retirer contacts`, `retirer sms`, `retirer localisation`…", "err"); return; }
    if (k === "camera" || k === "internet" || k === "biometrie") {
      out("Léa s'inquiète : « Sans ça, " + (k === "camera" ? "je ne peux plus déposer de chèque" : k === "internet" ? "l'appli ne peut plus joindre la banque" : "je ne peux plus me connecter") + ". » Moindre privilège ne veut pas dire zéro privilège : la permission est rétablie.", "err"); return;
    }
    if (k === "loc") { x.pm.loc = "off"; out("Localisation retirée. La recherche d'agence se fera par code postal.", "ok"); }
    else if (!x.pm[k]) { out("Déjà retirée.", "sys"); return; }
    else { x.pm[k] = false; out("Permission " + (k === "micro" ? "RECORD_AUDIO" : k === "contacts" ? "READ_CONTACTS" : "READ_SMS") + " retirée. " + (k === "sms" ? "Le code de connexion sera saisi ou collé, ou lu par l'API de récupération de SMS sans permission." : "Aucune fonction visible n'en dépendait."), "ok"); }
    afterPerm();
  }
  function limitCmd(c) {
    if (!need("comptoir", NEED.comptoir)) return;
    const x = F();
    if (permKey(norm(c.rawArg)) !== "loc") { out("Seule la localisation se limite : `limiter localisation`.", "err"); return; }
    x.pm.loc = "use"; out("Localisation limitée : seulement pendant l'utilisation et approximative (~3 km), pas précise ni permanente.", "ok"); afterPerm();
  }
  function apercuCmd() {
    if (!need("comptoir", NEED.comptoir)) return;
    const x = F();
    out("Le sélecteur d'applications (vue des tâches) affiche une miniature de l'écran de chaque appli à son dernier état :", "sys");
    if (!x.pvApercu) { code("┌ BanqueGuilde ─────────────────────\n│ Solde : 12 480,00 €\n│ IBAN : " + fIban(IBAN) + "\n│ Dernière opération : LOYER -1 250,00 €\n└───────────────────────────────────"); out("La miniature est stockée par le système, visible par quiconque ouvre le sélecteur (même téléphone verrouillé sur certains modèles), capturée par un enregistreur d'écran ou une capture d'écran.", "err"); }
    else { code("┌ BanqueGuilde ─────────────────────\n│ [écran masqué par l'application]\n└───────────────────────────────────"); out("Écran sécurisé : miniature vide, captures et enregistrements bloqués dans cette appli.", "ok"); }
  }
  function backupCmd() {
    if (!need("comptoir", NEED.comptoir)) return;
    const x = F();
    out("Sauvegarde cloud automatique du 30/09 (ce qui part chez le fournisseur, et se restaure sur un autre téléphone) :", "sys");
    if (x.pvSauv) { code("shared_prefs/prefs_ui.xml        1 Ko   (préférences d'affichage)\n[exclus : session.xml, comptes.db, debug.log, cache/]"); out("Les règles d'exclusion laissent partir les préférences d'affichage, pas les secrets.", "ok"); return; }
    code("shared_prefs/session.xml     2 Ko   " + (x.stTok ? "(chiffré : inutile hors de ce téléphone)" : "JETON EN CLAIR") + "\ndatabases/comptes.db      380 Ko  " + (x.stDb ? "(chiffrée)" : "BASE EN CLAIR") + "\nfiles/debug.log           12 Ko   " + (x.stLog ? "(sans secret)" : "CONTIENT LE JETON"));
    out(x.stTok && x.stDb && x.stLog ? "Grâce au coffre, la sauvegarde n'emporte que du chiffré (les clés matérielles ne se restaurent pas ailleurs). Mieux vaut quand même ne pas l'y mettre : `proteger sauvegarde`." : "Quiconque accède au compte cloud de Léa (mot de passe réutilisé, hameçonnage) ou restaure la sauvegarde sur son propre téléphone récupère le jeton et la base.", x.stTok && x.stDb && x.stLog ? "sys" : "err");
  }
  function protectCmd(c) {
    if (!need("comptoir", NEED.comptoir)) return;
    const x = F(), t = norm(c.rawArg);
    if (/apercu|ecran|capture|tache/.test(t)) { if (x.pvApercu) { out("Déjà fait.", "sys"); return; } x.pvApercu = true; out("Écran de l'appli marqué sécurisé (FLAG_SECURE sous Android ; sous iOS, une vue de couverture au passage en arrière-plan) : plus de miniature, captures bloquées. Compromis : Léa ne pourra plus faire de capture pour le support.", "ok"); }
    else if (/sauv|backup|nuage|cloud/.test(t)) { if (x.pvSauv) { out("Déjà fait.", "sys"); return; } x.pvSauv = true; out("Règles de sauvegarde ajoutées : session.xml, comptes.db, journal et cache exclus (sauvegarde cloud et transfert d'appareil).", "ok"); }
    else if (/notif/.test(t)) { if (x.pvNotif) { out("Déjà fait.", "sys"); return; } x.pvNotif = true; out("Les notifications de l'appli passent en « contenu masqué sur l'écran verrouillé » (visibilité privée) : « Nouvelle notification », sans le code.", "ok"); }
    else { out("Que protéger ? `proteger apercu` · `proteger sauvegarde` · `proteger notifications`", "err"); return; }
    if (x.pvApercu && x.pvSauv && x.pvNotif && !x.shotsDone) { x.shotsDone = true; note("sauvegardes"); out("Les fuites latérales sont bouchées.", "ok"); }
  }

  /* ---------- communications ---------- */
  function transportCmd(c) {
    if (!need("cafe", NEED.cafe)) return;
    const x = F(), t = norm(c.rawArg);
    if (/tls|https|chiffre/.test(t)) {
      if (!x.net.seen.http) { say("Ève", "Regarde d'abord ce que je lis en clair : `ecouter`."); return; }
      x.net.mode = "tls"; out("L'appli parle désormais en HTTPS (TLS) : le trafic est chiffré et le serveur doit présenter un certificat.", "ok");
    } else if (/http|clair/.test(t)) { x.net.mode = "http"; out("Retour au HTTP en clair (un mauvais choix : voir `ecouter`).", "err"); }
    else out("`transport http` ou `transport tls`.", "err");
  }
  function listenCmd() {
    if (!need("cafe", NEED.cafe)) return;
    const x = F(), n = x.net;
    if (n.mode === "http") {
      n.seen.http = true;
      out("Ève, simple oreille posée sur le Wi-Fi du café, lit ceci (rien n'est chiffré) :", "err"); code(REQ() + "\n\n" + RESP());
      out("Le jeton, l'IBAN, le solde : tout. Sans le moindre piratage, par simple écoute.", "err");
    } else {
      const rq = REQ().length + 29, rs = RESP().length + 45;
      out("Ève écoute le même trafic, en TLS :", "sys"); code("TLS 1.3 · SNI : api.banque.guilde\nenregistrements chiffrés : " + rq + " octets (requête), " + rs + " octets (réponse)\ncontenu : illisible");
      out("Ève apprend seulement avec quel serveur, quand, et combien d'octets. Mais un attaquant actif (Mallory) peut tenter de se faire passer pour le serveur : `presenter ‹certificat›`.", "ok");
    }
  }
  function presentCmd(c) {
    if (!need("cafe", NEED.cafe)) return;
    const x = F(), t = norm(c.rawArg);
    if (!t) { out("Mallory a plusieurs certificats en réserve :\n" + Object.values(CERTS).map(k => "  " + k.n + " · " + k.t).join("\n") + "\n`presenter ‹nom ou numéro›` : legitime, inconnu, autre, boutique, renouvele.", "sys"); return; }
    const key = /legit|^1$/.test(t) ? "legitime" : /inconnu|^2$/.test(t) ? "inconnu" : /autre|domaine|^3$/.test(t) ? "autre" : /boutique|wifi|^4$/.test(t) ? "boutique" : /renouv|nouveau|^5$/.test(t) ? "renouvele" : null;
    if (!key) { out("Je ne connais pas ce certificat. `presenter` sans argument les liste.", "err"); return; }
    if (x.net.mode === "http") { out("Pas de TLS : il n'y a pas de certificat à présenter ni à vérifier, donc rien à tromper. Mallory n'a même pas besoin de se déguiser. (`transport tls` d'abord.)", "sys"); return; }
    const k = CERTS[key], ch = checks(k), ok = ch.every(a => a[1]);
    out("Le téléphone se connecte à « api.banque.guilde » et reçoit " + k.t + ". Vérifications de l'appli :", "sys");
    code(ch.map(a => (a[1] ? "✓ " : "✗ ") + a[0]).join("\n"));
    x.net.last = { t: k.t, ok, key };
    if (ok && k.mitm) {
      out("ACCEPTÉ : Mallory se place au milieu, déchiffre, lit, rechiffre. L'appli ne voit rien, le cadenas est vert.", "err"); code("Ce que lit Mallory :\n" + REQ());
      if (!x.net.seen.rogue && key === "boutique") { x.net.seen.rogue = true; fig("pin"); }
    } else if (ok) out("Accepté : c'est bien le serveur, la connexion est normale.", "ok");
    else if (k.mitm) {
      const por = ch.slice(0, 3).every(a => a[1]);
      out("REFUSÉ : l'attaque échoue" + (por && x.net.pin !== "aucun" ? " : le certificat passait la validation habituelle, mais sa clé n'est pas celle épinglée." : "."), "ok");
      if (key === "boutique" && x.net.pin !== "aucun" && !x.net.seen.refused) { x.net.seen.refused = true; note("tls"); }
    } else {
      out("REFUSÉ… alors que c'est le VRAI serveur : il a renouvelé son certificat avec une nouvelle clé, que l'appli n'a jamais vue. Tous les clients à jour de l'appli sont coupés, et ils ne peuvent même plus télécharger la correction par l'appli.", "err");
      x.net.seen.renewKo = true;
      out("Épingler une seule clé sans plan de rotation est une panne programmée. Il faut épingler aussi une clé de secours générée à l'avance : `epingler secours`.", "sys");
    }
    if (key === "renouvele" && ok && x.net.pin === "secours") { x.net.seen.renewOk = true; out("La clé 2027 était épinglée en secours : le renouvellement passe sans incident, et la clé 2026 pourra être retirée à la prochaine version de l'appli.", "ok"); if (!x.net.seen.refused) note("tls"); }
  }
  function pinCmd(c) {
    if (!need("cafe", NEED.cafe)) return;
    const x = F(), t = norm(c.rawArg);
    if (!x.net.seen.rogue) { say("Ève", "Avant d'épingler, vois pourquoi : essaie `presenter boutique` en TLS."); return; }
    if (/aucun|retirer|non/.test(t)) { x.net.pin = "aucun"; out("Épinglage retiré : l'appli ne fait plus confiance qu'au magasin de confiance du système.", "err"); }
    else if (/secours|backup|deux/.test(t)) { x.net.pin = "secours"; out("Épinglage de DEUX clés publiques : la clé courante (2026) et une clé de secours (2027) générée à l'avance et conservée hors ligne. On épingle l'empreinte de la clé publique (SPKI), pas le certificat.", "ok"); code("épinglage : " + pinSet().join(" , ")); }
    else if (/cle|key|simple|un/.test(t)) { x.net.pin = "cle"; out("Épinglage de la clé publique courante :", "ok"); code("épinglage : " + pinSet().join(" , ")); out("Relance `presenter boutique`.", "sys"); }
    else out("`epingler cle` · `epingler secours` · `epingler aucun`", "err");
  }

  /* ---------- liens profonds ---------- */
  function linkCmd(c) {
    if (!need("portail", NEED.portail)) return;
    const x = F(), L = x.lk, a = c.rawArg.trim();
    if (!a) { out("`lien ‹numéro ou URL›` (voir l'affiche).", "err"); return; }
    const url = /^[1-4]$/.test(a) ? LINKS[Number(a) - 1] : a;
    out("Clic sur : " + url, "sys");
    const r = handleLink(url);
    out(r.t, r.r === "vuln" ? "err" : r.r === "blocked" || r.r === "safe" ? "ok" : "sys");
    if (r.r === "vuln" && /virement/.test(url)) { if (!L.seen.attack) { L.seen.attack = true; out("Ada, par-dessus ton épaule : « Voilà le défaut : un lien peut déclencher une action sensible. Protège l'appli : `durcir confirmation`, `durcir liste`, `durcir verifie`. »", "sys"); } }
    if (/virement/.test(url) && /to=FR7612345678901234567890666/.test(url) && L.confirm && L.list && L.verified && (r.r === "blocked")) { if (!L.seen.retest) { L.seen.retest = true; note("liens"); } }
  }
  function hardenCmd(c) {
    if (!need("portail", NEED.portail)) return;
    const x = F(), L = x.lk, t = norm(c.rawArg);
    if (!L.seen.attack) { say("Ada", "Vois d'abord le problème : `lien 2`."); return; }
    if (/confirm/.test(t)) { L.confirm = true; out("Actions sensibles : écran de confirmation obligatoire (bénéficiaire et montant en clair) et biométrie. Les paramètres comme auto=1 sont ignorés.", "ok"); }
    else if (/liste|valid|blanche/.test(t)) { L.list = true; out("Validation : actions autorisées en liste fermée, IBAN et montant contrôlés (format, plafond), hôtes web limités à banque.guilde, paramètres inconnus ignorés.", "ok"); }
    else if (/verifi|https|app link|applink/.test(t)) { L.verified = true; out("Seuls les liens https vérifiés (https://banque.guilde/app/…, prouvés par assetlinks.json) sont acceptés. Les schémas privés ne le sont plus : plus personne ne peut les revendiquer à la place de l'appli.", "ok"); }
    else { out("`durcir confirmation` · `durcir liste` · `durcir verifie`", "err"); return; }
    if (L.confirm && L.list && L.verified) out("Les trois protections sont en place : `lien 2` pour rejouer l'attaque (et `lien 1` pour voir l'effet sur l'ancien lien).", "sys");
  }

  /* ---------- perte, flotte, magasin ---------- */
  function declareCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(), ls = x.ls;
    if (ls.declared) { out("Déjà déclarée. `rejouer`, `localiser`, `effacer`, `lier`, `revoquer`.", "sys"); return; }
    ls.declared = true;
    out("Perte déclarée à 14 h 19, soit 12 minutes après la perte. Journal du serveur pour le compte de Léa :", "sys");
    code("14:07  dernière activité du téléphone (gare de Port-443-Nord)\n14:11  GET /v2/comptes             jeton gb1…  IP 203.0.113.77  (inconnue)\n14:12  GET /v2/beneficiaires       jeton gb1…  IP 203.0.113.77\n14:19  déclaration de perte");
    out("Quelqu'un utilise déjà le jeton de Léa depuis une autre adresse : Mallory a copié le fichier de session dans les minutes où le téléphone n'avait pas de verrou. Le coffre que tu as installé n'invalide pas cette copie. Cycle de perte : détecter, localiser, tenter l'effacement, révoquer côté serveur.", "err");
    fig("perte");
  }
  function locateCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(); if (!x.ls.declared) { out("Déclare d'abord la perte : `declarer perte`.", "sys"); return; }
    x.ls.located = true;
    out("Dernière position connue : train 7132, 14 h 09, gare de Port-443-Nord. Depuis : hors ligne (le trouveur a activé le mode avion depuis l'écran verrouillé). Le mode « perdu » (message sur l'écran de verrouillage) et l'effacement ne s'exécuteront qu'à la prochaine connexion.", "err");
  }
  function wipeCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(); if (!x.ls.declared) { out("Déclare d'abord la perte : `declarer perte`.", "sys"); return; }
    x.ls.wipeTried = true;
    out("Commande d'effacement à distance envoyée.", "sys");
    out("EN ATTENTE : le téléphone est hors ligne (mode avion). L'ordre s'exécutera à la prochaine connexion, peut-être jamais si Mallory n'y remet pas de SIM ou de Wi-Fi, ou si elle réinitialise l'appareil en mode de récupération. L'effacement est une bonne mesure, pas une garantie, et il n'efface pas la copie du jeton qui est déjà ailleurs.", "err");
    out("La vraie protection est côté serveur : `lier` et `revoquer`.", "sys");
  }
  function replayCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(), ls = x.ls, s = x.srv;
    if (!ls.declared) { out("Aucun incident déclaré : `declarer perte` d'abord.", "sys"); return; }
    ls.n = (ls.n || 0) + 1;
    out("Simulation : Mallory rejoue, depuis son ordinateur, le jeton qu'elle a copié.", "sys");
    code("GET /v2/comptes\nAuthorization: Bearer " + TOK + "\nX-Appareil: tel-inconnu-9F (IP 203.0.113.77)");
    ls.r1 = true;
    if (s.revoked) { out("401 Non autorisé : « session révoquée ». Le jeton copié est désormais de la ferraille.", "ok"); ls.rAfter = true; if (s.bound) afterLoss(); }
    else if (s.bound) {
      const nonce = sha256("nonce" + ls.n).slice(0, 12), real = sha256(HW + "|" + nonce + "|" + TOK).slice(0, 16), forged = sha256("?" + nonce + "|" + TOK).slice(0, 16);
      out("403 Interdit : le serveur exige une preuve de possession de la clé de l'appareil (défi " + nonce + "). Le téléphone, via le coffre, produit " + real + " ; Mallory, sans la clé, ne peut qu'inventer " + forged + ". Un jeton volé seul ne suffit plus.", "ok");
      ls.rBound = true;
    } else out("200 OK : le serveur accepte. Mallory lit les soldes " + RESP() + " et peut ajouter un bénéficiaire. Le jeton est un « porteur » : qui le possède est le propriétaire, tant que le serveur ne l'invalide pas.", "err");
  }
  function afterLoss() { const x = F(); if (x.srv.revoked && x.srv.bound && x.ls.rAfter && !x.lossDone) { x.lossDone = true; note("revoc"); out("Cycle de perte bouclé : détection, localisation, effacement tenté, jetons révoqués, liaison appareil/jeton. Schéma : `schema perte`.", "ok"); } }
  function bindCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(); if (!x.ls.r1) { say("Bob", "Regarde d'abord ce que Mallory fait du jeton : `rejouer`."); return; }
    if (x.srv.bound) { out("Déjà fait.", "sys"); return; }
    x.srv.bound = true;
    out("Le serveur enregistre la clé publique de l'appareil (générée dans le coffre, non exportable) et exige désormais, avec chaque jeton, une signature de défi produite par cette clé. Un jeton recopié sans la clé ne s'utilise plus.", "ok");
    out("Les jetons déjà émis restent à invalider : `revoquer`.", "sys"); afterLoss();
  }
  function revokeCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(); if (!x.ls.r1) { say("Bob", "Regarde d'abord ce que Mallory fait du jeton : `rejouer`."); return; }
    if (x.srv.revoked) { out("Déjà fait.", "sys"); return; }
    x.srv.revoked = true;
    out("Révocation côté serveur : tous les jetons de Léa (accès et rafraîchissement) sont invalidés, la session est fermée sur tous les appareils, et une nouvelle connexion exigera un second facteur depuis un appareil de confiance. Opération instantanée, qui ne dépend pas du téléphone perdu.", "ok");
    out("Teste : `rejouer`.", "sys"); afterLoss();
  }
  function attestCmd(c) {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(), t = norm(c.rawArg);
    const mod = /modif|root|jail|jb/.test(t), san = /sain|propre|normal|ok/.test(t);
    if (!mod && !san) { out("`integrite sain` ou `integrite modifie`.", "err"); return; }
    const rep = mod ? "bootloader=DEVERROUILLE;systeme=NON_VERIFIE;su=present" : "bootloader=VERROUILLE;systeme=VERIFIE;su=absent";
    const sig = sha256("attestation:" + HW + "|" + rep).slice(0, 16);
    out("Attestation d'intégrité signée par le matériel de l'appareil :", "sys"); code(rep.split(";").join("\n") + "\nsignature : " + sig);
    if (mod) { x.md.seen.modifie = true; out("Verdict du serveur : appareil MODIFIÉ (root ou jailbreak). Politique : accès à l'appli bancaire refusé, ou limité en lecture, et alerte à la flotte. Sur un appareil modifié, la protection du coffre et l'isolation des applis ne sont plus garanties.", "err"); out("Limite : c'est un signal, pas une preuve. Les contournements existent et la détection est une course permanente : on la combine avec les autres mesures (jetons liés, plafonds, surveillance des comportements) plutôt que de s'y fier seule.", "sys"); }
    else { x.md.seen.sain = true; out("Verdict : appareil sain. La signature est vérifiable par le serveur : l'appli ne peut pas se déclarer saine toute seule.", "ok"); }
  }
  function fleetCmd() {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(), req = Object.keys(x.md.req);
    const rows = fleet().map(([n, d]) => {
      const bad = Object.keys(RULES).filter(k => x.md.req[k] && !RULES[k][1](d));
      const sh = Object.keys(RULES).map(k => RULES[k][1](d) ? "✓" : "✗").join(" ");
      return n.padEnd(10) + " " + (d.d ? d.d + " ch" : "aucun").padEnd(7) + " " + (d.enc ? "chif" : "clair").padEnd(5) + " " + d.patch + " " + (d.root ? "modifié" : "sain   ") + "  " + sh + (req.length ? (bad.length ? "  → QUARANTAINE" : "  → conforme") : "");
    });
    out("Parc de la Guilde (colonnes ✓/✗ : code, chiffrement, correctifs, intégrité ; ✓ = règle respectée) :", "sys"); code(rows.join("\n"));
    if (!req.length) { out("Aucune règle n'est exigée : n'importe quel appareil accède à l'appli. `exiger ‹code|chiffrement|patch|integrite›`.", "err"); return; }
    const q = fleet().filter(([n, d]) => Object.keys(RULES).some(k => x.md.req[k] && !RULES[k][1](d))).length;
    out("Règles exigées : " + req.map(k => RULES[k][0]).join(", ") + ". " + (q ? q + " appareil(s) en quarantaine : accès à l'appli bloqué jusqu'à correction (Bob s'en charge ; effacement sélectif du conteneur professionnel pour les appareils personnels)." : "Tous les appareils sont conformes."), q ? "err" : "ok");
    if (Object.keys(RULES).every(k => x.md.req[k]) && !x.md.ok) { x.md.ok = true; if (x.md.seen.sain && x.md.seen.modifie) { note("mdm"); } out("Base de conformité complète (et appliquée par le serveur, pas seulement recommandée).", "ok"); }
    else if (x.md.ok && !S.notes.includes("mdm") && x.md.seen.sain && x.md.seen.modifie) note("mdm");
  }
  function requireCmd(c) {
    if (!need("guichet", NEED.guichet)) return;
    const x = F(), t = norm(c.rawArg);
    const k = /code/.test(t) ? "code" : /chiffr/.test(t) ? "chiffrement" : /patch|correctif|maj/.test(t) ? "patch" : /integr|root|jail/.test(t) ? "integrite" : null;
    if (!k) { out("`exiger code` · `exiger chiffrement` · `exiger patch` · `exiger integrite`", "err"); return; }
    x.md.req[k] = true; out("Règle imposée par la flotte : **" + RULES[k][0] + "**. `flotte` pour voir qui est conforme.", "ok");
  }
  function storeCmd() {
    if (!need("portail", NEED.portail)) return;
    out("Résultats de la recherche « BanqueGuilde » :", "sys");
    code(STORE.map(a => a.id + " · " + a.nom + "\n    " + a.ed + " · " + a.inst + " installations · " + a.src + "\n    publiée il y a " + a.age).join("\n"));
    out("`comparer ‹n›` pour inspecter une fiche, `installer ‹n›` pour l'installer.", "sys");
  }
  function compareCmd(c) {
    if (!need("portail", NEED.portail)) return;
    const x = F(), n = Number(norm(c.rawArg).split(" ").pop()), a = STORE.find(s => s.id === n);
    if (!a) { out("Quelle fiche ? `comparer 1`, `comparer 2` ou `comparer 3`.", "err"); return; }
    const sigOk = a.fp === OFFICIAL;
    out("Fiche « " + a.nom + " » :", "sys");
    code("éditeur       : " + a.ed + "\nsource        : " + a.src + "\nancienneté    : " + a.age + "\ninstallations : " + a.inst + "\npermissions   : " + a.perms + "\nsignature     : " + a.fp + (sigOk ? "  (= signature officielle)" : "  (≠ " + OFFICIAL + ")"));
    if (a.id === 1) out("C'est l'appli officielle : éditeur connu, signature attendue, permissions minimales, source officielle. Garde-la à jour.", "ok");
    else {
      out(a.id === 2 ? "Nom quasi identique, éditeur différent, publiée il y a 6 jours, 212 installations, et des permissions (SMS, accessibilité, superposition d'écran) qu'une vraie appli bancaire n'a pas : un clone. Même dans le magasin officiel, les contrôles ne sont pas infaillibles." : "Un APK hors magasin reçu par lien raccourci : aucun contrôle de l'éditeur, signature inconnue, demande d'administrateur de l'appareil. Si les sources inconnues sont désactivées par défaut, c'est pour une raison.", "err");
      x.st.seen[a.id === 2 ? "clone" : "apk"] = true;
    }
  }
  function installCmd(c) {
    if (!need("portail", NEED.portail)) return;
    const n = Number(norm(c.rawArg).split(" ").pop()), a = STORE.find(s => s.id === n);
    if (!a) { out("Installer quoi ? `installer 1`", "err"); return; }
    if (a.id === 1) out("L'appli officielle est déjà installée sur le téléphone de Léa. `maj` pour les mises à jour.", "ok");
    else { out("Installation de « " + a.nom + " »… une demande d'accessibilité s'affiche, puis le clone lit les SMS et superpose un faux écran de connexion. Mallory se frotte les mains. Ada annule et réinitialise l'appareil de test : `comparer " + a.id + "` t'aurait suffi pour le voir.", "err"); }
  }
  function updateCmd() {
    if (!need("portail", NEED.portail)) return;
    const x = F();
    if (x.st.upd) { out("Tout est à jour : BanqueGuilde 5.2.1, correctifs système 2026-09.", "ok"); return; }
    out("Mises à jour en attente sur le téléphone de Léa :", "sys");
    code("BanqueGuilde 5.2.0 → 5.2.1   corrige : WebView sans liste d'hôtes, fuite de journal (identifiants fictifs)\nSystème  2026-05 → 2026-09   correctifs de sécurité du noyau et des pilotes");
    x.st.upd = true;
    out("Appliquées. Et rien n'oblige à compter sur la bonne volonté de chacun : le serveur peut exiger une version minimale, et le MDM un niveau de correctifs (`exiger patch`).", "ok");
    out("Les correctifs sont publics : une fois publiés, ils décrivent aussi la faille. Retarder une mise à jour, c'est rester vulnérable à une faille désormais connue de tous.", "sys");
    if (x.st.seen.clone && x.st.seen.apk) note("magasin");
  }

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada":
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Léa, notre courrière, a laissé son téléphone dans le train de 14 h 07. Il contient l'appli de la banque de la Guilde, et quelqu'un l'a ramassé. J'ai fait une copie d'analyse fictive de l'appareil et de l'appli : ici, rien de réel.");
          say("Maître Ada", "Ton audit : que peut obtenir un trouveur selon le verrouillage ? Où l'appli range-t-elle ses secrets ? Que lui laisse-t-on voir et envoyer ? Puis on organise la réponse à la perte : serveur, flotte, magasin d'applications. Commence par l'atelier, au nord.");
          out("`aller nord` puis `trouveur`.", "sys");
        } else if (x.end) say("Maître Ada", "Léa a un nouveau téléphone, verrouillé, chiffré et sous gestion. Merci !");
        else if (objective() === "end") ending();
        else say("Maître Ada", "L'audit n'est pas fini. `indice` si tu bloques ; l'ordre est libre, mais je te conseille : verrou, stockage, permissions, réseau, liens, perte, flotte, magasin.");
        break;
      case "lea": say("Léa", x.end ? "Je ne poserai plus jamais mon téléphone sur une banquette. Enfin… je crois." : "Je sais, je sais. Il n'avait pas de code : « c'est pénible à taper dans le train ». Maintenant je comprends pourquoi ça compte."); break;
      case "mallory": say("Mallory", "Un téléphone qui traîne, un Wi-Fi gratuit, un lien qui fait cliquer : mon trio préféré. Je n'ai pas encore trouvé ton verrou, ni ton épinglage, d'ailleurs. Ça m'agace."); break;
      case "eve": say("Ève", "Je n'ai rien touché : j'écoute. En clair, je lis tout. En TLS, je vois seulement qui parle à qui et combien. Pour aller plus loin, il faut quelqu'un comme Mallory."); break;
      case "bob": say("Bob", x.ls && x.ls.declared ? "Révoquer côté serveur, c'est le geste qui compte : l'effacement dépend d'un téléphone qu'on n'a plus." : "La flotte, c'est six téléphones et dix façons de les oublier. Utilise la console."); break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Léa a un nouveau téléphone : code de huit chiffres ou biométrie avec limite d'essais, stockage chiffré, jeton dans le coffre, permissions réduites, TLS épinglé avec une clé de secours, liens validés, jetons liés à l'appareil, flotte conforme, installation depuis le magasin officiel. Et son ancien jeton ne vaut plus rien. Le téléphone perdu ne l'est plus pour la banque.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le trouveur = quelqu'un qui détient l'appareil.** Sans verrou, il a tout. Avec un verrou mais sans chiffrement, il lit la mémoire en contournant l'écran. Avec le chiffrement, la clé dépend du code et d'un secret matériel : les essais se font sur le téléphone, ralentis par le calcul de clé, par les délais croissants et par l'effacement. 4 chiffres = 10 000 codes (en quelques minutes à 80 ms par essai sans limite), 6 = un million, 8 = cent millions.");
    out("**Le coffre matériel = Android Keystore / StrongBox, iOS Keychain / Secure Enclave.** La clé est générée et utilisée dans une puce dédiée, non exportable ; l'appli demande des opérations, jamais la clé. Les préférences en clair, bases non chiffrées et journaux de débogage sont les fuites les plus courantes.");
    out("**Le manifeste = les permissions.** Chaque permission accorde une capacité (micro, contacts, SMS, position) dont héritent les bibliothèques tierces. Moindre privilège : au moment de l'usage, avec la précision minimale, et seulement pour une fonction visible.");
    out("**Le faux point d'accès et l'AC « Boutique-WiFi » = l'attaque active sur le réseau.** TLS valide la chaîne vers une autorité de confiance ; une autorité ajoutée par l'utilisateur ou mal émise passe la validation. L'épinglage vérifie la clé publique attendue, au prix d'une maintenance : clé de secours, rotation planifiée, et il ne protège pas contre un appareil que l'attaquant contrôle.");
    out("**Le lien de l'affiche = lien profond / intent.** Un lien venu de n'importe où déclenche une action. Confirmation, validation stricte, liste d'hôtes, liens https vérifiés.");
    out("**L'aperçu, les notifications et la sauvegarde = les fuites latérales.** Miniatures de tâches, captures, notifications d'écran verrouillé, sauvegardes cloud.");
    out("**Le guichet = MDM et révocation côté serveur.** Le jeton de Léa existait en dehors du téléphone : seul le serveur peut l'invalider. La liaison à une clé de l'appareil (preuve de possession) rend un jeton volé inutilisable. L'attestation d'intégrité détecte les appareils modifiés, comme signal. Le MDM impose la base (code, chiffrement, correctifs) et sait localiser, verrouiller, effacer.");
    out("**La vitrine = magasin d'applications et mises à jour.** Clones, APK hors magasin, correctifs qui corrigent des failles désormais publiques.");
    out("**Les simplifications du jeu.** (1) Le chiffrement du coffre est un chiffrement par flux construit sur SHA-256, pas du vrai AES-GCM, et la puce est un simple secret dans le code. (2) Les temps d'essai (80 ms, délais de type iOS) sont des ordres de grandeur ; les téléphones récents chiffrent toujours leur stockage et rendent l'extraction très difficile, ce que le jeu ne montre qu'avec un vieux modèle. (3) La validation de certificats et d'URL est réduite à quelques contrôles ; l'AC installée par un portail captif simplifie des mécanismes réels (profils, magasin utilisateur). (4) Les contournements (appareil modifié, hooking de l'épinglage, attaques physiques) ne sont ni montrés ni détaillés. (5) Le MDM, l'attestation, les liens vérifiés et les sauvegardes sont décrits à gros traits.");
    out("Rappel utile : **verrou long + stockage chiffré, secrets dans le coffre, permissions minimales, TLS épinglé avec clé de secours, liens validés, et surtout : révoquer côté serveur.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    finder: () => {
      const x = F(), L = LV[x.lvl];
      let b = T(8, 16, L.t, "f-b", "start") + T(8, 32, "chiffrement " + (x.enc ? "oui" : "non") + " · " + PO_S[x.pol], "f-s", "start");
      if (x.lvl === "aucun" || !x.enc) {
        b += R(8, 46, 404, 104, "f-bad") +
          T(210, 70, x.lvl === "aucun" ? "Aucun verrou : tout est lisible" : "Verrou sans chiffrement : code contourné", "f-b ft-bad") +
          T(210, 92, x.lvl === "aucun" ? "écran ouvert d'un geste, appli déjà connectée" : "lecture directe de la mémoire flash du téléphone", "f-s") +
          T(210, 110, "jeton, base de comptes, journal : exposés", "f-s ft-bad") +
          T(210, 134, "il faut un code ET le chiffrement du stockage", "f-s ft-ok") +
          T(210, 172, "sans chiffrement, le verrou est une porte sans mur", "f-s");
        return { cap: "Ce que voit le trouveur dans l'état actuel du téléphone. Change le verrou, active le chiffrement et la politique d'essais, puis relance `schema finder`.", svg: SVG(190, "Ce que voit un trouveur sans protection", b) };
      }
      [4, 6, 8].forEach((d, i) => {
        const y = 48 + i * 44, p = p30(d, x.pol), w = worst(d, x.pol), c = col(p);
        const len = isFinite(w) ? Math.max(4, Math.min(230, Math.log10(Math.max(w, 1)) / 9.5 * 230)) : 4;
        const fill = c === "ok" ? "var(--ok)" : c === "mid" ? "var(--you)" : "var(--bad)";
        const cls = c === "ok" ? "ft-ok" : c === "mid" ? "ft-priv" : "ft-bad";
        if (d === L.d) b += R(2, y - 8, 416, 42, "f-pub");
        b += T(8, y + 11, d + " chiffres", d === L.d ? "f-s ft-pub" : "f-s", "start") + R(80, y, 230, 14) + `<rect x="80" y="${y}" width="${len}" height="14" rx="3" fill="${fill}"/>` +
          T(316, y + 11, isFinite(w) ? dur(w) : "effacé à 10", "f-s " + cls, "start") + T(80, y + 31, "en 30 jours : " + pct(p), "f-s " + cls, "start");
      });
      b += T(8, 186, "pire cas · échelle log (1 s à 10 ans)", "f-s", "start");
      return { cap: "Temps pour énumérer tous les codes sur le téléphone, selon la longueur du code et la politique d'essais ; en dessous, la probabilité de réussite d'un trouveur en 30 jours. Vert : sûr, ambre : insuffisant, rouge : dangereux.", svg: SVG(196, "Temps d'énumération d'un code selon la politique d'essais", b) };
    },
    arbre: () => {
      const x = F();
      const rows = [["session.xml", "jeton en clair", "jeton chiffré", x.stTok], ["comptes.db", "base non chiffrée", "base chiffrée", x.stDb], ["debug.log", "jeton dans le journal", "journal sans secret", x.stLog], ["releve.pdf", "relevé en cache", "cache purgé", x.stCache]];
      let b = T(106, 18, "avant", "f-b", "middle") + T(314, 18, "maintenant", "f-b", "middle");
      rows.forEach((r, i) => {
        const y = 30 + i * 40;
        b += R(8, y, 196, 34, "f-bad") + T(16, y + 14, r[0], "f-b", "start") + T(16, y + 28, r[1], "f-s ft-bad", "start") +
          R(216, y, 196, 34, r[3] ? "f-ok" : "f-bad") + T(224, y + 14, r[0], "f-b", "start") + T(224, y + 28, r[3] ? r[2] : r[1], "f-s " + (r[3] ? "ft-ok" : "ft-bad"), "start");
      });
      const n = (x.stTok ? 1 : 0) + (x.stDb ? 1 : 0);
      b += R(8, 198, 404, 44, n ? "f-ok" : "") + KEY(22, 220, n ? "f-pub" : "f-priv") + T(60, 214, "coffre matériel (Keystore / Keychain)", "f-b", "start") + T(60, 232, n ? "clé dans la puce ; fichiers chiffrés seulement" : "rien n'y est encore confié", "f-s", "start");
      return { cap: "Arborescence de l'appli avant et maintenant : rouge = lisible par quiconque accède aux fichiers ; vert = chiffré avec une clé du coffre matériel, non exportable.", svg: SVG(250, "Arbre de stockage de l'application avant et après", b) };
    },
    pin: () => {
      const x = F(), n = x.net, tls = n.mode === "tls";
      let b = R(8, 28, 96, 56) + T(56, 50, "appli", "f-b") + T(56, 68, "BanqueGuilde", "f-s") +
        R(162, 28, 96, 56, "f-bad") + T(210, 46, "Wi-Fi du café", "f-b ft-bad") + T(210, 62, "faux point", "f-s") + T(210, 76, "d'accès", "f-s") +
        R(316, 28, 96, 56) + T(364, 50, "serveur", "f-b") + T(364, 68, "api.banque.guilde", "f-s");
      b += AR(104, 56, 162, 56, tls ? "f-pub" : "f-bad", true) + AR(258, 56, 316, 56, tls ? "f-pub" : "f-bad", true);
      if (!tls) b += T(133, 48, "clair", "f-s ft-bad") + T(287, 48, "clair", "f-s ft-bad") + T(210, 106, "Ève et Mallory lisent le jeton", "f-b ft-bad");
      else b += LOCK(121, 86, "f-pub") + T(133, 48, "TLS", "f-s ft-pub") + T(287, 48, "TLS", "f-s ft-pub");
      const pinTxt = n.pin === "aucun" ? "aucun" : n.pin === "cle" ? "clé 2026" : "clé 2026 + clé 2027 (secours)";
      b += T(8, 130, "épinglage : " + pinTxt, "f-b " + (n.pin === "aucun" ? "ft-priv" : "ft-ok"), "start");
      if (tls) {
        const l = n.last;
        b += T(8, 152, l ? "dernier certificat : " + (l.key === "boutique" ? "AC Boutique-WiFi" : l.key) + " → " + (l.ok ? "accepté" : "refusé") : "aucun certificat testé : `presenter`", "f-s " + (l ? (l.ok && CERTS[l.key].mitm ? "ft-bad" : l.ok ? "ft-ok" : (CERTS[l.key].mitm ? "ft-ok" : "ft-bad")) : ""), "start");
        if (l && l.ok && CERTS[l.key].mitm) b += T(8, 172, "Mallory déchiffre puis rechiffre : l'appli ne voit rien", "f-s ft-bad", "start");
        else if (l && !l.ok && CERTS[l.key].mitm) b += T(8, 172, "la clé du faux certificat n'est pas celle attendue", "f-s ft-ok", "start");
        else if (l && !l.ok) b += T(8, 172, "panne : le vrai serveur est refusé (pas de clé de secours)", "f-s ft-bad", "start");
        b += T(8, 196, n.pin === "aucun" ? "TLS seul : toute AC installée est crue" : "épingler : clé du serveur = empreinte prévue", "f-s", "start");
      }
      b += T(8, 214, "limite : clé de secours, rotation, appareil sain", "f-s", "start");
      return { cap: "Communication de l'appli avec le serveur via le Wi-Fi du café : en clair, avec TLS seul, puis avec épinglage. Se met à jour selon tes réglages et le dernier certificat testé.", svg: SVG(226, "Communication avec ou sans épinglage de certificat", b) };
    },
    perms: () => {
      const p = F().pm;
      const rows = [["INTERNET", true, "accordée", "nécessaire"], ["USE_BIOMETRIC", true, "accordée", "nécessaire"], ["CAMERA", true, "accordée", "dépôt de chèque"],
        ["RECORD_AUDIO", false, p.micro ? "accordée" : "retirée", "conversations"], ["READ_CONTACTS", false, p.contacts ? "accordée" : "retirée", "proches, santé, justice"], ["READ_SMS", false, p.sms ? "accordée" : "retirée", "codes à usage unique"],
        ["FINE_LOCATION", false, p.loc === "always" ? "permanente" : p.loc === "use" ? "à l'usage" : "retirée", "domicile, habitudes"]];
      let b = T(8, 16, "permission", "f-s", "start") + T(150, 16, "état", "f-s", "start") + T(240, 16, "ce qu'elle révèle", "f-s", "start");
      rows.forEach((r, i) => {
        const y = 24 + i * 26, bad = !r[1] && (r[2] === "accordée" || r[2] === "permanente"), mid = r[2] === "à l'usage";
        const c = r[1] || (!bad && !mid) ? "f-ok" : mid ? "f-priv" : "f-bad", t = r[1] || (!bad && !mid) ? "ft-ok" : mid ? "ft-priv" : "ft-bad";
        b += R(4, y, 412, 22, c) + T(10, y + 15, r[0], "f-s", "start") + T(150, y + 15, r[2], "f-s " + t, "start") + T(240, y + 15, r[1] ? r[3] : (bad ? r[3] : "—"), "f-s " + (bad ? "ft-bad" : ""), "start");
      });
      b += T(8, 224, "vert : minimal · ambre : réduit · rouge : excessif et exposé", "f-s", "start");
      return { cap: "Les permissions de l'appli et ce que chacune révélerait. Le moindre privilège garde ce qu'une fonction visible utilise, pas plus.", svg: SVG(236, "Permissions et ce qu'elles révèlent", b) };
    },
    perte: () => {
      const x = F(), ls = x.ls, s = x.srv;
      const steps = [["14:07", "Perte dans le train", true], ["14:11", "Mallory rejoue le jeton copié", true], ["14:19", "Perte déclarée", !!ls.declared], ["", "Localisation (hors ligne : avion)", !!ls.located], ["", "Effacement à distance (en attente)", !!ls.wipeTried],
        ["", "Liaison appareil/jeton (preuve de possession)", !!s.bound], ["", "Révocation des jetons côté serveur", !!s.revoked], ["", "Rejeu de Mallory : refusé", !!ls.rAfter]];
      let b = "";
      steps.forEach((r, i) => {
        const y = 14 + i * 30, last = i === steps.length - 1;
        b += (i < steps.length - 1 ? LN(18, y + 16, 18, y + 30, "f-dash") : "") + `<circle cx="18" cy="${y + 8}" r="7" class="f-box ${r[2] ? (i === 1 ? "f-bad" : "f-ok") : ""}"/>` + T(18, y + 12, r[2] ? "✓" : "", "f-s", "middle") +
          T(34, y + 12, r[0], "f-s", "start") + T(78, y + 12, r[1], "f-t " + (r[2] ? (i === 1 ? "ft-bad" : "ft-ok") : ""), "start");
      });
      const can = !(s.revoked || s.bound);
      b += T(8, 262, "jeton volé exploitable : " + (can ? "OUI" : "non"), "f-b " + (can ? "ft-bad" : "ft-ok"), "start");
      return { cap: "Cycle de perte et réponse : l'effacement à distance est incertain, la révocation côté serveur et la liaison à l'appareil ne dépendent pas du téléphone perdu.", svg: SVG(276, "Cycle de perte et de réponse", b) };
    },
  };

  GAMES.mobile = {
    id: "mobile", order: 26, title: "Le Téléphone Perdu", pageTitle: "Mobile Quest", subtitle: "aventure textuelle · sécurité mobile",
    blurb: "Un téléphone avec l'appli de la banque est oublié dans un train : verrouillage, stockage, permissions, réseau, liens et réponse à la perte.",
    concept: "Sécurité mobile : stockage, permissions, communications, perte de l'appareil",
    start: "quai", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() {
      const x = F();
      Object.assign(x, { lvl: "aucun", enc: false, pol: "libre", seen: {}, stTok: false, stDb: false, stLog: false, stCache: false,
        pm: { micro: true, contacts: true, sms: true, loc: "always", camera: true, internet: true, biometrie: true }, rev: {},
        net: { mode: "http", pin: "aucun", seen: {}, last: null }, lk: { confirm: false, list: false, verified: false, seen: {} },
        ls: {}, srv: { revoked: false, bound: false }, md: { req: {}, seen: {} }, st: { seen: {}, upd: false } });
    },
    figAlias: { finder: ["trouveur", "verrou", "code"], arbre: ["stockage", "fichiers"], pin: ["tls", "epinglage", "reseau"], perms: ["permission", "permissions"], perte: ["cycle", "revocation", "reponse"] },
    help: "Spécifiques : `verrou` · `chiffrer` · `essais` · `trouveur` · `arbre` · `ouvrir` · `migrer` · `purger` · `manifeste` · `reveler` · `retirer` · `limiter` · `apercu` · `sauvegarde` · `proteger` · `transport` · `ecouter` · `presenter` · `epingler` · `lien` · `durcir` · `declarer perte` · `localiser` · `effacer` · `rejouer` · `lier` · `revoquer` · `integrite` · `flotte` · `exiger` · `magasin` · `comparer` · `installer` · `maj`",
    verbs: {
      lock: { words: ["verrou", "verrouiller"], run: lockCmd }, encr: { words: ["chiffrer", "chiffrement"], run: encCmd }, pol: { words: ["essais"], run: polCmd },
      finder: { words: ["trouveur", "fouiller"], run: finderCmd }, tree: { words: ["arbre", "arborescence", "ls"], run: treeCmd }, openf: { words: ["ouvrir", "cat", "afficher"], run: openCmd },
      mig: { words: ["migrer", "deplacer", "transferer"], run: migrateCmd }, purge: { words: ["purger", "nettoyer", "supprimer"], run: purgeCmd },
      manif: { words: ["manifeste", "permissions"], run: manifestCmd }, reveal: { words: ["reveler", "revele"], run: revealCmd }, retire: { words: ["retirer"], run: retireCmd }, limit: { words: ["limiter", "restreindre"], run: limitCmd },
      apercu: { words: ["apercu", "taches"], run: apercuCmd }, backup: { words: ["sauvegarde", "sauvegardes", "backup"], run: backupCmd }, protect: { words: ["proteger", "masquer", "exclure"], run: protectCmd },
      transport: { words: ["transport", "protocole"], run: transportCmd }, listen: { words: ["ecouter", "ecoute"], run: listenCmd }, present: { words: ["presenter", "certificat"], run: presentCmd }, pin: { words: ["epingler", "epinglage", "pin"], run: pinCmd },
      link: { words: ["lien", "url"], run: linkCmd }, harden: { words: ["durcir", "renforcer"], run: hardenCmd },
      declare: { words: ["declarer"], run: declareCmd }, locate: { words: ["localiser", "geolocaliser"], run: locateCmd }, wipe: { words: ["effacer", "wipe"], run: wipeCmd }, replay: { words: ["rejouer", "replay"], run: replayCmd },
      bind: { words: ["lier"], run: bindCmd }, revoke: { words: ["revoquer", "invalider"], run: revokeCmd }, attest: { words: ["integrite", "attestation"], run: attestCmd },
      fleet: { words: ["flotte", "parc"], run: fleetCmd }, require: { words: ["exiger", "imposer"], run: requireCmd },
      store: { words: ["magasin", "boutique"], run: storeCmd }, compare: { words: ["comparer"], run: compareCmd }, install: { words: ["installer"], run: installCmd }, update: { words: ["maj", "mettre a"], run: updateCmd },
    },
    intro() {
      out("Le Téléphone Perdu", "title");
      out("Léa, courrière de la Guilde, a laissé son téléphone sur une banquette du train de 14 h 07. Il contient l'application de la banque de la Guilde. Maître Ada te confie une copie d'analyse fictive de l'appareil : verrouillage, fichiers de l'appli, permissions, réseau, liens, sauvegardes, puis la réponse à la perte. Tout est simulé, rien n'est réel.", "");
    },
  };
})();
