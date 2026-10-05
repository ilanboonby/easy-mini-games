"use strict";
/* Le Sceau à Deux Clés : phishing, SMS, TOTP (RFC 6238 réel), proxy AitM, WebAuthn lié à l'origine, fatigue MFA. */
(function () {
  const F = () => f();
  const LEGIT = "guilde-port443.org";
  const FAKE1 = "guilde-p0rt443.org";
  const HOMO = "guіlde-port443.org"; // le « і » est la lettre cyrillique U+0456
  const ORIGIN = "https://" + LEGIT;
  const FAKE_ORIGIN = "https://" + FAKE1;
  const SECRET = "PORT443-SECRET-ALICE";
  const PWD = "printemps2026";
  const T0 = 1760000112;

  /* ---------- TOTP réel : HMAC-SHA-256 construit sur le sha256 du moteur ---------- */
  const hexBytes = h => { const r = []; for (let i = 0; i < h.length; i += 2) r.push(parseInt(h.substr(i, 2), 16)); return r; };
  const hex2 = b => b.toString(16).padStart(2, "0");
  // sha256 du moteur sur des octets bruts (le moteur ne lit que du texte : on lui prête, un instant, un TextEncoder qui renvoie ces octets)
  function shaBytes(bytes) {
    const TE = window.TextEncoder;
    window.TextEncoder = function () { this.encode = () => Uint8Array.from(bytes); };
    try { return hexBytes(sha256("")); } finally { window.TextEncoder = TE; }
  }
  function hmac(key, msg) {
    let k = key.slice(); if (k.length > 64) k = shaBytes(k);
    while (k.length < 64) k.push(0);
    return shaBytes(k.map(b => b ^ 0x5c).concat(shaBytes(k.map(b => b ^ 0x36).concat(msg))));
  }
  const strBytes = s => Array.from(new TextEncoder().encode(s));
  const ctrBytes = n => { const b = []; let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
  function hotp(secret, ctr, digits) {
    digits = digits || 6;
    const h = hmac(strBytes(secret), ctrBytes(ctr));
    const off = h[31] & 15;
    const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
    return { h, off, bin, code: String(bin % 10 ** digits).padStart(digits, "0") };
  }
  const step = () => Math.floor(F().clock / 30);
  const stamp = t => new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
  // le serveur accepte l'étape courante et ses deux voisines (dérive d'horloge)
  function verifyTotp(code) {
    const s = step();
    for (const d of [0, -1, 1]) if (hotp(SECRET, s + d).code === code) return { ok: true, d, step: s + d };
    for (let d = -20; d <= 20; d++) if (hotp(SECRET, s + d).code === code) return { ok: false, d, step: s + d };
    return { ok: false, d: null };
  }

  /* ---------- WebAuthn en miniature : signature RSA jouet (modpow) ---------- */
  const P = 50000017n, Q = 51000041n, N = P * Q, E = 65537n;
  function inv(a, m) { let [r0, r1, s0, s1] = [a, m, 1n, 0n]; while (r1) { const q = r0 / r1;[r0, r1] = [r1, r0 - q * r1];[s0, s1] = [s1, s0 - q * s1]; } return ((s0 % m) + m) % m; }
  const D = inv(E, (P - 1n) * (Q - 1n));
  const hm = msg => BigInt(parseInt(sha256(msg).slice(0, 11), 16)) % N; // empreinte réduite (44 bits) du message signé
  const signMsg = msg => BigInt(modpow(hm(msg), D, N)); // fait DANS la clé : D ne sort jamais
  const verifyMsg = (msg, sig) => BigInt(modpow(sig, E, N)) === hm(msg); // fait par le serveur avec la clé publique (N, E)
  const chal = n => sha256("defi|" + n).slice(0, 8);
  const curCh = () => chal(F().keyN || 0);
  const shortN = v => { const s = v.toString(); return s.length > 14 ? s.slice(0, 6) + "…" + s.slice(-4) : s; };

  /* ---------- SMS, push ---------- */
  const smsCode = n => String(parseInt(sha256("sms|" + n).slice(0, 8), 16) % 1000000).padStart(6, "0");
  const numOf = i => parseInt(sha256("num|" + i).slice(0, 4), 16) % 100;
  const guessOf = i => parseInt(sha256("guess|" + i).slice(0, 4), 16) % 100;
  const sid = tag => sha256("sid|" + tag + "|" + F().clock).slice(0, 16);

  /* ---------- Analyse des courriers ---------- */
  const lev = (a, b) => { const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]); for (let j = 1; j <= b.length; j++) d[0][j] = j; for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); return d[a.length][b.length]; };
  const CONF = { "і": "i", "о": "o", "а": "a", "е": "e", "р": "p", "с": "c", "ѕ": "s", "ӏ": "l" };
  const skeleton = s => [...s].map(c => CONF[c] || c).join("");
  const hostOf = u => u.replace(/^https?:\/\//, "").split("/")[0];
  const regDom = h => h.split(".").slice(-2).join(".");
  const cp = c => "U+" + c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
  function domInfo(d) {
    if (d === LEGIT) return { kind: "ok", txt: `« ${d} » : c'est exactement le domaine officiel de la Guilde.` };
    const odd = [...d].filter(c => c.charCodeAt(0) > 127);
    if (odd.length) return { kind: "homoglyph", txt: `« ${d} » contient ${odd.length} caractère(s) hors alphabet latin : « ${odd.join("")} » (${odd.map(cp).join(", ")}, lettre cyrillique qui ressemble à « ${CONF[odd[0]] || "?"} »). Une fois « décodé », le domaine est ${skeleton(d) === LEGIT ? "identique à l'officiel à l'œil, mais c'est un AUTRE domaine" : "trompeur"}.` };
    const dist = lev(d, LEGIT);
    if (dist <= 2) {
      const diffs = d.length === LEGIT.length ? [...d].map((c, i) => c !== LEGIT[i] ? `« ${c} » à la place de « ${LEGIT[i]} »` : null).filter(Boolean) : [];
      return { kind: "typo", txt: `« ${d} » est à distance ${dist} du domaine officiel${diffs.length ? " : " + diffs.join(", ") : ""}. C'est du typosquatting : un nom très proche, enregistré par un tiers.` };
    }
    if (d.includes("port443")) return { kind: "brand", txt: `« ${d} » reprend le nom « port443 » mais son domaine enregistré est « ${regDom(d)} », qui n'appartient pas à la Guilde (${LEGIT}). Un nom de marque dans un autre domaine ne prouve rien.` };
    return { kind: "other", txt: `« ${d} » n'a aucun rapport avec ${LEGIT}.` };
  }
  const MAILS = {
    1: { name: "Maître Ada", addr: "ada@" + LEGIT, reply: null, subj: "Réunion de la Guilde jeudi à 18 h", phish: false,
      body: ["Bonjour,", "la réunion mensuelle aura lieu jeudi à 18 h dans la salle des archives.", "L'ordre du jour est sur l'agenda de la Guilde.", "Ada"],
      linkTxt: ORIGIN + "/agenda", linkReal: ORIGIN + "/agenda", att: null, ask: null,
      auth: { spf: ["pass", LEGIT], dkim: ["pass", LEGIT], dmarc: ["pass", "aligné"] } },
    2: { name: "Service Informatique", addr: "support@" + FAKE1, reply: null, subj: "Votre mot de passe expire dans 24 h", phish: true,
      body: ["Bonjour,", "votre mot de passe expire dans 24 h. Sans action de votre part, votre compte sera suspendu.", "Connectez-vous pour le renouveler :"],
      linkTxt: ORIGIN + "/mot-de-passe", linkReal: FAKE_ORIGIN + "/connexion", att: null, ask: "identifiants",
      auth: { spf: ["pass", FAKE1], dkim: ["pass", FAKE1], dmarc: ["pass", "aligné"] },
      trap: "Alice clique, voit une page identique à celle de la Guilde, y saisit son identifiant et son mot de passe : ils partent chez Mallory." },
    3: { name: "Comptabilité", addr: "compta@" + HOMO, reply: null, subj: "DERNIER AVIS : facture impayée, poursuites sous 24 h", phish: true,
      body: ["Madame, Monsieur,", "malgré nos relances, la facture d'octobre reste impayée.", "Réglez immédiatement. Le détail est dans la pièce jointe."],
      linkTxt: null, linkReal: null, att: "Facture_octobre.pdf.exe", ask: "paiement",
      auth: { spf: ["pass", HOMO], dkim: ["pass", HOMO], dmarc: ["pass", "aligné"] },
      trap: "Bob double-clique sur la pièce jointe : un « .exe » se lance en silence (dans le jeu : un faux logiciel espion de démonstration, inoffensif)." },
    4: { name: "Maître Ada", addr: "ada@" + LEGIT, reply: "ada.guilde@relais-courrier.top", subj: "Service urgent, reste discrète", phish: true,
      body: ["Bonjour,", "je suis en réunion et je ne peux pas téléphoner. J'ai besoin que tu m'achètes 5 cartes cadeaux de 100 pièces", "et que tu m'envoies les codes dans l'heure. Ne dis rien à personne, je te rembourse ce soir."],
      linkTxt: null, linkReal: null, att: null, ask: "cartes cadeaux",
      auth: { spf: ["fail", "relais-courrier.top"], dkim: ["none", "-"], dmarc: ["fail", "From ≠ domaine d'envoi, politique : rejeter"] },
      trap: "Alice envoie les codes des cartes cadeaux à ce qu'elle croit être Maître Ada. L'argent est perdu." },
    5: { name: "Sécurité Guilde", addr: "securite@" + LEGIT, reply: null, subj: "Nouvelle connexion à votre compte", phish: false,
      body: ["Bonjour,", "une connexion à votre compte a eu lieu depuis un nouvel appareil (Lyon, 14 h 02).", "Si c'était vous, ignorez ce message. Sinon, ouvrez l'application de la Guilde et changez votre mot de passe."],
      linkTxt: ORIGIN + "/securite", linkReal: ORIGIN + "/securite", att: null, ask: null,
      auth: { spf: ["pass", LEGIT], dkim: ["pass", LEGIT], dmarc: ["pass", "aligné"] } },
    6: { name: "Port-443 Express", addr: "suivi@express-port443.net", reply: null, subj: "Colis retenu : réglez 1,99 pièce sous 12 h", phish: true,
      body: ["Bonjour,", "votre colis est retenu à la douane de Port-443. Pour le libérer, réglez les frais de 1,99 pièce par carte sous 12 h,", "sinon il sera renvoyé."],
      linkTxt: "https://suivi.express-port443.net/colis", linkReal: "https://bit-lien.top/x7Kq", att: null, ask: "paiement",
      auth: { spf: ["softfail", "express-port443.net"], dkim: ["none", "-"], dmarc: ["none", "aucune politique publiée"] },
      trap: "Alice entre sa carte sur la page « de paiement » : le numéro est volé, et le prélèvement de 1,99 n'est que l'appât." },
  };
  const URG = /(imm[ée]diat|urgent|\b24 ?h|\b12 ?h|expire|suspendu|dernier avis|dans l'heure|sans d[ée]lai|poursuites|discr[èe]te)/i;
  function analyse(m) {
    const fl = [], ad = m.addr.split("@")[1], di = domInfo(ad);
    if (di.kind !== "ok") fl.push(["Domaine", di.txt]);
    if (m.linkTxt && hostOf(m.linkTxt) !== hostOf(m.linkReal)) fl.push(["Lien", `le texte affiché mène à « ${hostOf(m.linkTxt)} » mais le lien réel pointe vers « ${hostOf(m.linkReal)} » (${m.linkReal}). Un lien masqué est un signal très fort.`]);
    if (m.reply && m.reply.split("@")[1] !== ad) fl.push(["Réponse", `les réponses iraient à « ${m.reply} », un domaine différent de l'expéditeur affiché : un fraudeur veut recevoir la réponse lui-même.`]);
    const a = m.auth, bad = ["spf", "dkim", "dmarc"].filter(k => a[k][0] !== "pass");
    if (bad.length) fl.push(["En-têtes", `${bad.map(k => k.toUpperCase() + " : " + a[k][0]).join(", ")}. ${a.spf[0] === "fail" && ad === LEGIT ? "Le serveur qui a envoyé ce message n'est pas autorisé à écrire au nom de " + LEGIT + " : l'expéditeur affiché est usurpé." : "L'expéditeur n'est pas authentifié."}`]);
    else if (di.kind !== "ok") fl.push(["En-têtes", `SPF, DKIM et DMARC passent… mais pour le domaine de l'attaquant (${ad}). Une authentification valide prouve QUI envoie, pas que l'expéditeur est de confiance.`]);
    if (URG.test(m.subj + " " + m.body.join(" "))) fl.push(["Urgence", "pression temporelle ou secret (« 24 h », « dans l'heure », « immédiatement »…) : on vous empêche de réfléchir et de vérifier."]);
    if (m.att && /\.(exe|scr|js|bat|docm|zip)$/i.test(m.att)) fl.push(["Pièce jointe", `« ${m.att} » : ${/\.\w+\.exe$/i.test(m.att) ? "double extension, le « .pdf » n'est qu'un déguisement devant un vrai exécutable (.exe)" : "type de fichier exécutable ou à macros"}.`]);
    if (m.ask) fl.push(["Demande", `le message cherche à obtenir : ${m.ask}. Une organisation sérieuse ne demande pas cela par courrier.`]);
    return fl;
  }
  const authLines = m => {
    const a = m.auth;
    return `SPF   : ${a.spf[0]} (domaine d'envoi : ${a.spf[1]})\nDKIM  : ${a.dkim[0]} (signé par : ${a.dkim[1]})\nDMARC : ${a.dmarc[0]} (${a.dmarc[1]})`;
  };
  const mailN = c => { const m = /\d+/.exec(c.target || ""); const n = m ? parseInt(m[0], 10) : 0; return MAILS[n] ? n : 0; };

  /* ---------- Carnet ---------- */
  const notes = {
    phish: ["Reconnaître un courrier piégé", "Le phishing (hameçonnage) imite un expéditeur de confiance pour vous faire agir : saisir un mot de passe, ouvrir un fichier, payer. Indices : domaine presque identique (typosquatting : p0rt, caractères cyrilliques qui imitent des lettres latines), lien dont la cible réelle diffère du texte affiché, expéditeur usurpé, urgence ou secret, pièce jointe exécutable, demande d'identifiants ou d'argent. Aucun indice isolé ne prouve tout : on les additionne."],
    spf: ["SPF, DKIM, DMARC", "SPF : le domaine liste les serveurs autorisés à envoyer en son nom. DKIM : le serveur signe le message, la signature se vérifie avec une clé publique publiée dans le DNS. DMARC : le domaine dit quoi faire (rien, quarantaine, rejet) quand SPF/DKIM ne correspondent pas à l'adresse « De » affichée. Ils combattent l'USURPATION d'un domaine. Mais un attaquant qui possède un domaine voisin (guilde-p0rt443.org) obtient des « pass » valides pour SON domaine."],
    why2f: ["Pourquoi un second facteur", "Un mot de passe est un secret : quiconque le copie (phishing, fuite, réutilisation) se connecte comme vous, sans que le serveur puisse faire la différence. Un second facteur ajoute autre chose qu'on sait : ce qu'on possède (téléphone, clé) ou ce qu'on est. Il faut alors voler deux choses, de nature différente."],
    sms: ["SMS et SIM swap", "Le code par SMS prouve que vous contrôlez un numéro de téléphone, pas un appareil. Le SIM swap (un opérateur convaincu de transférer votre numéro vers une autre carte SIM, par ingénierie sociale) ou l'interception du réseau mobile redirigent le code vers l'attaquant. Mieux que rien, mais déconseillé pour les comptes sensibles."],
    totp: ["TOTP : un code qui se calcule", "Le téléphone et le serveur partagent un secret (donné une fois, souvent par QR code). Chaque 30 secondes, ils calculent HMAC(secret, ⌊heure ÷ 30⌋) puis en tirent 6 chiffres (RFC 6238). Rien ne circule par le réseau mobile, et un code expire vite ; le serveur tolère une tranche d'écart (horloges) et refuse un code déjà utilisé. Mais il se tape à la main : on peut le taper sur un faux site."],
    aitm: ["Le proxy en temps réel (AitM)", "Un faux site « transparent » relaie en direct vos saisies au vrai site : mot de passe, puis code TOTP (encore valable quelques secondes), et récupère le cookie de session renvoyé. L'utilisateur voit le vrai contenu, l'attaquant est connecté. Aucun code à usage unique saisi par un humain n'y résiste : il faut un facteur qui vérifie QUI demande."],
    webauthn: ["WebAuthn : la signature liée à l'origine", "Le site envoie un défi aléatoire ; la clé (ou passkey) le signe avec une clé privée qui ne sort jamais, et le navigateur ajoute à ce qui est signé l'origine réelle du site. Le serveur vérifie avec la clé publique. Sur un faux site, l'origine signée est fausse : la réponse est inutilisable ailleurs, et rien ne se tape ou ne se recopie. Le navigateur ne propose d'ailleurs la passkey qu'au site pour lequel elle a été créée."],
    fatigue: ["La fatigue MFA", "Avec un simple « Approuver / Refuser » sur le téléphone, l'attaquant qui a le mot de passe déclenche des dizaines de demandes jusqu'à ce que la victime, excédée ou endormie, approuve. Parades : demander de saisir un nombre affiché sur l'écran de connexion (number matching), limiter le nombre de demandes, former à refuser et signaler. Contre un proxy AitM, cela ne suffit toujours pas."],
  };

  /* ---------- Entités ---------- */
  const mailEnt = n => ({ names: ["courrier " + n, "message " + n, "mail " + n, String(n)], label: null,
    desc: () => { const d = F().dec[n]; return `Statut : ${d === "signal" ? "signalé (quarantaine)" : d === "keep" ? "gardé" : "lu, pas encore classé"}.`; }, onExamine: () => showMail(n), vis: () => true });
  const ents = {
    ada: { npc: true, names: ["ada", "maitre ada", "doyenne"], label: "Maître Ada", desc: () => "Maître Ada, doyenne de la Guilde, qui garde les clés du Sceau du Coffre. Elle observe tout, sans jamais élever la voix." },
    alice: { npc: true, names: ["alice"], label: "Alice", vis: () => S.room === "portail", desc: () => "Alice, archiviste de la Guilde. Son compte est la cible de l'audit." },
    bob: { npc: true, names: ["bob"], label: "Bob", desc: () => "Bob, artisan de l'atelier des jetons : cadrans, clés et sceaux n'ont pas de secret pour lui." },
    eve: { npc: true, names: ["eve"], label: "Ève", desc: () => "Ève, assise près de la ligne, écoute passivement tout ce qui passe sur le fil." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory (jouée par Ada, pour l'audit)", desc: () => "Mallory, l'attaquante. Dans ce bac à sable, elle est simulée : tout est fictif, ses outils n'existent que dans le jeu." },
    boite: { names: ["boite", "reception", "boite reception", "inbox", "courrier", "courriers"], label: "la boîte de réception", vis: () => true,
      desc: () => { const x = F(); return "La boîte de réception de la Guilde :\n" + Object.keys(MAILS).map(n => { const m = MAILS[n]; return `  ${n}. ${m.name.padEnd(21)} ${m.subj.slice(0, 40)}  ${x.dec[n] ? (x.dec[n] === "signal" ? "[signalé]" : "[gardé]") : x.seen[n] ? "[lu]" : "[nouveau]"}`; }).join("\n") + "\n`examiner courrier ‹n›` pour ouvrir, `survoler ‹n›`, `entetes ‹n›`, `analyser ‹n›` pour enquêter, puis `signaler ‹n›` ou `garder ‹n›`."; } },
    page: { names: ["page", "portail", "page connexion", "connexion"], label: "la page de connexion", vis: () => S.room === "portail",
      desc: () => { const x = F(); return `La page de connexion de la Guilde (${ORIGIN}). Compte : alice. Protection active : **${FACT[x.factor]}**.\n\`connexion\` joue une connexion d'Alice. \`activer ‹facteur›\` règle la protection : ${["sms", "totp", "cle", "push", "numero", "aucun"].join(", ")} (selon ton avancement).`; } },
    pendule: { names: ["pendule", "horloge", "heure"], label: "la pendule", vis: () => S.room === "portail",
      desc: () => { const t = F().clock; return `La pendule du portail, réglée sur le temps Unix : le nombre de secondes écoulées depuis le 1er janvier 1970.\nHeure : **${t}** (${stamp(t)}).\nLes jetons TOTP découpent ce temps en tranches de 30 secondes ; le numéro de la tranche s'appelle l'étape. \`attendre ‹secondes›\` fait avancer la pendule.`; } },
    faux: { names: ["faux portail", "faux", "faux site", "proxy", "relais"], label: "le faux portail de Mallory", vis: () => S.room === "repaire",
      desc: () => `Le faux portail de Mallory (${FAKE_ORIGIN}) : une copie conforme de la page de la Guilde, qui relaie en direct tout ce qu'on lui tape vers le vrai site. Lance \`simuler proxy\` pour voir.` },
    jeton: { names: ["jeton", "application", "authentificateur", "app"], label: "le jeton d'Alice (application TOTP)", take: false,
      desc: () => `Le jeton d'Alice : une application qui garde le secret partagé et sait calculer un code à partir de l'étape. \`generer ‹étape›\`.` },
    cle: { names: ["cle", "cle securite", "cle de securite", "passkey", "clef"], label: "la clé de sécurité", take: false,
      desc: () => `Une clé de sécurité FIDO2 : elle garde une clé privée qui n'en sort jamais, et signe un défi quand on la touche. \`utiliser cle sur page\`.` },
  };
  for (let n = 1; n <= 6; n++) ents["m" + n] = mailEnt(n);

  const FACT = { none: "mot de passe seul", sms: "mot de passe + code SMS", totp: "mot de passe + code TOTP", push: "mot de passe + notification « Approuver »", pushnum: "mot de passe + notification avec saisie d'un nombre", key: "mot de passe + clé WebAuthn" };

  const rooms = {
    hall: { name: "Le hall de la Guilde", short: "Hall", alias: ["hall", "guilde"], ents: ["ada"], exits: { est: "courrier", nord: "portail", ouest: "atelier" },
      desc: () => "Sous la voûte, un grand coffre de chêne porte le Sceau de la Guilde : deux serrures, deux clés différentes. À l'est, la salle du courrier ; au nord, le portail des comptes ; à l'ouest, l'atelier des jetons." },
    courrier: { name: "La salle du courrier", short: "Courrier", alias: ["courrier", "salle courrier"], ents: ["boite", "m1", "m2", "m3", "m4", "m5", "m6"], exits: { ouest: "hall" },
      desc: () => "Des casiers de bois et une longue table couverte de lettres cachetées : la boîte de réception de la Guilde, dépouillée chaque matin. Certaines lettres viennent de vrais correspondants. D'autres, non." },
    portail: { name: "Le portail des comptes", short: "Portail", alias: ["portail", "comptes"], ents: ["alice", "page", "pendule"], exits: { sud: "hall", est: "repaire" },
      desc: () => "Un grand écran de cristal affiche la page de connexion de la Guilde. Alice, archiviste, se tient devant, un peu inquiète. Une pendule murale indique le temps Unix. À l'est, une porte grillagée mène au bac à sable où Mallory (simulée) attend." },
    atelier: { name: "L'atelier des jetons", short: "Atelier", alias: ["atelier", "jetons"], ents: ["bob"], exits: { est: "hall" },
      desc: () => "Cadrans de laiton, sceaux, clés de toutes tailles : Bob fabrique ici de quoi prouver qui l'on est." },
    repaire: { name: "Le bac à sable de Mallory", short: "Bac à sable", alias: ["repaire", "bac sable", "mallory"], ents: ["mallory", "eve", "faux"], exits: { ouest: "portail" },
      desc: () => "Une salle d'audit isolée : tout ce qui s'y passe est simulé, sur des données fictives. Mallory (jouée par Ada, pour l'exercice) y rejoue ses attaques contre le portail. Ève écoute près d'une ligne. Face à toi, le faux portail de Mallory, copie parfaite de la page de la Guilde." },
  };

  /* ---------- Objectif et indices ---------- */
  const triaged = () => Object.keys(MAILS).every(n => (F().dec[n] === "signal") === MAILS[n].phish && F().dec[n]);
  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.triaged) return "mails";
    if (!x.pwdone) return "pw";
    if (!x.smsdone) return x.factor === "sms" ? "sms2" : "sms";
    if (!x.bobjeton) return "bob";
    if (x.factor !== "totp" && !x.gen) return "totp1";
    if (!x.gen) return "gen";
    if (!x.expired) return "exp";
    if (!x.aitm) return "aitm";
    if (!x.bobkey) return "bob2";
    if (!x.keyreg) return "keyreg";
    if (!x.keylog) return "keylog";
    if (!x.keyfake) return "keyfake";
    if (!x.pushdone) return x.factor === "push" ? "push2" : "push";
    if (!x.numdone) return x.factor === "pushnum" ? "num2" : "num";
    if (!x.cmp) return "cmp";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Maître Ada t'attend dans le hall.", "`parler ada`"],
    mails: () => ["Va à la salle du courrier (est), examine chaque courrier, enquête avec les outils, puis tranche pour les six.", "`aller est`, `examiner courrier 1`, `survoler 1`, `entetes 1`, `analyser 1`, puis `signaler 1` ou `garder 1`. Recommence avec 2 à 6. Un mauvais choix peut être corrigé."],
    pw: () => ["Mallory a le mot de passe d'Alice. Observe la page de connexion (portail, au nord du hall), puis laisse Mallory le rejouer (bac à sable, à l'est du portail).", "`aller nord`, `examiner page`, `aller est`, `simuler rejeu`."],
    sms: () => ["Ajoute un second facteur : un code par SMS. Il se règle au portail.", "`aller ouest`, `activer sms`, puis `connexion` pour voir le SMS d'Alice."],
    sms2: () => ["Le SMS est actif. Retourne chez Mallory : le mot de passe seul ne suffit plus, mais regarde ce qu'elle tente d'autre (le numéro de téléphone, pas le téléphone).", "`aller est`, `simuler rejeu`, puis `simuler simswap`."],
    bob: () => ["Le SMS ne tient pas. Bob, à l'atelier, a un facteur qui ne passe pas par le réseau mobile.", "Depuis le portail : `aller sud`, `aller ouest`, `parler bob`."],
    totp1: () => ["Active le facteur TOTP au portail, avec le jeton que Bob t'a donné.", "`aller est` (retour au hall), `aller nord`, `activer totp`."],
    gen: () => {
      const s = step(), x = F();
      return [`Joue une connexion d'Alice. Le code se calcule à partir de l'étape : le nombre de tranches de 30 secondes dans l'heure de la pendule. Utilise la calculatrice, arrondis vers le bas, puis demande le code au jeton.`, `\`connexion\`, \`examiner pendule\`, \`calc ${x.clock} / 30\` (garde la partie entière), \`generer ${s}\`, puis \`valider ‹le code›\`.`];
    },
    exp: () => ["Un code ne vaut que quelques secondes. Rejoue ton ancien code après avoir laissé passer du temps (le serveur a déjà consommé ce code une fois).", "`attendre 60`, `connexion`, `valider ‹le code que tu avais généré›`."],
    aitm: () => ["Teste le TOTP contre le faux portail de Mallory (bac à sable) : tu joues Alice, qui tape son code sur le faux site.", `\`aller est\` (si besoin), \`simuler proxy\`, \`generer ${step()}\`, puis \`valider ‹le code›\`.`],
    bob2: () => ["Le TOTP tombe aussi. Retourne voir Bob : il a mieux.", "`aller ouest`, `aller sud`, `aller ouest`, `parler bob`."],
    keyreg: () => ["Enrôle la clé de sécurité sur le portail.", "`aller est`, `aller nord`, `activer cle`."],
    keylog: () => ["Connecte Alice avec la clé.", "`utiliser cle sur page`"],
    keyfake: () => ["Rejoue l'attaque par proxy, mais cette fois, c'est la clé qu'on touche, sur le faux portail.", "`aller est`, `simuler proxy`, puis `utiliser cle sur faux`."],
    push: () => ["Reste un dernier facteur à comparer : la notification « Approuver ». Active-la au portail, puis laisse Mallory spammer.", "`aller ouest`, `activer push`, `aller est`, `simuler fatigue`."],
    push2: () => ["La notification est active. Laisse Mallory la spammer.", "`aller est`, `simuler fatigue`."],
    num: () => ["Durcis la notification : Alice devra saisir un nombre affiché à l'écran de connexion.", "`aller ouest`, `activer numero`, `aller est`, `simuler fatigue`."],
    num2: () => ["Rejoue la fatigue contre la notification à nombre.", "`aller est`, `simuler fatigue`."],
    cmp: () => ["Fais le bilan : confronte chaque facteur à chaque attaque.", "`comparer`"],
    end: () => ["Rends compte à Maître Ada.", "`parler ada`"],
    fin: () => ["Audit terminé ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- Courriers : commandes ---------- */
  function inMail(c) {
    if (S.room !== "courrier") { out("Les courriers sont dans la salle du courrier (est du hall).", "sys"); return 0; }
    const n = mailN(c);
    if (!n) { out("Quel courrier ? Un numéro de 1 à 6 : `examiner courrier 1`", "err"); return 0; }
    return n;
  }
  function showMail(n) {
    const m = MAILS[n], x = F(); x.seen[n] = true;
    out(`Courrier ${n}`, "title");
    code(`De      : ${m.name} <${m.addr}>\nRépondre: ${m.reply || "(même adresse)"}\nObjet   : ${m.subj}\nPièce jointe : ${m.att || "aucune"}\n\n${m.body.join("\n")}${m.linkTxt ? "\n\n   [ " + m.linkTxt + " ]" : ""}`);
    out(`Enquête possible : \`survoler ${n}\` (cible réelle du lien), \`entetes ${n}\` (SPF/DKIM/DMARC), \`analyser ${n}\` (le domaine de l'expéditeur). Puis \`signaler ${n}\` ou \`garder ${n}\`.`, "sys");
  }
  function hoverCmd(c) {
    const n = inMail(c); if (!n) return;
    const m = MAILS[n]; F().seen[n] = true;
    if (!m.linkTxt) { out(`Le courrier ${n} ne contient aucun lien.${m.att ? " Mais il a une pièce jointe : " + m.att + "." : ""}`, "sys"); return; }
    out("Tu survoles le lien sans cliquer :", "sys");
    code(`affiché : ${m.linkTxt}\nréel    : ${m.linkReal}`);
    if (hostOf(m.linkTxt) !== hostOf(m.linkReal)) out(`**Les deux ne correspondent pas** : le texte promet « ${hostOf(m.linkTxt)} », le clic mènerait à « ${hostOf(m.linkReal)} ».`, "err");
    else out("Le lien affiché et le lien réel pointent vers le même site, celui de la Guilde.", "ok");
  }
  function headersCmd(c) {
    const n = inMail(c); if (!n) return;
    const m = MAILS[n], x = F(); x.seen[n] = true;
    out(`En-têtes d'authentification du courrier ${n} (simplifiés) :`, "sys");
    code(authLines(m));
    out("SPF : le serveur d'envoi est-il autorisé par le domaine ? DKIM : la signature du message est-elle valide ? DMARC : le domaine « De » est-il aligné, et que faire sinon ?", "sys");
    const a = m.auth;
    if (["spf", "dkim", "dmarc"].every(k => a[k][0] === "pass")) out(m.addr.split("@")[1] === LEGIT ? "Tout passe, pour le domaine officiel de la Guilde : bon signe." : "Tout passe… mais pour QUEL domaine ? Compare avec celui de la Guilde (`analyser " + n + "`). Une authentification valide ne rend pas un domaine honnête.", m.addr.split("@")[1] === LEGIT ? "ok" : "err");
    else out("Au moins un contrôle échoue ou manque : l'expéditeur n'est pas authentifié.", "err");
    note("spf");
  }
  function analyseCmd(c) {
    const n = inMail(c); if (!n) return;
    const m = MAILS[n]; F().seen[n] = true;
    const ad = m.addr.split("@")[1], di = domInfo(ad);
    out(`Analyse du domaine de l'expéditeur du courrier ${n} :`, "sys");
    code(`adresse      : ${m.addr}\ndomaine      : ${ad}\nofficiel     : ${LEGIT}\ncaractères   : ${[...ad].every(ch => ch.charCodeAt(0) < 128) ? "tous ASCII" : [...ad].filter(ch => ch.charCodeAt(0) > 127).map(cp).join(" ") + " hors ASCII"}\ndistance     : ${lev(ad, LEGIT)} modification(s) de l'officiel`);
    out(di.txt, di.kind === "ok" ? "ok" : "err");
    if (di.kind === "ok" && m.reply) out(`Mais le champ « Répondre à » est « ${m.reply} » : un domaine étranger.`, "err");
  }
  function decide(c, sign) {
    const n = inMail(c); if (!n) return;
    const m = MAILS[n], x = F();
    if (!x.seen[n]) { out(`Ouvre-le d'abord : \`examiner courrier ${n}\`.`, "sys"); return; }
    x.dec[n] = sign ? "signal" : "keep";
    const fl = analyse(m), right = sign === m.phish;
    if (right && sign) {
      out(`Bien vu : le courrier ${n} est un hameçonnage. Mis en quarantaine. Voici ce que le moteur de vérification a relevé :`, "ok");
      fl.forEach(([k, t]) => out(`· **${k}** : ${t}`));
    } else if (right) {
      out(`Courrier ${n} gardé : il est légitime. Pourquoi :`, "ok");
      out(`· **En-têtes** : SPF, DKIM et DMARC passent, pour le domaine officiel ${LEGIT}.\n· **Domaine** : l'adresse est exactement celle de la Guilde.${m.linkTxt ? "\n· **Lien** : le lien affiché et le lien réel mènent au même site officiel." : ""}\n· **Demande** : aucune demande de mot de passe, de code ou d'argent par courrier${n === 5 ? " (le message renvoie vers l'application, pas vers un lien de connexion)" : ""}.\n· **Urgence** : aucune pression artificielle.`);
      if (n === 5) out("Une alerte de sécurité n'est pas suspecte en soi : ce qui compte, c'est ce qu'on te demande d'en faire.", "sys");
    } else if (sign) {
      out(`Faux positif : le courrier ${n} est légitime. Aucun indice sérieux : ${fl.length ? fl.map(a => a[0]).join(", ") : "SPF/DKIM/DMARC passent, domaine officiel, lien cohérent, aucune demande sensible"}. Signaler tout et n'importe quoi noie l'équipe de sécurité et apprend aux gens à ignorer les alertes. Réexamine-le (\`entetes ${n}\`, \`survoler ${n}\`) et corrige.`, "err");
    } else {
      out(`Piégé ! Tu as gardé le courrier ${n}, qui est un hameçonnage. Conséquence (simulée) : ${m.trap}`, "err");
      out("Voici les indices que tu pouvais relever :", "sys");
      fl.forEach(([k, t]) => out(`· **${k}** : ${t}`));
      out(`Corrige avec \`signaler ${n}\`.`, "sys");
    }
    if (!x.triaged && triaged()) {
      x.triaged = true; note("phish"); fig("courrier");
      out("Les six courriers sont triés correctement.", "ok");
      say("Maître Ada", "Bien. Mais regarde Alice : avant ton arrivée, elle a cliqué sur le courrier 2 et saisi son mot de passe sur le faux site. Mallory le possède. Un jour, quelqu'un se fera toujours avoir : la vraie question est ce qui arrive ensuite. Va au portail, au nord, puis rends-toi au bac à sable.");
    }
  }

  /* ---------- Simulation des attaques ---------- */
  // renvoie { ok: l'attaquant réussit-il ?, lines }
  function attempt(att, fac) {
    const x = F(), L = [], s = step();
    if (fac === "none") {
      if (att === "rejeu") return { ok: true, lines: [`Mallory ouvre ${ORIGIN} et saisit l'identifiant « alice » et le mot de passe volé « ${PWD} ».`, "Le serveur ne peut pas distinguer Alice de Mallory : il ne vérifie que ce secret. Accès accordé."], cookie: sid("rejeu") };
      return { ok: true, lines: ["Aucun second facteur : Mallory n'a même pas besoin de cette attaque, le mot de passe volé suffit."] };
    }
    if (att === "rejeu") {
      const m = {
        sms: () => { const c = smsCode(x.smsN + 100); return [`Mallory saisit l'identifiant et le mot de passe volés. Le serveur répond : « un code vient d'être envoyé par SMS ».`, `Sur le téléphone d'Alice, un SMS arrive : « Port-443 : votre code est ${c} ». Mallory n'a pas ce téléphone.`, "Elle tente un code au hasard (1 chance sur 1 000 000) : refusé. Après 3 essais, le compte est verrouillé."]; },
        totp: () => ["Le serveur demande le code TOTP à 6 chiffres. Il se calcule avec le secret partagé, qui n'est que dans le jeton d'Alice et sur le serveur.", "Mallory a le mot de passe, pas le secret : elle ne peut pas calculer le code. Refusé."],
        push: () => ["Le serveur envoie une notification « Est-ce vous ? » sur le téléphone d'Alice. Alice ne se connecte pas : elle appuie sur « Refuser ».", "Une seule demande : Mallory échoue. (Si elle insistait ? Voir `simuler fatigue`.)"],
        pushnum: () => ["Le serveur envoie une demande avec saisie d'un nombre. Alice ne se connecte pas : elle la refuse.", "Mallory échoue."],
        key: () => ["Le serveur demande à la clé de signer un défi. Mallory a le mot de passe, mais pas la clé matérielle, ni son code PIN ou son geste de validation.", "Refusé."],
      }[fac]();
      return { ok: false, lines: m };
    }
    if (att === "simswap") {
      if (fac === "sms") {
        const c = smsCode(x.smsN + 200);
        return { ok: true, lines: ["Mallory, avec quelques informations d'Alice trouvées sur les réseaux, appelle l'opérateur : « j'ai perdu ma carte SIM, activez-en une nouvelle ». Le numéro d'Alice migre vers la SIM de Mallory (SIM swap).", `Mallory se connecte avec le mot de passe volé. Le SMS arrive désormais chez elle : « Port-443 : votre code est ${c} ». Elle le saisit.`, "Accès accordé. Le serveur croyait vérifier un appareil ; il vérifiait un numéro."], cookie: sid("simswap") };
      }
      return { ok: false, lines: [{ totp: "Le code TOTP ne passe pas par le réseau mobile : il est calculé dans le jeton. Voler le numéro de téléphone ne donne aucun code.", push: "La notification est liée à l'application installée sur l'appareil d'Alice, pas au numéro de téléphone. Mallory ne reçoit rien.", pushnum: "La notification est liée à l'appareil d'Alice, pas à son numéro. Mallory ne reçoit rien.", key: "Aucun SMS en jeu : la clé est un objet que Mallory n'a pas. Le SIM swap ne lui sert à rien." }[fac]] };
    }
    if (att === "proxy") {
      if (fac === "key") {
        const ch = curCh(), msg = FAKE_ORIGIN + "|" + ch, sig = signMsg(msg);
        const okv = verifyMsg(ORIGIN + "|" + ch, sig);
        return { ok: okv, sig, ch, lines: [`Alice arrive sur ${FAKE_ORIGIN}. Le proxy obtient un défi du vrai site : ${ch}.`, `La clé signe l'origine qu'elle voit réellement + le défi : « ${FAKE_ORIGIN}|${ch} » → signature ${shortN(sig)}.`, `Le proxy la renvoie au vrai site, qui vérifie pour SON origine (${ORIGIN}) : la signature ne correspond pas. Refusé.`] };
      }
      const rel = { sms: () => { const c = smsCode(x.smsN + 300); return [`Alice tape son mot de passe sur le faux portail ; le proxy le relaie. Le vrai site envoie un SMS à Alice : ${c}.`, "Alice le tape sur le faux portail ; le proxy le relaie en une seconde, le serveur compare : identique."]; },
        totp: () => { const c = hotp(SECRET, s).code; const r = verifyTotp(c); return [`Alice tape son mot de passe, puis son code TOTP du moment : ${c}. Le proxy relaie, 1 seconde plus tard.`, `Le serveur calcule le code de l'étape ${s} : identique (${r.ok ? "accepté" : "refusé"}). Le code est encore valable.`]; },
        push: () => ["Alice tape son mot de passe sur le faux portail ; le proxy le relaie. Le vrai site envoie « Est-ce vous ? » : Alice croit approuver SA connexion et appuie sur « Approuver »."],
        pushnum: () => ["Le proxy relaie aussi le nombre affiché par le vrai site à l'écran de connexion : Alice le voit sur le faux portail, le tape sur son téléphone, et approuve. Le nombre protège contre le spam, pas contre un proxy."] }[fac]();
      return { ok: true, lines: [...rel, "Le vrai site répond par un cookie de session ; le proxy le garde. Mallory est connectée en tant qu'Alice, mot de passe et second facteur inclus."], cookie: sid("proxy") };
    }
    if (att === "fatigue") {
      if (fac === "push") return { ok: true, lines: ["Mallory se connecte avec le mot de passe volé, encore et encore. Chaque tentative envoie une notification à Alice.", "Alice en refuse six, de plus en plus agacée. À 3 h du matin, la septième est approuvée « pour que ça s'arrête ».", "Accès accordé : le serveur ne sait pas que cette approbation ne correspondait à aucune action d'Alice."], cookie: sid("fatigue") };
      if (fac === "pushnum") {
        const lines = ["Mallory se connecte à répétition. Chaque tentative affiche un nombre à Mallory ; Alice doit le saisir sur son téléphone, mais elle ne le voit pas."];
        for (let i = 1; i <= 3; i++) { const n = numOf(i), g = guessOf(i); lines.push(`Tentative ${i} : nombre attendu ${String(n).padStart(2, "0")}, Alice (qui ne connaît pas le nombre) tape ${String(g).padStart(2, "0")} : ${g === n ? "accepté" : "refusé"}.`); if (g === n) return { ok: true, lines, cookie: sid("fatigue") }; }
        lines.push("Trois échecs : le compte est verrouillé et Alice est alertée. Une approbation par réflexe ne suffit plus.");
        return { ok: false, lines };
      }
      return { ok: false, lines: [{ sms: "Il n'y a pas de bouton « Approuver » à spammer : le serveur attend un code. Mallory ne peut que faire envoyer des SMS à Alice, sans pouvoir les lire.", totp: "Il n'y a rien à approuver : le serveur attend un code que seul le jeton calcule.", key: "Il n'y a rien à approuver à distance : la clé exige un geste physique, sur place, au bon site." }[fac]] };
    }
    return { ok: false, lines: ["Rien ne se passe."] };
  }
  const ATTS = { rejeu: "rejeu du mot de passe volé", simswap: "SIM swap", proxy: "proxy en temps réel (AitM)", fatigue: "fatigue MFA (spam de notifications)" };
  function simulate(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "repaire") { out("Les attaques simulées se lancent depuis le bac à sable de Mallory (est du portail).", "sys"); return; }
    let att = null;
    if (/rejeu|replay|mdp|mot de passe|password/.test(t)) att = "rejeu";
    else if (/sim|swap|sms/.test(t)) att = "simswap";
    else if (/proxy|aitm|relais|mandataire|faux/.test(t)) att = "proxy";
    else if (/fatigue|push|spam|notif/.test(t)) att = "fatigue";
    if (!att) { out("Quelle attaque ? `simuler rejeu` · `simuler simswap` · `simuler proxy` · `simuler fatigue`", "err"); return; }
    const fac = x.factor;
    out(`Simulation : ${ATTS[att]} contre « ${FACT[fac]} ».`, "title");
    if (att === "proxy" && (fac === "totp" || fac === "key" || fac === "sms")) {
      x.proxy = fac;
      out(`Mallory a envoyé à Alice le lien du faux portail (${FAKE_ORIGIN}), pareil au vrai à un caractère près. Tu joues Alice : elle tape son mot de passe, le faux portail le relaie, et le vrai site réclame le second facteur.`, "");
      if (fac === "totp") out(`Le faux portail demande : « Code à 6 chiffres ». Sors ton jeton : \`generer ${step()}\` (étape courante), puis tape-le sur le faux portail : \`valider ‹code›\`.`, "sys");
      else if (fac === "sms") { x.smsN++; out(`Le vrai site envoie un SMS à Alice : « Port-443 : votre code est ${smsCode(x.smsN)} ». Tape-le sur le faux portail : \`valider ‹code›\`.`, "sys"); }
      else out(`Le faux portail affiche « Touchez votre clé de sécurité ». Fais-le : \`utiliser cle sur faux\`.`, "sys");
      return;
    }
    const r = attempt(att, fac);
    r.lines.forEach(l => out(l));
    if (r.ok) out("**Mallory est dans le compte d'Alice.**" + (r.cookie ? ` (cookie de session volé : sid=${r.cookie})` : ""), "err");
    else out("**L'attaque échoue.**", "ok");
    progress(att, fac, r);
  }
  function progress(att, fac, r) {
    const x = F();
    if (att === "rejeu" && fac === "none" && !x.pwdone) {
      x.pwdone = true; note("why2f");
      say("Maître Ada", "Voilà le problème : un seul secret, et il a fuité. Ajoutons un second facteur, quelque chose que Mallory ne peut pas copier en même temps. Commençons par le plus répandu : le code envoyé par SMS. Retourne au portail (ouest) : `activer sms`.");
    }
    if (att === "simswap" && fac === "sms" && r.ok && !x.smsdone) {
      x.smsdone = true; note("sms");
      say("Maître Ada", "Le SMS ne vérifie qu'un numéro. Il faut un facteur lié à un appareil ou à un secret, pas au réseau. Bob, à l'atelier des jetons (hall, puis ouest), t'attend.");
    }
    if (att === "fatigue" && fac === "push" && r.ok && !x.pushdone) {
      x.pushdone = true; note("fatigue");
      say("Maître Ada", "Une approbation par réflexe est une défense faible. Exigeons qu'Alice prouve qu'elle SAIT quel écran de connexion elle approuve : un nombre à saisir. Portail : `activer numero`.");
    }
    if (att === "fatigue" && fac === "pushnum" && !r.ok && !x.numdone) x.numdone = true;
  }

  /* ---------- Portail ---------- */
  function activate(c) {
    const x = F(), t = norm(c.rawArg);
    if (S.room !== "portail") { out("Les facteurs se règlent au portail des comptes (nord du hall).", "sys"); return; }
    if (/aucun|rien|desactiv/.test(t)) { x.factor = "none"; out("Tu retires tout second facteur : mot de passe seul (utile uniquement pour comparer).", "sys"); return; }
    if (/sms/.test(t)) {
      if (!x.pwdone) { say("Maître Ada", "Pas encore : vois d'abord ce que Mallory fait avec le mot de passe seul (`simuler rejeu` au bac à sable)."); return; }
      x.factor = "sms"; out("Le portail enverra désormais un code à 6 chiffres par SMS au numéro enregistré d'Alice. `connexion` pour l'essayer.", "ok");
    } else if (/totp|jeton|code/.test(t)) {
      if (!x.smsdone || !S.inv.includes("jeton")) { say("Maître Ada", "Tu n'as pas encore de jeton : Bob t'en donnera un après l'étape du SMS."); return; }
      x.factor = "totp";
      out("Enrôlement du jeton : le portail génère un secret et le montre une seule fois (en vrai, sous forme de QR code en base32). Le jeton et le serveur le gardent tous les deux :", "ok");
      code(`secret partagé : ${SECRET}\nalgorithme     : HMAC-SHA-256, 6 chiffres, pas de 30 s`);
      out("`connexion` pour te connecter avec un code.", "sys");
    } else if (/cle|passkey|webauthn|clef/.test(t)) {
      if (!x.bobkey || !S.inv.includes("cle")) { say("Maître Ada", "Tu n'as pas de clé : Bob t'en donnera une."); return; }
      x.factor = "key"; x.keyreg = true;
      out("Enrôlement de la clé : elle crée une paire de clés pour CE site (identifiant : guilde-port443.org). Le serveur ne reçoit que la clé publique ; la privée ne quitte jamais la clé.", "ok");
      code(`clé publique (envoyée au serveur) :\n  n = ${N}\n  e = ${E}\nclé privée : reste dans la clé (jamais transmise)`);
      out("(Clé jouet : RSA en miniature, sur 52 bits. Les vraies passkeys utilisent ECDSA ou Ed25519.) `utiliser cle sur page` pour te connecter.", "sys");
    } else if (/numero|nombre|correspondance|matching/.test(t)) {
      if (!x.pushdone) { say("Maître Ada", "Pas encore : vois d'abord la notification simple (`activer push`, puis `simuler fatigue`)."); return; }
      x.factor = "pushnum"; out("Le portail affichera un nombre à 2 chiffres ; Alice devra le saisir sur son téléphone pour approuver.", "ok");
    } else if (/push|notif|approuver/.test(t)) {
      if (!x.keyfake) { say("Maître Ada", "Une chose à la fois : termine d'abord l'étape de la clé de sécurité."); return; }
      x.factor = "push"; out("Le portail enverra une notification « Est-ce vous ? » avec les boutons Approuver / Refuser. `simuler fatigue` au bac à sable pour la tester.", "ok");
    } else out("Quel facteur ? `activer sms` · `activer totp` · `activer cle` · `activer push` · `activer numero` · `activer aucun`", "err");
  }
  function connect() {
    const x = F();
    if (S.room !== "portail") { out("La connexion se joue sur la page du portail (nord du hall).", "sys"); return; }
    out("Alice tape son identifiant et son mot de passe : le portail les accepte.", "sys");
    x.login = null;
    switch (x.factor) {
      case "none": out("Aucun second facteur : Alice est connectée. (Mallory aurait pu faire pareil.)", "ok"); break;
      case "sms": x.smsN++; x.login = "sms"; out(`Le portail envoie un SMS. Sur le téléphone d'Alice : « Port-443 : votre code est ${smsCode(x.smsN)} ».`, "sys"); out("Saisis-le : `valider ‹code›`.", "sys"); break;
      case "totp": x.login = "totp"; out("Le portail demande le code à 6 chiffres du jeton. `valider ‹code›` (le code se génère avec `generer ‹étape›`).", "sys"); break;
      case "key": out("Le portail demande à la clé de signer un défi : `utiliser cle sur page`.", "sys"); break;
      case "push": out("Une notification arrive sur le téléphone d'Alice : « Est-ce vous ? ». Elle reconnaît sa propre connexion et appuie sur Approuver. Connectée.", "ok"); break;
      case "pushnum": out(`Le portail affiche le nombre ${String(numOf(0)).padStart(2, "0")} ; Alice, qui voit l'écran, le saisit sur son téléphone. Connectée.`, "ok"); break;
    }
  }
  function validate(c) {
    const x = F(), v = (c.rawArg || "").replace(/\s+/g, "");
    if (S.room === "repaire") {
      if (!x.proxy) { out("Rien à valider ici pour l'instant. (`simuler proxy` lance une simulation où tu joues Alice.)", "sys"); return; }
      if (!/^\d{6}$/.test(v)) { out("Un code à 6 chiffres : `valider ‹code›`.", "err"); return; }
      if (x.proxy === "sms") {
        if (v !== smsCode(x.smsN)) { out("Le faux portail relaie, le vrai site refuse : ce n'est pas le code du SMS. Réessaie.", "err"); return; }
        out("Alice tape le code sur le faux portail ; le proxy le relaie à l'instant. Accepté par le vrai site. Mallory récupère le cookie de session : **Mallory est dans le compte** (sid=" + sid("proxy") + ").", "err"); x.proxy = null; return;
      }
      const r = verifyTotp(v);
      if (!r.ok) { out(r.d !== null ? `Le vrai site refuse : ce code est celui de l'étape ${r.step}, l'étape courante est ${step()}. Le proxy relaie à l'instant : il faut un code de l'étape courante. Régénère-le.` : "Le vrai site refuse ce code. Génère-le avec `generer ‹étape›` (étape courante : " + step() + ").", "err"); return; }
      if (x.used[r.step]) { out("Le vrai site refuse : ce code a déjà été utilisé (étape " + r.step + "). Laisse passer une tranche : `attendre 30`, puis `generer " + (step() + 1) + "`... ou régénère pour l'étape courante.", "err"); return; }
      x.used[r.step] = true; x.proxy = null;
      out(`Alice tape le code ${v} sur le faux portail. Le proxy le relaie au vrai site 1 seconde plus tard ; il reste ${30 - (x.clock % 30)} s dans la tranche : le serveur le calcule de son côté (étape ${r.step}), c'est identique. Accepté.`, "sys");
      out(`Le vrai site renvoie un cookie de session ; le proxy le copie : **Mallory est dans le compte d'Alice** (sid=${sid("proxy")}). Le code, le mot de passe, tout était valide, simplement tapé sur le mauvais site.`, "err");
      if (!x.aitm) {
        x.aitm = true; note("aitm"); fig("aitm");
        say("Maître Ada", "Le TOTP n'a pas vérifié QUI demandait le code : il ne sait pas où Alice l'a tapé. Il nous faut un facteur qui lie la réponse au site. Retourne voir Bob (hall, puis ouest).");
      }
      return;
    }
    if (S.room !== "portail") { out("Les codes se valident au portail.", "sys"); return; }
    if (!x.login) { out("Aucune connexion en cours. `connexion` d'abord.", "sys"); return; }
    if (!/^\d{6}$/.test(v)) { out("Un code à 6 chiffres : `valider ‹code›`.", "err"); return; }
    if (x.login === "sms") {
      if (v !== smsCode(x.smsN)) { out("Code SMS incorrect.", "err"); return; }
      x.login = null; out("Code SMS accepté : Alice est connectée.", "ok"); return;
    }
    const r = verifyTotp(v);
    if (r.ok && x.used[r.step]) { out(`Refusé : ce code (étape ${r.step}) a déjà été utilisé. Un code TOTP ne sert qu'une fois, même dans sa fenêtre de validité.`, "err"); return; }
    if (r.ok) {
      x.used[r.step] = true; x.login = null;
      out(`Accepté. Le serveur a calculé le code de l'étape ${step()}${r.d ? ` (et ses voisines ±1 : le tien est celui de l'étape ${r.step}, toléré pour la dérive d'horloge)` : ""} et l'a trouvé identique. Alice est connectée.`, "ok");
      if (!x.gen) { x.gen = true; note("totp"); fig("totp"); out("Le code a été consommé : ce même code est maintenant inutilisable.", "sys"); }
      return;
    }
    if (r.d !== null && r.d < -1) {
      out(`Refusé : ce code est celui de l'étape ${r.step}, soit ${-r.d} tranches de 30 s (au moins ${-r.d * 30 - (x.clock % 30)} s) plus tôt. Le serveur n'accepte que l'étape courante (${step()}) et ses voisines. Un code volé ou noté est périmé en un instant.`, "err");
      if (!x.expired && x.gen) { x.expired = true; out("Voilà pourquoi un code TOTP intercepté sert peu… sauf s'il est relayé immédiatement.", "sys"); }
    } else if (r.d !== null) out(`Refusé : ce code correspond à l'étape ${r.step}, pas à l'étape courante (${step()}).`, "err");
    else out("Refusé : ce code ne correspond à aucune étape récente. Vérifie l'étape utilisée pour le générer (`generer ‹étape›`).", "err");
  }
  function generate(c) {
    const x = F();
    if (!S.inv.includes("jeton")) { out("Tu n'as pas de jeton. Bob en a un.", "err"); return; }
    let s = null;
    const a = (c.rawArg || "").trim();
    if (/^\d+$/.test(a)) s = parseInt(a, 10);
    else if (/maintenant|now|courant/i.test(a) && x.gen) s = step();
    else { out(`Le jeton calcule le code d'une étape précise : \`generer ‹étape›\`. L'étape, c'est ⌊heure ÷ 30⌋ (partie entière) : lis la pendule du portail (\`examiner pendule\`) et utilise \`calc ‹expression›\`.${x.gen ? " Tu connais la manœuvre : `generer maintenant` marche aussi." : ""}`, "err"); return; }
    const r = hotp(SECRET, s), hx = r.h.map(hex2).join("");
    out("Le jeton calcule :", "sys");
    code(`secret partagé : ${SECRET}\nétape          : ${s}\nHMAC-SHA-256(secret, étape sur 8 octets) =\n  ${hx.slice(0, 32)}\n  ${hx.slice(32)}\ndernier octet → décalage ${r.off} ; octets ${r.h.slice(r.off, r.off + 4).map(hex2).join(" ")} → 31 bits = ${r.bin}\n${r.bin} mod 1 000 000 = ${r.code}`);
    out(`Code du jeton pour l'étape ${s} : **${r.code}**` + (s === step() ? ` (étape courante : valable encore ${30 - (x.clock % 30)} s environ)` : s < step() ? " (une étape passée : ce code est périmé)" : " (une étape future)"), "ok");
    x.lastCode = r.code;
  }
  function wait(c) {
    const x = F(), n = parseInt(c.rawArg, 10);
    if (!n || n < 1 || n > 3600) { out("Combien de secondes ? `attendre 60`", "err"); return; }
    x.clock += n;
    out(`Tu patientes ${n} s. Pendule : ${x.clock} (${stamp(x.clock)}), étape ${step()}, il reste ${30 - (x.clock % 30)} s dans la tranche.`, "sys");
  }
  function useCle(c) {
    const x = F(), ch = curCh();
    if (!x.bobkey) { out("Tu n'as pas la clé.", "err"); return; }
    if (S.room === "repaire") {
      if (x.proxy !== "key") { out("Pas de demande de la clé en ce moment : lance `simuler proxy` avec la clé active.", "sys"); return; }
      const r = attempt("proxy", "key");
      out("Alice touche sa clé sur le faux portail.", "sys");
      r.lines.forEach(l => out(l));
      code(`défi du vrai site        : ${r.ch}\nce que la clé signe      : ${FAKE_ORIGIN}|${r.ch}\nce que le serveur attend : ${ORIGIN}|${r.ch}\nsignature (n=${shortN(N)}) : ${r.sig}\nsig^e mod n (côté serveur) : ${modpow(r.sig, E, N)}\nempreinte attendue        : ${hm(ORIGIN + "|" + r.ch)}`);
      out("**Refusé.** La réponse est cryptographiquement liée au faux site : Mallory ne peut ni la rejouer sur le vrai ni la modifier (elle n'a pas la clé privée). Et en vrai, le navigateur n'aurait même pas proposé la passkey pour ce domaine.", "ok");
      x.proxy = null; x.keyN = (x.keyN || 0) + 1;
      if (!x.keyfake) { x.keyfake = true; note("webauthn"); fig("webauthn", true); say("Maître Ada", "C'est ça, un facteur résistant à l'hameçonnage. Reste à comparer les autres : la simple notification (fatigue MFA). Retourne au portail : `activer push`."); }
      return;
    }
    if (S.room !== "portail") { out("La clé se touche devant la page de connexion du portail.", "sys"); return; }
    if (x.factor !== "key") { out("La clé n'est pas enrôlée sur le portail : `activer cle`.", "sys"); return; }
    out("Alice saisit son mot de passe, puis le portail lance l'authentification WebAuthn.", "sys");
    const msg = ORIGIN + "|" + ch, sig = signMsg(msg), ok = verifyMsg(msg, sig);
    code(`serveur → navigateur : défi aléatoire ${ch}\nnavigateur → clé    : origine ${ORIGIN} + défi\nclé : signe « ${msg} » avec sa clé privée\n  signature = ${sig}\nserveur : sig^e mod n = ${modpow(sig, E, N)}\n          empreinte attendue = ${hm(msg)}  → ${ok ? "identique" : "différent"}`);
    out("Signature valide : Alice est connectée. Aucun code recopié, aucun secret transmis ; le défi change à chaque connexion.", "ok");
    x.keyN = (x.keyN || 0) + 1;
    if (!x.keylog) { x.keylog = true; fig("webauthn"); say("Maître Ada", "Mais ce n'est pas tout : voyons ce qui se passe quand Alice se laisse berner par le faux portail. Au bac à sable : `simuler proxy`."); }
  }
  function compare() {
    const x = F();
    const facs = ["none", "sms", "totp", "push", "pushnum", "key"], atts = ["rejeu", "simswap", "proxy", "fatigue"];
    out("Bilan : chaque facteur face à chaque attaque (simulations réelles du jeu)", "title");
    let tx = "Facteur".padEnd(30) + "rejeu  SIM   proxy fatig.\n";
    const lbl = { none: "mot de passe seul", sms: "+ SMS", totp: "+ TOTP", push: "+ notification simple", pushnum: "+ notification à nombre", key: "+ clé WebAuthn" };
    for (const fc of facs) tx += lbl[fc].padEnd(30) + atts.map(a => (attempt(a, fc).ok ? "✘" : "✔").padEnd(a === "simswap" ? 6 : a === "proxy" ? 6 : 7)).join("") + "\n";
    code(tx);
    out("✘ : l'attaquant réussit · ✔ : l'attaque est bloquée. (Une attaque non pertinente pour un facteur est comptée comme bloquée.)", "sys");
    out("Seule la clé WebAuthn résiste aux quatre. Le TOTP vaut mieux que le SMS, mais tombe devant un proxy. Les notifications, sans nombre, tombent devant la fatigue.", "ok");
    if (!x.cmp) { x.cmp = true; fig("compare"); say("Maître Ada", "Tu as tout comparé. Viens me voir : il est temps de conclure."); }
  }

  /* ---------- Dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "ada": {
        if (!x.quest) {
          x.quest = true;
          say("Maître Ada", "Bienvenue. La Guilde reçoit chaque jour des courriers piégés, et un jour ou l'autre, quelqu'un se laisse prendre. Notre Sceau a deux serrures : un secret qu'on connaît, un objet qu'on possède. Ton audit : d'abord apprendre à reconnaître les pièges, puis comprendre ce qui protège un compte quand le mot de passe est quand même volé.");
          say("Maître Ada", "Tout est simulé sur des données fictives, avec l'accord de la Guilde. Commence par la salle du courrier, à l'est.");
          out("`aller est`, puis `examiner courrier 1`.", "sys");
        } else if (x.end) say("Maître Ada", "Merci pour cet audit. Le Sceau tient.");
        else if (objective() === "end") ending();
        else if (objective() === "mails") say("Maître Ada", "Six courriers t'attendent à l'est. Examine, enquête, tranche : un mauvais choix peut être corrigé.");
        else say("Maître Ada", "L'audit continue. `indice` si tu bloques.");
        break;
      }
      case "alice":
        if (!x.triaged) say("Alice", "Je ne devrais pas te parler avant que le courrier soit trié ? On me dit que j'ai cliqué sur quelque chose…");
        else if (!x.pwdone) say("Alice", "J'ai saisi mon mot de passe sur un faux site… Je n'ai rien vu venir. Tout le monde peut se faire avoir, non ?");
        else if (!x.gen) say("Alice", "Joue ma connexion avec `connexion` : je tape mon mot de passe, puis il y a un second facteur.");
        else if (!x.keylog) say("Alice", "Mon jeton marche bien, mais Mallory arrive quand même à se connecter ? C'est inquiétant.");
        else say("Alice", "Avec la clé, je n'ai rien à recopier. Je préfère, de loin.");
        break;
      case "bob":
        if (!x.smsdone) say("Bob", "Je fabrique des jetons et des clés. Reviens quand tu auras vu ce que vaut un code par SMS.");
        else if (!x.bobjeton) {
          x.bobjeton = true; give("jeton");
          say("Bob", "Le SMS prouve un numéro, pas un appareil. Voici mieux : un jeton TOTP. Au moment de l'enrôlement, le serveur et ce jeton se partagent un secret. Ensuite, chacun calcule, indépendamment, un code à partir de ce secret et de l'heure (par tranches de 30 secondes). Rien ne voyage, et le code change tout le temps.");
          out("Tu reçois **le jeton d'Alice**. Retourne au portail : `activer totp`.", "ok");
        } else if (x.aitm && !x.bobkey) {
          x.bobkey = true; give("cle");
          say("Bob", "Le proxy relaie ce qu'Alice tape. Il faut que la réponse dépende du SITE. Voici une clé FIDO2 : le site envoie un défi aléatoire ; la clé le signe avec une clé privée qui ne sort jamais, en y joignant l'origine réelle vue par le navigateur. Un faux site obtient une réponse qui ne vaut que pour lui.");
          out("Tu reçois **la clé de sécurité**. Portail : `activer cle`.", "ok");
        } else if (!x.aitm) say("Bob", "Ton jeton est à jour. Essaie de comprendre combien de temps vit un code, et à qui Alice peut le taper.");
        else say("Bob", "La clé fait son travail. N'oublie pas d'en avoir une de secours : en perdre l'unique exemplaire, c'est perdre son compte.");
        break;
      case "eve":
        if (!x.smsdone) say("Ève", "J'écoute ce qui passe sur la ligne. Les SMS, eux, ne sont pas chiffrés comme un site en HTTPS : un opérateur négligent, un réseau mobile mal protégé, une carte SIM détournée, et ils sont lisibles.");
        else say("Ève", "Un code TOTP, lui, ne passe pas par le réseau mobile. Mais s'il est tapé sur un faux site, je n'ai même plus besoin d'écouter : Mallory le reçoit directement.");
        break;
      case "mallory":
        say("Mallory", "(Jouée par Ada, pour l'exercice.) Je rejoue ce que fait une vraie attaquante : lance `simuler ‹attaque›` et regarde, étape par étape, si je passe. Rien n'est réel ici.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Maître Ada", "Nous allons déployer des passkeys à toute la Guilde, garder un TOTP pour les comptes qui ne peuvent pas encore en avoir, et supprimer le SMS pour les comptes sensibles. Et les courriers piégés continueront d'arriver : la formation et le signalement restent notre première ligne de défense.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**Le Sceau à deux clés = l'authentification multifacteur (MFA).** On combine des facteurs de natures différentes : ce qu'on sait (mot de passe), ce qu'on possède (téléphone, clé), ce qu'on est (biométrie). Voler un seul ne suffit pas.");
    out("**La salle du courrier = la messagerie, et ses pièges = le phishing.** Domaines trompeurs (typosquatting : « p0rt443 », ou homoglyphes : une lettre cyrillique qui imite une lettre latine, que le navigateur peut afficher en « xn-- »), lien affiché ≠ lien réel, usurpation de l'expéditeur, urgence, pièce jointe à double extension.");
    out("**SPF, DKIM, DMARC.** SPF : quels serveurs peuvent envoyer pour un domaine ; DKIM : signature vérifiable par clé publique dans le DNS ; DMARC : politique (rien, quarantaine, rejet) quand ils ne s'alignent pas avec l'adresse « De ». Ils combattent l'usurpation d'un domaine, pas le typosquatting : un domaine voisin peut avoir tous ses « pass ».");
    out("**Le code par SMS.** Il prouve un numéro de téléphone, pas un appareil : SIM swap, interception, redirection d'appels. Mieux que rien, mais déconseillé pour les comptes sensibles.");
    out("**Le jeton d'Alice = TOTP (RFC 6238).** Secret partagé + temps : code = troncature de HMAC(secret, ⌊heure ÷ 30⌋). Ici, un vrai HMAC-SHA-256 construit sur le SHA-256 du moteur ; les applications du commerce utilisent en général HMAC-SHA-1 par défaut. Le serveur accepte l'étape courante et ses voisines (dérive d'horloge) et refuse de rejouer un code. Il n'est valable que quelques dizaines de secondes.");
    out("**Le faux portail = un proxy AitM (adversary-in-the-middle).** Il relaie en direct mot de passe, code et cookie de session. Aucun code saisi par l'humain n'y résiste, ni SMS, ni TOTP, ni notification (même avec number matching, car le proxy relaie aussi le nombre).");
    out("**La clé de sécurité = WebAuthn / FIDO2 (passkeys).** Inscription : une paire de clés par site, seule la clé publique est enregistrée. Connexion : le serveur envoie un défi ; l'authentificateur signe (défi + origine vue par le navigateur) avec la clé privée ; le serveur vérifie avec la clé publique. Un faux site obtient une signature valable seulement pour lui, et le navigateur ne propose la passkey qu'à son vrai domaine (RP ID). Rien à recopier : le phishing de ce facteur ne fonctionne pas.");
    out("**La fatigue MFA = bombardement de notifications.** Une approbation par réflexe n'est pas une vérification. Parades : saisie d'un nombre, limite de demandes, alerte, préférence pour les facteurs sans « Approuver ».");
    out("**Les simplifications du jeu.** (1) La signature « WebAuthn » est un RSA jouet de 52 bits sans remplissage ; les vraies utilisent ECDSA/Ed25519 sur une structure authenticatorData + clientDataJSON, avec compteur et RP ID. L'attestation, la synchronisation des passkeys, la récupération de compte et les clés de secours ne sont pas modélisées. (2) Le TOTP est réel mais le secret s'affiche en clair (en vrai : QR code en base32), sans limitation de débit ni resynchronisation. (3) L'analyse des courriers est un jeu de règles lisibles ; les vrais filtres combinent réputation, apprentissage automatique et signalements, et un courrier piégé peut très bien passer toutes les vérifications. (4) SIM swap et interception sont résumés. (5) Un nouvel utilisateur peut aussi être piégé hors messagerie (SMS, appel, QR code, faux support) : la vigilance ne se limite pas aux courriers. (6) Tout est simulé, sur des données fictives, dans un cadre d'audit autorisé.");
    out("Rappel utile : **un mot de passe se vole, un code se relaie : seul un facteur lié au site (clé ou passkey WebAuthn) résiste au phishing. Active-le partout où c'est possible, garde une clé de secours, et signale les courriers suspects plutôt que de les ignorer.**", "ok");
  }

  /* ---------- Schémas ---------- */
  const figs = {
    courrier: () => {
      const row = (y, txt, c) => R(8, y, 244, 34, c) + T(16, y + 21, txt, "f-s", "start");
      const call = (y, n, a, b) => AR(252, y + 17, 270, y + 17, "f-bad") + T(278, y + 14, n + " " + a, "f-b ft-bad f-s", "start") + T(278, y + 27, b, "f-s", "start");
      return {
        cap: "Anatomie d'un courrier piégé : cinq endroits où chercher des indices.",
        svg: SVG(250, "Anatomie d'un courrier piégé",
          T(8, 14, "Courrier piégé (exemple)", "f-b", "start") +
          row(22, "De : support@guilde-p0rt443.org", "f-bad") + call(22, "①", "Domaine", "p0rt ≠ port") +
          row(60, "Objet : expire dans 24 h !", "f-bad") + call(60, "②", "Urgence", "pression, secret") +
          row(98, "Lien : guilde-port443.org/…", "f-bad") + call(98, "③", "Lien masqué", "réel : …p0rt443.org") +
          row(136, "PJ : Facture.pdf.exe", "f-bad") + call(136, "④", "Pièce jointe", "double extension") +
          row(174, "SPF · DKIM · DMARC", "f-pub") + AR(252, 191, 270, 191, "f-pub") + T(278, 188, "⑤ En-têtes", "f-b ft-pub f-s", "start") + T(278, 201, "usurpation ?", "f-s", "start") +
          T(8, 236, "Ils passent même pour un domaine voisin : toujours croiser avec ①.", "f-s", "start"))
      };
    },
    totp: () => {
      const x = F(), s = step(), r = hotp(SECRET, s), el = x.clock % 30;
      return {
        cap: `Génération d'un TOTP à l'étape ${s} (heure ${x.clock}) : le téléphone et le serveur calculent la même chose, sans rien échanger.`,
        svg: SVG(190, "Génération d'un code TOTP",
          R(8, 14, 130, 44, "f-priv") + T(73, 33, "secret partagé", "f-b ft-priv") + T(73, 48, "(donné une fois)", "f-s") +
          R(8, 70, 130, 44, "f-pub") + T(73, 89, "étape = ⌊t / 30⌋", "f-b ft-pub") + T(73, 104, "= " + s, "f-s") +
          AR(138, 36, 176, 56, "f-priv") + AR(138, 92, 176, 74, "f-pub") +
          R(176, 40, 110, 50) + T(231, 61, "HMAC-SHA-256", "f-b") + T(231, 78, "+ troncature", "f-s") +
          AR(286, 65, 316, 65) + R(316, 40, 96, 50, "f-ok") + T(364, 58, "code", "f-s") + T(364, 79, r.code, "f-b ft-ok") +
          T(8, 140, "Valable sur une tranche de 30 s (±1 tolérée) :", "f-s", "start") +
          R(8, 148, 404, 14) + `<rect x="8" y="148" width="${Math.round(404 * el / 30)}" height="14" rx="3" fill="var(--bad)" opacity=".5"/>` +
          T(8, 180, "début", "f-s", "start") + T(412, 180, "fin : nouveau code", "f-s", "end") + T(8 + 404 * el / 30, 176, "▲ " + el + " s", "f-s ft-bad"))
      };
    },
    aitm: () => ({
      cap: "Le proxy AitM : Alice voit le vrai site, Mallory capte tout au passage, y compris le code et le cookie de session.",
      svg: SVG(230, "Attaque par proxy en temps réel",
        R(8, 20, 100, 58) + T(58, 42, "Alice", "f-b") + T(58, 58, "tape tout sur", "f-s") + T(58, 70, "le faux site", "f-s") +
        R(160, 20, 100, 58, "f-bad") + T(210, 42, "Proxy", "f-b ft-bad") + T(210, 58, "de Mallory", "f-s") + T(210, 70, "p0rt443", "f-s") +
        R(312, 20, 100, 58, "f-ok") + T(362, 42, "Vrai site", "f-b ft-ok") + T(362, 58, "guilde-", "f-s") + T(362, 70, "port443.org", "f-s") +
        AR(108, 36, 160, 36, "f-bad") + AR(260, 36, 312, 36, "f-bad") + AR(312, 62, 260, 62, "f-ok") + AR(160, 62, 108, 62, "f-ok") +
        T(210, 108, "① mot de passe  ② code TOTP (relayé en 1 s)", "f-s") +
        T(210, 128, "③ le vrai site renvoie le cookie de session", "f-s") +
        T(210, 148, "④ Mallory le copie : elle est connectée.", "f-b ft-bad f-s") +
        T(210, 184, "Rien n'a été « cassé » : le code était valide,", "f-s") + T(210, 200, "il a simplement été tapé sur le mauvais site.", "f-s") +
        T(210, 222, "Le TOTP ne vérifie pas l'origine.", "f-b ft-bad f-s"))
    }),
    webauthn: fake => {
      const ch = chal(Math.max(0, (F().keyN || 1) - 1)), mReal = ORIGIN + "|" + ch, mFake = FAKE_ORIGIN + "|" + ch, sR = signMsg(mReal), sF = signMsg(mFake);
      return {
        cap: "WebAuthn : la clé signe défi + origine réelle. Sur le faux site, la signature produite ne vaut que pour le faux site.",
        svg: SVG(260, "Défi-réponse WebAuthn lié à l'origine",
          R(8, 14, 110, 50, "f-pub") + T(63, 33, "Serveur", "f-b ft-pub") + T(63, 50, "clé publique", "f-s") +
          R(160, 14, 96, 50) + T(208, 33, "Navigateur", "f-b") + T(208, 50, "voit l'origine", "f-s") +
          R(300, 14, 112, 50, "f-priv") + T(356, 33, "Clé", "f-b ft-priv") + T(356, 50, "clé privée", "f-s") +
          AR(118, 30, 160, 30) + AR(256, 30, 300, 30) + AR(300, 50, 256, 50) + AR(160, 50, 118, 50) +
          T(8, 86, "défi = " + ch + " ; signature = H(origine|défi)^d mod n", "f-s", "start") +
          R(8, 98, 404, 70, "f-ok") + T(16, 116, "Vrai site : " + ORIGIN, "f-b ft-ok f-s", "start") +
          T(16, 134, "signature " + shortN(sR), "f-s", "start") + T(16, 152, "le serveur vérifie avec e : ✔ identique", "ft-ok f-s", "start") +
          R(8, 178, 404, 70, "f-bad") + T(16, 196, "Faux site : " + FAKE_ORIGIN, "f-b ft-bad f-s", "start") +
          T(16, 214, "signature " + shortN(sF) + " (origine fausse)", "f-s", "start") + T(16, 232, "relayée au vrai site : " + (verifyMsg(mReal, sF) ? "?" : "✘ ne correspond pas"), "ft-bad f-s", "start"))
      };
    },
    compare: () => {
      const facs = ["none", "sms", "totp", "push", "pushnum", "key"], atts = ["rejeu", "simswap", "proxy", "fatigue"];
      const lbl = { none: "mot de passe seul", sms: "+ SMS", totp: "+ TOTP", push: "+ push simple", pushnum: "+ push à nombre", key: "+ clé WebAuthn" };
      const head = ["rejeu", "SIM swap", "proxy", "fatigue"];
      let b = "";
      head.forEach((h, i) => b += T(206 + i * 52 + 24, 18, h, "f-s"));
      facs.forEach((fc, j) => {
        const y = 28 + j * 30;
        b += T(8, y + 19, lbl[fc], "f-s", "start");
        atts.forEach((a, i) => { const ok = attempt(a, fc).ok; b += R(206 + i * 52 + 2, y, 46, 24, ok ? "f-bad" : "f-ok") + T(206 + i * 52 + 25, y + 17, ok ? "✘" : "✔", "f-b " + (ok ? "ft-bad" : "ft-ok")); });
      });
      b += T(8, 224, "✘ l'attaquant réussit · ✔ bloquée", "f-s", "start");
      return { cap: "Comparaison finale : seule la clé WebAuthn, liée à l'origine, résiste aux quatre attaques.", svg: SVG(240, "Facteurs contre attaques", b) };
    },
  };

  GAMES.mfa = {
    id: "mfa", order: 12, title: "Le Sceau à Deux Clés", pageTitle: "MFA Quest", subtitle: "aventure textuelle · phishing, TOTP, WebAuthn",
    blurb: "Trie un courrier piégé, génère un vrai code TOTP, puis déjoue un proxy en temps réel avec une clé WebAuthn.",
    concept: "Phishing, TOTP, WebAuthn",
    start: "hall", firstCommand: "parler ada",
    ents, rooms, notes, hints, figs, objective, talk, debrief, isEnd: () => !!F().end,
    setup() { const x = F(); x.clock = T0; x.factor = "none"; x.dec = {}; x.seen = {}; x.used = {}; x.smsN = 1; x.keyN = 0; },
    refig(name) { fig(name, name === "webauthn" ? !!F().keyfake : undefined); },
    figAlias: { courrier: ["mail", "phishing", "courriel", "anatomie"], totp: ["code", "otp", "temps"], aitm: ["proxy", "relais"], webauthn: ["cle", "passkey", "origine"], compare: ["comparaison", "tableau", "bilan"] },
    help: "Spécifiques : `signaler ‹n›` · `garder ‹n›` · `survoler ‹n›` · `entetes ‹n›` · `analyser ‹n›` · `activer ‹facteur›` · `connexion` · `valider ‹code›` · `generer ‹étape›` · `attendre ‹s›` · `simuler ‹attaque›` · `comparer`",
    gate(dest) {
      const x = F();
      if ((dest === "portail" || dest === "repaire") && !x.triaged) { say("Maître Ada", "Pas encore : le courrier d'abord (salle à l'est du hall). Il faut trier les six messages."); return true; }
      if (dest === "atelier" && !x.smsdone) { say("Maître Ada", "L'atelier de Bob n'est utile qu'après ton essai du SMS : ne brûlons pas les étapes."); return true; }
      return false;
    },
    use(key, a, b) {
      if (key === "cle+page") { useCle(); return; }
      if (key === "cle+faux") { useCle(); return; }
      if (key === "jeton+page") { out("Le jeton ne se branche pas : il calcule un code. `generer ‹étape›`, puis `valider ‹code›` (après `connexion`).", "sys"); return; }
      if (key === "faux+page") { out("Le faux portail n'est pas lié au vrai : il ne fait que relayer.", "sys"); return; }
      return false;
    },
    verbs: {
      report: { words: ["signaler", "reporter", "denoncer", "quarantaine"], run: c => decide(c, true) },
      keep: { words: ["garder", "conserver", "classer", "laisser"], run: c => decide(c, false) },
      hover: { words: ["survoler", "survol", "cible"], run: hoverCmd },
      headers: { words: ["entetes", "entete", "headers", "en tetes"], run: headersCmd },
      analyze: { words: ["analyser", "analyse", "domaine", "decoder"], run: analyseCmd },
      activate: { words: ["activer", "adopter", "enroler"], run: activate },
      connect: { words: ["connexion", "connecter", "login", "se"], run: connect },
      validate: { words: ["valider", "taper", "code"], run: validate },
      generate: { words: ["generer", "genere", "totp"], run: generate },
      wait: { words: ["attendre", "patienter", "attends"], run: wait },
      simulate: { words: ["simuler", "simulation", "lancer"], run: simulate },
      compare: { words: ["comparer", "comparaison", "tableau"], run: compare },
    },
    intro() {
      out("Le Sceau à Deux Clés", "title");
      out("Sous la voûte de la Guilde de Port-443 trône un coffre dont le Sceau a deux serrures. Mais chaque matin, le courrier apporte son lot de pièges, et la doyenne, Maître Ada, sait qu'un seul mot de passe volé peut suffire à tout ouvrir. Elle t'engage pour un audit autorisé : apprendre à reconnaître les courriers piégés, puis comprendre ce qui protège encore un compte quand le mot de passe est tombé dans de mauvaises mains. Tout est simulé, sur des données fictives.", "");
    },
  };
})();
