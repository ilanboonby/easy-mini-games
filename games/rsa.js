"use strict";
/* La Forge de Rivest : RSA fabriqué à la main avec de petits nombres. */
(function () {
  const BIG_N = 1000036000099; // 1000003 × 1000033
  const BIG_MAX = 3000000;
  const F = () => f();

  const notes = {
    premiers: ["Deux nombres premiers secrets", "RSA commence par deux grands nombres premiers p et q, gardés secrets. Un nombre premier n'a pas d'autre diviseur que 1 et lui-même."],
    n: ["Le module n = p × q", "Multiplier deux nombres est facile. n sera public : il fait partie des deux clés."],
    phi: ["φ(n) = (p−1)(q−1)", "Cette valeur ne se calcule facilement que si l'on connaît p et q. Elle reste secrète : c'est elle qui permet de fabriquer la clé privée."],
    ed: ["Les exposants e et d", "On choisit e premier avec φ, puis on trouve d tel que e × d ≡ 1 (mod φ). La clé publique est (e, n), la privée (d, n)."],
    chiffrer: ["Chiffrer : c = m^e mod n", "Avec la clé publique, n'importe qui chiffre un message m (un nombre plus petit que n). Calculer c est facile, même avec de grands nombres."],
    dechiffrer: ["Déchiffrer : m = c^d mod n", "Seule la clé privée (d) permet de retrouver m. Essayer de déchiffrer avec la clé publique donne un résultat sans rapport."],
    signer: ["Signer : s = m^d mod n", "On inverse les rôles : la clé privée produit la signature, la clé publique la vérifie (s^e mod n doit redonner m)."],
    securite: ["Sécurité : la factorisation", "Casser RSA revient à retrouver p et q à partir de n. Avec 3 chiffres c'est immédiat, avec 13 chiffres une seconde, avec 617 chiffres (RSA-2048) c'est hors de portée. En pratique on ajoute un bourrage aléatoire (OAEP, PSS) car le RSA « brut » est dangereux."],
  };

  const ents = {
    rivest: { npc: true, names: ["rivest", "dame rivest", "forgeronne", "serruriere"], label: "Dame Rivest, forgeronne de clés",
      desc: () => "Dame Rivest, bras couverts de suie, une clé à molette dans une main et un parchemin de calculs dans l'autre. Elle forge les paires de clés de toute la ville." },
    etabli: { names: ["etabli", "forge", "enclume"], label: "un établi", desc: () => "Sur l'établi : un cadenas ouvert, une clé, et un parchemin « 1. Choisir deux nombres premiers. 2. Calculer n et φ. 3. Choisir e. 4. Trouver d. 5. Tester. »" },
    greffier: { npc: true, names: ["greffier", "archiviste"], label: "le Greffier des nombres premiers",
      desc: () => "Le Greffier, qui connaît chaque nombre premier par cœur et refuse d'en enregistrer un qui n'en est pas un." },
    liste: { names: ["liste", "premiers", "tableau", "nombres"], label: "la liste des premiers",
      desc: () => "Gravés au mur : 2 3 5 7 11 13 17 19 23 29 31 37 41 43 47... Un nombre premier n'a pas d'autre diviseur que 1 et lui-même. 9 = 3×3 et 15 = 3×5 n'en sont pas." },
    meule: { npc: true, names: ["meule", "grande meule"], label: "la Grande Meule",
      desc: () => "Une meule de pierre, grande comme une charrette, qui ne tourne qu'à la voix : on lui annonce un nombre, elle dit si c'est le bon." },
    machine: { names: ["machine", "banc", "appareil"], label: "la machine d'essai",
      desc: () => "Une machine de cuivre avec trois manettes : `chiffrer ‹m›` (clé publique), `dechiffrer ‹c›` (clé privée), `signer ‹m›` puis `verifier ‹s›`. Elle travaille avec TA paire de clés." },
    mallory: { npc: true, names: ["mallory"], label: "Mallory",
      desc: () => "Mallory, assise sur un tabouret, un boulier géant sur les genoux. Elle ne quitte pas ton cadenas des yeux." },
    pub: { names: ["cle publique", "cadenas", "cadenas public"], label: "ta clé publique (e, n)",
      desc: () => `Ta clé publique : **(e, n) = (${F().e}, ${F().n})**. Tu peux la distribuer à tout le monde.` },
    priv: { names: ["cle privee", "cle", "sceau"], label: "ta clé privée (d, n)",
      desc: () => `Ta clé privée : **(d, n) = (${F().d}, ${F().n})**. Elle ne quitte jamais ta poche.` },
  };

  const rooms = {
    forge: { name: "La Forge de Dame Rivest", short: "Forge", alias: ["forge"], ents: ["rivest", "etabli"], exits: { nord: "registre", est: "meule", sud: "banc", ouest: "antre" },
      desc: () => "Une forge chaude, des clés à moitié finies sur tous les murs. Au nord, le Registre des nombres premiers. À l'est, la Grande Meule. Au sud, le Banc d'essai. À l'ouest, une arrière-boutique d'où vient un bruit de boulier." },
    registre: { name: "Le Registre des nombres premiers", short: "Registre", alias: ["registre", "premiers"], ents: ["greffier", "liste"], exits: { sud: "forge" },
      desc: () => "Une salle silencieuse, des rayonnages de parchemins. Le Greffier enregistre les nombres premiers que les forgeron·ne·s choisissent pour leurs clés." },
    meule: { name: "La Grande Meule", short: "Meule", alias: ["meule"], ents: ["meule"], exits: { ouest: "forge" },
      desc: () => "Dans une cave voûtée, la Grande Meule tourne lentement. C'est ici que l'on calcule n, φ, puis que l'on choisit les exposants e et d." },
    banc: { name: "Le Banc d'essai", short: "Banc d'essai", alias: ["banc", "essai"], ents: ["machine"], exits: { nord: "forge" },
      desc: () => "Une machine de cuivre, des leviers, des cadrans. On y teste une paire de clés avant de l'utiliser pour de vrai." },
    antre: { name: "L'arrière-boutique de Mallory", short: "Arrière-boutique", alias: ["antre", "arriere", "boutique"], ents: ["mallory"], exits: { est: "forge" },
      desc: () => "Une pièce encombrée d'ardoises couvertes de divisions. Mallory a installé ici son atelier de casseuse de cadenas." },
  };

  const objective = () => {
    const x = F();
    if (!x.quest) return "quest";
    if (!x.p || !x.q) return "pq";
    if (!x.n) return "n";
    if (!x.phi) return "phi";
    if (!x.e) return "e";
    if (!x.d) return "d";
    if (!x.encDone) return "enc";
    if (!x.decDone) return "dec";
    if (!x.verifyDone) return "sign";
    if (!x.factored) return "factor";
    if (!x.sweepDone) return "sweep";
    if (!x.end) return "end";
    return "fin";
  };
  const hints = {
    quest: () => ["Dame Rivest est juste là.", "`parler rivest`"],
    pq: () => ["Il faut deux nombres premiers distincts entre 5 et 19. Le Registre est au nord de la Forge.", "`aller nord` puis `choisir p 7` et `choisir q 11` (ou d'autres premiers)."],
    n: () => ["Va à la Grande Meule (est de la Forge) et annonce-lui la valeur de n.", `\`aller est\`, puis \`calc ${F().p}*${F().q}\` et \`dire ‹résultat›\`.`],
    phi: () => ["Même chose pour φ(n), le produit de (p−1) et (q−1).", `\`calc ${F().p - 1}*${F().q - 1}\` puis \`dire ‹résultat›\`.`],
    e: () => ["Choisis l'exposant public e : plus grand que 1, plus petit que φ, sans diviseur commun avec φ.", `Par exemple \`choisir e 3\` (si 3 ne divise pas ${F().phi}), sinon essaie 5, 7, 11…`],
    d: () => ["Cherche d tel que e × d laisse un reste de 1 quand on divise par φ.", `Teste des valeurs : \`calc ${F().e}*‹d› mod ${F().phi}\` jusqu'à obtenir 1, puis \`choisir d ‹d›\`.`],
    enc: () => ["Va au Banc d'essai (sud de la Forge) et chiffre un message plus petit que n.", `\`aller sud\` puis \`chiffrer ${Math.min(F().n - 1, 5)}\`.`],
    dec: () => ["Déchiffre maintenant le résultat avec ta clé privée.", `\`dechiffrer ${F().c}\``],
    sign: () => ["Dernier test : la signature. Signe un message, puis vérifie-la.", "`signer 9` puis `verifier ‹la signature›`."],
    factor: () => ["Mallory veut casser ton cadenas. Rends-toi dans son arrière-boutique (ouest de la Forge) et aide-la à factoriser n.", `\`aller ouest\`, \`parler mallory\`, puis \`diviser 2\`, \`diviser 3\`… jusqu'à trouver un diviseur de ${F().n}.`],
    sweep: () => ["Mallory te propose un cadenas de 13 chiffres. Fais balayer son boulier assez loin.", "`balayer 1000003` (ou un nombre plus grand, jusqu'à 3000000)."],
    end: () => ["Tu as tout compris. Retourne voir Dame Rivest.", "`parler rivest`"],
    fin: () => ["Mission terminée ! Relis ton carnet.", "`carnet`"],
  };

  /* ---------- dialogues ---------- */
  function talk(id) {
    const x = F();
    switch (id) {
      case "rivest":
        if (!x.quest) {
          x.quest = true;
          say("Dame Rivest", "La Banque du Port veut changer de cadenas, et je suis clouée au lit demain. Il faut que quelqu'un sache forger une paire de clés de A à Z. Ce sera toi. On va le faire à la main, avec de petits nombres, pour voir tous les rouages.");
          say("Dame Rivest", "La recette tient en cinq étapes (regarde l'établi). Un cadenas RSA, c'est de l'arithmétique : on choisit deux nombres premiers secrets, on en tire un nombre public, et la difficulté d'inverser l'opération fait toute la sécurité.");
          out("Commence par le Registre des nombres premiers, au nord (`aller nord`).", "sys");
        } else if (x.end) say("Dame Rivest", "Tu forges mieux que moi. La banque t'attend pour la vraie paire : 2048 bits, ça fait des nombres de 617 chiffres.");
        else if (!x.d) say("Dame Rivest", "Tu en es à l'étape " + ({ pq: 1, n: 2, phi: 2, e: 3, d: 4 }[objective()] || 1) + ". Regarde l'établi (`examiner établi`).");
        else if (!x.verifyDone || !x.encDone || !x.decDone) say("Dame Rivest", "Ta paire de clés est prête. Teste-la au Banc d'essai : chiffrer, déchiffrer, puis signer et vérifier.");
        else if (!x.factored || !x.sweepDone) say("Dame Rivest", "Les clés marchent. Reste la vraie question : qu'est-ce qui empêche Mallory de les casser ? Va la voir, elle s'impatiente. Elle te dira tout.");
        else ending();
        break;
      case "greffier":
        say("Le Greffier", "Je n'enregistre que des nombres premiers entre 5 et 19 (pour que tes calculs restent faisables à la main). Choisis p puis q, distincts : `choisir p ‹nombre›` et `choisir q ‹nombre›`. Si tu en proposes un qui ne l'est pas, je te donnerai ses facteurs.");
        break;
      case "meule":
        if (!x.p || !x.q) say("Grande Meule", "Je ne tourne que pour des nombres premiers enregistrés. Passe d'abord par le Registre.");
        else if (!x.n) say("Grande Meule", "Combien vaut n, le produit de p et q ? Annonce-le : `dire ‹nombre›`. Tu peux calculer avec `calc ‹a*b›`.");
        else if (!x.phi) say("Grande Meule", "Bien. Maintenant φ(n), le produit de (p−1) et (q−1). `dire ‹nombre›`.");
        else if (!x.e) say("Grande Meule", `Choisis l'exposant public e : 1 < e < ${x.phi}, et sans diviseur commun avec ${x.phi}. \`choisir e ‹nombre›\`.`);
        else if (!x.d) say("Grande Meule", `Trouve d tel que e × d ≡ 1 (mod ${x.phi}). \`choisir d ‹nombre›\`. Aide : \`calc ${x.e}*‹d› mod ${x.phi}\` doit donner 1.`);
        else say("Grande Meule", "Ta paire est forgée. Va l'essayer au Banc d'essai.");
        break;
      case "mallory":
        if (!x.d) say("Mallory", "Tu n'as pas encore de cadenas à me montrer. Reviens quand tu en auras un.");
        else if (!x.factored) {
          say("Mallory", `Ton cadenas est public : e = ${x.e}, n = ${x.n}. Je sais que n = p × q, mais je ne connais ni p ni q. Si je les trouve, je calcule φ, puis d : ta clé privée. Alors, voyons : à toi de diviser ! \`diviser ‹nombre›\` teste si un nombre divise n.`);
        } else if (!x.sweepDone) say("Mallory", `Tu vois, ${x.n}, c'est un jouet. Mais la banque veut un vrai cadenas. Voici le sien : **n = ${BIG_N}**. À la main tu n'y arriveras pas. Mon boulier, lui, peut balayer tous les diviseurs d'un coup : \`balayer ‹max›\` (jusqu'à ${BIG_MAX}).`);
        else say("Mallory", "Maintenant tu sais ce qui me bloque : la taille des nombres. Et ça, je n'y peux rien.");
        break;
      default: out("Il ne répond pas.", "sys");
    }
  }

  /* ---------- commandes ---------- */
  function need(room, msg) { if (S.room !== room) { out(msg, "sys"); return false; } return true; }

  function pick(c) {
    const m = c.raw.match(/^\S+\s+([pqed])\b\s*(\d+)?/i);
    const x = F();
    if (!m) { out("Choisir quoi ? `choisir p ‹n›`, `q`, `e` ou `d`.", "err"); return; }
    const w = m[1].toLowerCase(), n = m[2] == null ? NaN : parseInt(m[2], 10);
    if (!(n >= 0)) { out(`Donne un nombre : \`choisir ${w} ‹nombre›\`.`, "err"); return; }
    if (w === "p" || w === "q") {
      if (!need("registre", "Les nombres premiers s'enregistrent au Registre (nord de la Forge).")) return;
      if (n < 5 || n > 19) { say("Le Greffier", "Entre 5 et 19, pour que tes calculs restent faisables à la main."); return; }
      if (!isPrime(n)) { let k = 2; while (n % k) k++; say("Le Greffier", `${n} = ${k} × ${n / k}. Ce n'est pas un nombre premier.`); return; }
      if ((w === "p" && n === x.q) || (w === "q" && n === x.p)) { say("Le Greffier", "p et q doivent être différents."); return; }
      x[w] = n; x.n = x.phi = x.e = x.d = null;
      out(`Le Greffier inscrit **${w} = ${n}**. Ce nombre reste secret.`, "ok");
      if (x.p && x.q) { note("premiers"); out("Les deux nombres sont enregistrés. Direction la Grande Meule (retour à la Forge puis `aller est`).", "sys"); }
      return;
    }
    if (!need("meule", "Les exposants se choisissent à la Grande Meule (est de la Forge).")) return;
    if (w === "e") {
      if (!x.phi) { say("Grande Meule", "Il me faut d'abord n puis φ(n)."); return; }
      if (!(n > 1 && n < x.phi)) { say("Grande Meule", `e doit être strictement entre 1 et ${x.phi}.`); return; }
      const g = gcd(n, x.phi);
      if (g !== 1) { say("Grande Meule", `${n} et ${x.phi} ont un diviseur commun (${g}) : e n'aurait pas d'inverse modulo φ, donc pas de clé privée. Essaie un autre e.`); return; }
      x.e = n; x.d = null;
      out(`e = **${n}** est accepté (premier avec ${x.phi}). Ta clé publique sera (${n}, ${x.n}).`, "ok");
      out(`Reste d : tel que e × d ≡ 1 (mod ${x.phi}). Essaie \`calc ${n}*‹d› mod ${x.phi}\`.`, "sys");
      return;
    }
    // d
    if (!x.e) { say("Grande Meule", "Choisis d'abord e."); return; }
    const r = (x.e * n) % x.phi;
    if (r !== 1) { say("Grande Meule", `${x.e} × ${n} = ${x.e * n}, et ${x.e * n} mod ${x.phi} = ${r}. Il faut 1.`); return; }
    x.d = n; give("pub"); give("priv");
    out(`${x.e} × ${n} = ${x.e * n} = ${Math.floor(x.e * n / x.phi)} × ${x.phi} + 1. La Meule s'arrête avec un déclic : **d = ${n}**.`, "ok");
    out(`Clé publique : (${x.e}, ${x.n}). Clé privée : (${n}, ${x.n}). Tu oublies p, q et φ : ils ne servent plus et ne doivent jamais fuiter.`, "ok");
    note("ed"); fig("cles");
  }

  function sayNum(txt) {
    const x = F();
    const n = parseInt(txt, 10);
    if (!/^\d+$/.test(txt)) { out(txt ? "Personne ne réagit." : "Dire quoi ?", "sys"); return; }
    if (S.room !== "meule") { out("Personne ne réagit.", "sys"); return; }
    if (!x.p || !x.q) { say("Grande Meule", "Je ne tourne pas : pas de nombres premiers enregistrés."); return; }
    if (!x.n) {
      if (n === x.p * x.q) { x.n = n; out(`La Meule tourne : **n = ${x.p} × ${x.q} = ${n}**. n sera public.`, "ok"); note("n"); out(`Maintenant φ(n) = (p−1)(q−1). \`dire ‹nombre›\`.`, "sys"); }
      else say("Grande Meule", "Non : n est le PRODUIT de p et q.");
    } else if (!x.phi) {
      const ph = (x.p - 1) * (x.q - 1);
      if (n === ph) { x.phi = ph; out(`**φ(n) = ${x.p - 1} × ${x.q - 1} = ${ph}**. Cette valeur reste secrète : sans p et q, elle est introuvable.`, "ok"); note("phi"); out("Choisis maintenant e : `choisir e ‹nombre›`.", "sys"); }
      else say("Grande Meule", "Non : φ(n) = (p−1) × (q−1).");
    } else say("Grande Meule", "Tu as déjà n et φ. Choisis e : `choisir e ‹nombre›`.");
  }

  function encrypt(c) {
    const x = F();
    if (!need("banc", "La machine d'essai est au Banc (sud de la Forge).")) return;
    if (!x.d) { out("La machine n'a pas de clés à utiliser : forge ta paire d'abord.", "err"); return; }
    const m = parseInt(c.rest.find(t => /^\d+$/.test(t)), 10);
    if (!(m >= 2 && m < x.n)) { out(`Donne un message m (un nombre) entre 2 et ${x.n - 1} : \`chiffrer 5\`.`, "err"); return; }
    x.m = m; x.c = modpow(m, x.e, x.n); x.encDone = true;
    out(`Clé publique (${x.e}, ${x.n}) : c = ${m}^${x.e} mod ${x.n} = **${x.c}**. Mallory peut voir ${x.c}, ${x.e} et ${x.n}, mais pas ${m}.`, "ok");
    note("chiffrer"); fig("chiffrement");
  }
  function decrypt(c) {
    const x = F();
    if (!need("banc", "La machine d'essai est au Banc (sud de la Forge).")) return;
    if (!x.d) { out("La machine n'a pas de clés à utiliser.", "err"); return; }
    const v = parseInt(c.rest.find(t => /^\d+$/.test(t)), 10);
    if (!(v >= 0)) { out("Donne le chiffré : `dechiffrer ‹c›`.", "err"); return; }
    if (/public/.test(c.rest.join(" "))) {
      x.wrong = true;
      out(`Avec la clé PUBLIQUE : ${v}^${x.e} mod ${x.n} = **${modpow(v, x.e, x.n)}**. Ce n'est pas ton message : la clé publique chiffre, elle ne déchiffre pas.`, "err"); return;
    }
    const m = modpow(v, x.d, x.n);
    out(`Clé privée (${x.d}, ${x.n}) : m = ${v}^${x.d} mod ${x.n} = **${m}**.`, "ok");
    if (x.c != null && v === x.c && m === x.m) { out(`C'est exactement ton message d'origine (${x.m}).`, "ok"); x.decDone = true; note("dechiffrer"); fig("chiffrement"); }
    else if (x.c != null && v !== x.c) out(`(Pour retrouver ton message, déchiffre ${x.c}, le chiffré de tout à l'heure.)`, "sys");
  }
  function sign(c) {
    const x = F();
    if (!need("banc", "La machine d'essai est au Banc (sud de la Forge).")) return;
    if (!x.d) { out("La machine n'a pas de clés à utiliser.", "err"); return; }
    const m = parseInt(c.rest.find(t => /^\d+$/.test(t)), 10);
    if (!(m >= 2 && m < x.n)) { out(`Donne un message entre 2 et ${x.n - 1} : \`signer 9\`.`, "err"); return; }
    x.sm = m; x.s = modpow(m, x.d, x.n);
    out(`Clé PRIVÉE : s = ${m}^${x.d} mod ${x.n} = **${x.s}**. La signature de ${m} est ${x.s}. Vérifie-la : \`verifier ${x.s}\`.`, "ok");
  }
  function check(c) {
    const x = F();
    if (!need("banc", "La machine d'essai est au Banc (sud de la Forge).")) return;
    if (x.s == null) { out("Signe d'abord un message : `signer ‹m›`.", "err"); return; }
    const s = parseInt(c.rest.find(t => /^\d+$/.test(t)), 10);
    if (!(s >= 0)) { out("Donne la signature : `verifier ‹s›`.", "err"); return; }
    const v = modpow(s, x.e, x.n);
    if (s === x.s && v === x.sm) {
      out(`Clé PUBLIQUE : ${s}^${x.e} mod ${x.n} = **${v}**, c'est bien ton message ${x.sm}. Signature authentique : seule la clé privée a pu la produire.`, "ok");
      x.verifyDone = true; note("signer"); fig("signature");
    } else out(`Clé publique : ${s}^${x.e} mod ${x.n} = ${v}. Ce n'est pas le message signé (${x.sm}) : signature falsifiée ou modifiée. Essaie avec la vraie signature, ${x.s}.`, "err");
  }

  function divide(c) {
    const x = F();
    if (!need("antre", "Mallory fait ses divisions dans son arrière-boutique (ouest de la Forge).")) return;
    if (!x.d) { say("Mallory", "Je n'ai aucun cadenas à casser pour l'instant."); return; }
    const k = parseInt(c.rest.find(t => /^\d+$/.test(t)), 10);
    if (!(k >= 2)) { out("Quel diviseur essayer ? `diviser 3`", "err"); return; }
    x.tries = (x.tries || 0) + 1;
    if (x.n % k !== 0 || k >= x.n) { out(`${x.n} ÷ ${k} : reste ${x.n % k}. Pas un diviseur.  (${x.tries} essai${x.tries > 1 ? "s" : ""})`, "sys"); return; }
    const p = k, q = x.n / k, ph = (p - 1) * (q - 1);
    x.factored = true;
    out(`${x.n} = **${p} × ${q}** : trouvé en ${x.tries} essai${x.tries > 1 ? "s" : ""} !`, "ok");
    say("Mallory", `Parfait : p = ${p}, q = ${q}, donc φ = ${ph}. Il me reste à trouver d tel que ${x.e} × d ≡ 1 mod ${ph}… ${x.d} ! C'est ta clé privée.`);
    if (x.c != null) say("Mallory", `Et ton chiffré ${x.c} ? ${x.c}^${x.d} mod ${x.n} = ${modpow(x.c, x.d, x.n)}. Merci pour ton message !`);
    out("Mallory a cassé ton cadenas, parce que n est minuscule. Voyons ce qui se passe avec de vrais nombres.", "err");
    note("securite");
    say("Mallory", `Mais la banque ne se contentera pas de ${x.n}. Son cadenas : **n = ${BIG_N}**. \`balayer ‹max›\` fait tester à mon boulier tous les diviseurs de 2 à max (jusqu'à ${BIG_MAX}).`);
  }
  function sweep(c) {
    const x = F();
    if (!need("antre", "Le boulier de Mallory est dans son arrière-boutique (ouest de la Forge).")) return;
    if (!x.factored) { say("Mallory", "Factorise d'abord ton propre cadenas à la main (`diviser ‹nombre›`)."); return; }
    const max = parseInt(c.rest.find(t => /^\d+$/.test(t)), 10);
    if (!(max >= 2)) { out("Jusqu'où balayer ? `balayer 1000003`", "err"); return; }
    if (max > BIG_MAX) { say("Mallory", `Mon boulier s'arrête à ${BIG_MAX} dans cette démo.`); return; }
    const t0 = performance.now(); let found = 0;
    for (let k = 2; k <= max; k++) if (BIG_N % k === 0) { found = k; break; }
    const ms = Math.max(1, Math.round(performance.now() - t0));
    if (!found) { out(`Aucun diviseur de ${BIG_N} jusqu'à ${max} (${ms} ms). Va plus loin !`, "sys"); return; }
    x.sweepDone = true;
    out(`Trouvé après ${found - 1} essais, en ${ms} ms : **${BIG_N} = ${found} × ${BIG_N / found}**.`, "ok");
    say("Mallory", "Treize chiffres : une seconde. Mais regarde l'échelle : chaque chiffre de plus multiplie l'effort. Les vrais cadenas RSA-2048 font 617 chiffres. Là, mon boulier devrait tester environ 10^308 diviseurs. Même avec mille milliards d'essais par seconde, il faudrait bien plus que l'âge de l'univers. C'est la seule chose qui me retient.");
    fig("echelle");
    out("Retourne voir Dame Rivest (`aller est`, puis `parler rivest`).", "sys");
  }

  function ending() {
    const x = F(); x.end = true;
    out("Épilogue", "title");
    say("Dame Rivest", "Tu as forgé une paire de clés, chiffré, signé, et vu pourquoi la taille des nombres est tout. La banque a de quoi dormir tranquille : sa vraie paire sera forgée avec des premiers de plus de 300 chiffres chacun. Bravo.");
    debrief();
    out("FIN. `carnet` pour relire tes notes, `analogies` pour revoir ce bilan, `recommencer` pour rejouer.", "title");
  }
  function debrief() {
    out("Comment ça marche vraiment : les analogies décodées", "title");
    out("**La forge et la recette en cinq étapes = génération d'une paire de clés RSA.** Deux nombres premiers p et q, le module n = p × q, φ(n) = (p−1)(q−1), un exposant public e premier avec φ, et d inverse de e modulo φ.");
    out("**La clé publique (e, n) et la clé privée (d, n).** Chiffrer, c'est m^e mod n ; déchiffrer, c'est c^d mod n. Cela fonctionne parce que e × d ≡ 1 (mod φ(n)) (théorème d'Euler). Signer, c'est la même opération en sens inverse : s = m^d mod n, vérifiée avec la clé publique.");
    out("**La Grande Meule.** Elle représente le calcul modulaire : on ne garde que les restes. C'est facile dans un sens (puissance modulaire rapide) et infaisable dans l'autre sans la clé.");
    out("**Mallory et son boulier = la factorisation.** Casser RSA, c'est retrouver p et q à partir de n. Avec n = 77, c'est immédiat ; avec 13 chiffres, une seconde ; avec 617 chiffres, aucune méthode connue n'y arrive (en pratique). On parle de clés de 2048 ou 3072 bits.");
    out("**Les simplifications du jeu.** (1) Des nombres de 1 à 3 chiffres, avec des « messages » qui sont des nombres. (2) Le RSA « brut » est dangereux : on ajoute toujours un bourrage aléatoire (OAEP pour chiffrer, PSS pour signer), sinon le même message donne toujours le même chiffré. (3) En vrai, e vaut presque toujours 65537, et d se calcule avec l'algorithme d'Euclide étendu, pas en essayant des valeurs. (4) RSA ne chiffre que de petits messages : on s'en sert pour chiffrer une clé symétrique (voir le jeu TLS). (5) Un ordinateur quantique assez grand casserait RSA (algorithme de Shor) : d'où la cryptographie post-quantique.");
    out("Les noms sont des clins d'œil : Rivest, Shamir et Adleman ont inventé RSA (1977).", "sys");
    out("Rappel utile : **la sécurité de RSA repose sur un problème difficile (factoriser), pas sur le secret de l'algorithme.**", "ok");
  }

  /* ---------- schémas ---------- */
  const figs = {
    cles: () => {
      const x = F();
      return {
        cap: "Fabrication d'une paire RSA : p et q restent secrets, n est public, φ sert seulement à trouver d.",
        svg: SVG(260, "Génération d'une paire de clés RSA",
          R(8, 8, 230, 34, "f-priv") + T(123, 30, `p = ${x.p}  q = ${x.q}  (secrets)`, "ft-priv") +
          AR(123, 42, 123, 58) + R(8, 58, 230, 34) + T(123, 80, `n = p × q = ${x.n}`, "") +
          AR(123, 92, 123, 108) + R(8, 108, 230, 34) + T(123, 130, `φ = (p−1)(q−1) = ${x.phi}`, "") +
          AR(123, 142, 123, 158) + R(8, 158, 230, 34) + T(123, 180, `e = ${x.e}  (premier avec φ)`, "") +
          AR(123, 192, 123, 208) + R(8, 208, 230, 44) + T(123, 226, `e × d ≡ 1 (mod ${x.phi})`, "") + T(123, 243, `d = ${x.d}`, "f-b") +
          R(262, 40, 150, 56, "f-pub") + T(337, 62, "clé publique", "ft-pub f-b") + T(337, 82, `(${x.e}, ${x.n})`, "ft-pub") +
          R(262, 150, 150, 56, "f-priv") + T(337, 172, "clé privée", "ft-priv f-b") + T(337, 192, `(${x.d}, ${x.n})`, "ft-priv") +
          AR(238, 76, 262, 68, "f-pub") + AR(238, 226, 262, 190, "f-priv"))
      };
    },
    chiffrement: () => {
      const x = F();
      return {
        cap: "Chiffrer avec la clé publique (e, n), déchiffrer avec la clé privée (d, n). Mallory voit le chiffré et la clé publique, jamais le message.",
        svg: SVG(200, "Chiffrement et déchiffrement RSA",
          R(8, 40, 100, 60) + T(58, 64, "Alice", "f-b") + T(58, 84, `m = ${x.m}`, "") +
          R(160, 40, 100, 60) + T(210, 64, "chiffré", "f-b") + T(210, 84, `c = ${x.c}`, "ft-pub") +
          R(312, 40, 100, 60) + T(362, 64, "Bob", "f-b") + T(362, 84, `m = ${x.decDone ? x.m : "?"}`, x.decDone ? "ft-ok" : "") +
          AR(108, 70, 160, 70, "f-pub") + T(134, 32, `^${x.e} mod ${x.n}`, "ft-pub f-s") + T(134, 118, "clé publique", "f-s") +
          AR(260, 70, 312, 70, "f-priv") + T(286, 32, `^${x.d} mod ${x.n}`, "ft-priv f-s") + T(286, 118, "clé privée", "f-s") +
          R(120, 140, 180, 44, "f-bad") + T(210, 158, "Mallory voit seulement", "ft-bad") + T(210, 175, `c = ${x.c}, e = ${x.e}, n = ${x.n}`, "ft-bad"))
      };
    },
    signature: () => {
      const x = F();
      return {
        cap: "Signer, c'est le chemin inverse : la clé privée produit s, la clé publique redonne le message pour vérifier.",
        svg: SVG(150, "Signature RSA",
          R(8, 30, 100, 60) + T(58, 54, "message", "f-b") + T(58, 74, `m = ${x.sm}`, "") +
          R(160, 30, 100, 60) + T(210, 54, "signature", "f-b") + T(210, 74, `s = ${x.s}`, "ft-priv") +
          R(312, 30, 100, 60) + T(362, 54, "vérifié", "f-b") + T(362, 74, `${x.sm} ✔`, "ft-ok") +
          AR(108, 60, 160, 60, "f-priv") + T(134, 24, `^${x.d} mod ${x.n}`, "ft-priv f-s") + T(134, 108, "clé privée", "f-s") +
          AR(260, 60, 312, 60, "f-pub") + T(286, 24, `^${x.e} mod ${x.n}`, "ft-pub f-s") + T(286, 108, "clé publique", "f-s"))
      };
    },
    echelle: () => ({
      cap: "Chaque chiffre de plus multiplie l'effort de factorisation par dix. À 617 chiffres, c'est hors de portée (l'échelle est logarithmique).",
      svg: SVG(210, "Effort de factorisation selon la taille de n",
        T(8, 20, "n à 3 chiffres (77)", "f-s", "start") + R(8, 28, 400, 14) + `<rect x="8" y="28" width="6" height="14" rx="3" fill="var(--ok)"/>` + T(20, 40, "≈ 3 essais", "ft-ok f-s", "start") +
        T(8, 74, "n à 13 chiffres", "f-s", "start") + R(8, 82, 400, 14) + `<rect x="8" y="82" width="110" height="14" rx="3" fill="var(--you)"/>` + T(126, 94, "≈ 10^6 essais : 1 seconde", "ft-priv f-s", "start") +
        T(8, 128, "n à 617 chiffres (RSA-2048)", "f-s", "start") + R(8, 136, 400, 14) + `<rect x="8" y="136" width="400" height="14" rx="3" fill="var(--bad)"/>` + T(400, 148, "≈ 10^308 essais ▶▶", "f-b", "end") +
        T(8, 180, "À 10^12 essais/s, il faudrait ≈ 10^296 secondes.", "f-s", "start") + T(8, 196, "L'univers a environ 4×10^17 secondes.", "f-s", "start"))
    }),
  };

  GAMES.rsa = {
    id: "rsa", order: 2, title: "La Forge de Rivest", pageTitle: "RSA Quest", subtitle: "aventure textuelle · RSA",
    blurb: "Forge une paire de clés RSA à la main, puis regarde Mallory essayer de la casser.",
    concept: "RSA, factorisation, signature",
    start: "forge", firstCommand: "parler rivest",
    ents, rooms, notes, hints, figs, objective, talk, say: sayNum, debrief, isEnd: () => !!F().end,
    refig(name) { fig(name); },
    figAlias: { cles: ["cle", "forge"], chiffrement: ["chiffrer", "dechiffrer", "rsa"], signature: ["signer"], echelle: ["factorisation", "taille"] },
    help: "Spécifiques : `choisir p|q|e|d ‹nombre›` · `chiffrer ‹m›` · `dechiffrer ‹c›` · `signer ‹m›` · `verifier ‹s›` · `diviser ‹k›` · `balayer ‹max›`",
    verbs: {
      pick: { words: ["choisir", "fixer", "inscrire"], run: pick },
      encrypt: { words: ["chiffrer", "chiffre"], run: encrypt },
      decrypt: { words: ["dechiffrer", "dechiffre"], run: decrypt },
      sign: { words: ["signer"], run: sign },
      check: { words: ["verifier", "controler"], run: check },
      divide: { words: ["diviser", "essayer", "tester"], run: divide },
      sweep: { words: ["balayer", "scanner"], run: sweep },
    },
    intro() {
      out("La Forge de Rivest", "title");
      out("Port-443 : la Banque du Port veut un nouveau cadenas, un vrai, de ceux dont seule la banque détient la clé. Dame Rivest, qui forge toutes les paires de clés de la ville, te prend comme apprenti·e. Mais avant de manipuler des nombres de 600 chiffres, on apprend les rouages avec de petits nombres, à la main.\nIl y a aussi Mallory, qui rôde, et qui voudrait bien se fabriquer la clé de quelqu'un d'autre.", "");
      out("Tu disposes d'une calculatrice de poche : `calc 7*11`, `calc 5^3 mod 77`.", "sys");
    },
  };
})();
