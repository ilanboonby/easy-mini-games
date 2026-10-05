// Rejoue une liste de commandes dans un jeu et affiche l'état final.
// Usage : node tests/play.js <id du jeu> <fichier.json> [sortie_sans_extension]
// Écrit <sortie>.txt (journal complet) et <sortie>.png (capture mobile). Variables : CHROMIUM (chemin), NODE_PATH.
const { chromium } = require("playwright");
const fs = require("fs"), path = require("path");
(async () => {
  const [id, file, out] = process.argv.slice(2);
  const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  const page = await browser.newPage({ viewport: { width: 400, height: 800 } });
  const errs = []; page.on("pageerror", e => errs.push(e.stack.split("\n").slice(0, 3).join(" | ")));
  await page.goto("file://" + path.resolve(__dirname, "../index.html"));
  await page.click(`.gcard[data-id="${id}"]`);
  for (const c of JSON.parse(fs.readFileSync(file, "utf8"))) { await page.fill("#cmd", c); await page.press("#cmd", "Enter"); }
  const st = await page.evaluate(() => { const f = { ...S.f }; for (const k in f) if (typeof f[k] === "string" && f[k].length > 60) f[k] = f[k].slice(0, 60) + "…"; return { room: S.room, flags: f, notes: S.notes.length + "/" + Object.keys(G.notes).length, figs: S.figs, end: !!S.f.end }; });
  console.log(JSON.stringify(st)); console.log("Erreurs JS :", errs);
  if (out) { fs.writeFileSync(out + ".txt", await page.locator("#log").innerText()); await page.screenshot({ path: out + ".png" }); }
  await browser.close();
})();
