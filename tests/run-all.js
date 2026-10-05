// Rejoue un parcours complet de chaque jeu dans un navigateur et vérifie que la fin est atteinte.
// Usage : npm i playwright (ou utiliser un Playwright déjà installé), puis `node tests/run-all.js`
const { chromium } = require("playwright");
const fs = require("fs"), path = require("path");
// Un parcours par fichier tests/<id>.json (un tableau vide est ignoré)
const GAMES = fs.readdirSync(__dirname).filter(f => f.endsWith(".json")).map(f => f.slice(0, -5)).filter(g => JSON.parse(fs.readFileSync(path.join(__dirname, g + ".json"), "utf8")).length).sort();
(async () => {
  const opts = process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {};
  const browser = await chromium.launch(opts);
  let failed = 0;
  for (const g of GAMES) {
    const page = await browser.newPage({ viewport: { width: 400, height: 800 } });
    const errs = []; page.on("pageerror", e => errs.push(e.message));
    await page.goto("file://" + path.resolve(__dirname, "../index.html"));
    await page.click(`.gcard[data-id="${g}"]`);
    for (const c of JSON.parse(fs.readFileSync(path.join(__dirname, g + ".json"), "utf8"))) { await page.fill("#cmd", c); await page.press("#cmd", "Enter"); }
    const st = await page.evaluate(() => ({ end: !!S.f.end, notes: S.notes.length, total: Object.keys(G.notes).length }));
    const ok = st.end && st.notes === st.total && !errs.length;
    if (!ok) failed++;
    console.log(`${ok ? "OK  " : "FAIL"} ${g}  (carnet ${st.notes}/${st.total}, erreurs JS : ${errs.length})`);
    await page.close();
  }
  await browser.close();
  process.exit(failed ? 1 : 0);
})();
