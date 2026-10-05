// Planche de contact des schémas débloqués après un parcours. Usage : node tests/figs.js <id> <fichier.json> <sortie.png>
const { chromium } = require("playwright");
const fs = require("fs"), path = require("path");
(async () => {
  const [id, file, out] = process.argv.slice(2);
  const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  const page = await browser.newPage({ viewport: { width: 860, height: 800 } });
  const errs = []; page.on("pageerror", e => errs.push(e.message));
  await page.goto("file://" + path.resolve(__dirname, "../index.html"));
  await page.click(`.gcard[data-id="${id}"]`);
  for (const c of JSON.parse(fs.readFileSync(file, "utf8"))) { await page.fill("#cmd", c); await page.press("#cmd", "Enter"); }
  await page.evaluate(() => { const l = document.getElementById("log"); [...l.children].forEach(c => { if (!c.classList.contains("fig")) c.remove(); }); l.style.cssText = "display:grid;grid-template-columns:repeat(2,1fr);gap:8px;overflow:visible;flex:none"; for (const e of [document.querySelector(".app"), document.documentElement, document.body]) e.style.height = "auto"; document.getElementById("bar").remove(); document.getElementById("form").remove(); });
  await page.screenshot({ path: out, fullPage: true });
  console.log("schémas :", await page.locator("figure.fig").count(), "erreurs :", errs);
  await browser.close();
})();
