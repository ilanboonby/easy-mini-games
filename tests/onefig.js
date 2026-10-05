// Un PNG par schéma distinct après un parcours. Usage : node tests/onefig.js <id> <fichier.json> <préfixe>  (écrit <préfixe>0.png, <préfixe>1.png…)
const { chromium } = require("playwright");
const fs = require("fs"), path = require("path");
(async () => {
  const [id, file, prefix] = process.argv.slice(2);
  const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  const page = await browser.newPage({ viewport: { width: 460, height: 800 } });
  await page.goto("file://" + path.resolve(__dirname, "../index.html"));
  await page.click(`.gcard[data-id="${id}"]`);
  for (const c of JSON.parse(fs.readFileSync(file, "utf8"))) { await page.fill("#cmd", c); await page.press("#cmd", "Enter"); }
  await page.locator("#log").evaluate(e => { e.style.overflow = "visible"; e.style.flex = "none"; });
  const labels = await page.$$eval("figure.fig svg", s => s.map(x => x.getAttribute("aria-label")));
  const figs = await page.locator("figure.fig").all();
  const seen = new Set(); let n = 0;
  for (let i = figs.length - 1; i >= 0; i--) { if (seen.has(labels[i])) continue; seen.add(labels[i]); await figs[i].screenshot({ path: `${prefix}${n++}.png` }); }
  console.log(n, "schémas distincts :", [...seen]);
  await browser.close();
})();
