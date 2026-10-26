// Optional real-browser offline check. Run with bundled Node/Playwright on Windows.
const path = require('path');
const { pathToFileURL } = require('url');
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({channel:'msedge',headless:true});
  const page = await browser.newPage();
  await page.goto(pathToFileURL(path.resolve(__dirname,'..','index.html')).href);
  const all = await page.locator('#cards .card:visible').count();
  await page.locator('#search').fill('Paillier');
  const filtered = await page.locator('#cards .card:visible').count();
  if (!(all>filtered && filtered>0)) throw Error(`Search filter failed: all=${all}, filtered=${filtered}`);
  const links = await page.locator('a[href]').count();
  console.log(`OFFLINE INDEX OK: ${all} cards; ${filtered} Paillier matches; ${links} local links`);
  await browser.close();
})().catch(e => {console.error(e);process.exit(1)});
