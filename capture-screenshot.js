const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1280, height: 800 });
  const filePath = 'file://' + path.resolve('index.html');
  await page.goto(filePath);
  // Wait for entrance animations
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'preview.png' });
  await browser.close();
  console.log('Screenshot saved as preview.png');
})();