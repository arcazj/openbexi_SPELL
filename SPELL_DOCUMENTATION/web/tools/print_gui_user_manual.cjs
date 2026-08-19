"use strict";

const path = require("path");
const { pathToFileURL } = require("url");

const projectRoot = path.resolve(__dirname, "..", "..", "..");
const playwrightModule = process.env.SPELL_PLAYWRIGHT_MODULE ||
  path.join(projectRoot, "frontend", "node_modules", "playwright");
const { chromium } = require(playwrightModule);

async function main() {
  const [htmlPath, outputPath] = process.argv.slice(2);
  if (!htmlPath || !outputPath) {
    throw new Error("usage: node print_gui_user_manual.cjs INPUT.html OUTPUT.pdf");
  }

  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(pathToFileURL(path.resolve(htmlPath)).href, { waitUntil: "load" });
    await page.evaluate(async () => {
      await document.fonts.ready;
      await Promise.all(Array.from(document.images).map((image) => image.decode()));
      for (const anchor of document.querySelectorAll("a[href]")) {
        const href = anchor.getAttribute("href");
        if (!href.startsWith("#") && anchor.href.startsWith("file:")) {
          anchor.removeAttribute("href");
          anchor.classList.add("local-reference");
        }
      }
    });
    await page.emulateMedia({ media: "print" });

    const footer = [
      '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:8px;',
      'color:#5b6772;width:100%;padding:0 0.66in;display:flex;',
      'justify-content:space-between;">',
      '<span>Next-Generation SPELL Web GUI User Manual | 0.1.0-draft.1</span>',
      '<span>Page <span class="pageNumber"></span> of ',
      '<span class="totalPages"></span></span></div>',
    ].join("");

    await page.pdf({
      path: path.resolve(outputPath),
      format: "Letter",
      preferCSSPageSize: true,
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: "<div></div>",
      footerTemplate: footer,
      tagged: true,
      outline: true,
    });
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exit(1);
});
