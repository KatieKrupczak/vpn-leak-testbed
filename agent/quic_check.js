const puppeteer = require('puppeteer');

(async () => {
  const url = process.argv[2];
  
  if (!url) {
    console.error('Error: No URL provided');
    process.exit(1);
  }

  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      //'--disable-ipv6',
      '--disable-dev-shm-usage',
      '--enable-quic',
      '--origin-to-force-quic-on=*:443'
    ]
  });

  const page = await browser.newPage();
  
  try {
    await page.goto(url, { 
      waitUntil: 'load',
      timeout: 30000 
    });
  } catch (error) {
    console.error(`Failed to load ${url}:`, error.message);
  }
  
  await browser.close();
})();