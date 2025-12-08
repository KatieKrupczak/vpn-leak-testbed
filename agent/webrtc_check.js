const puppeteer = require('puppeteer-core');

(async () => {
  // Get the STUN/TURN URL from command line argument
  const stunUrl = process.argv[2];
  
  if (!stunUrl) {
    console.error('Error: No STUN/TURN URL provided');
    process.exit(1);
  }

  console.log(`Testing WebRTC with: ${stunUrl}`);

  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    //args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-ipv6']
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.goto('about:blank');
  
  // Pass the URL into the page context
  await page.evaluate(async (url) => {
    const pc = new RTCPeerConnection({ 
      iceServers: [{ urls: url }] 
    });
    const dc = pc.createDataChannel('probe');
    dc.onopen = () => dc.send('probe');
    await pc.setLocalDescription(await pc.createOffer());
    
    // Wait for ICE gathering
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    pc.close();
  }, stunUrl);

  await browser.close();
})();