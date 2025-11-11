const puppeteer = require('puppeteer-core');

(async () => {
  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.goto('about:blank'); // or any page
  // create WebRTC peer connection in the page
  await page.evaluate(async () => {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
    const dc = pc.createDataChannel('probe');
    dc.onopen = () => dc.send('probe');
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise(resolve => setTimeout(resolve, 5000));
    pc.close();
  });

  await browser.close();
})();
