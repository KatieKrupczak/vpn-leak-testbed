const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  const stunUrl = process.argv[2];
  const outputJson = process.argv[3]; // JSON file to append candidates to
  if (!stunUrl || !outputJson) {
    console.error('Usage: node webrtc_check.js <STUN_URL> <OUTPUT_JSON>');
    process.exit(1);
  }

  console.log(`Testing WebRTC with STUN server: ${stunUrl}`);

  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.goto('about:blank');

  const candidates = await page.evaluate(async (url) => {
    return new Promise((resolve) => {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: url }] });
      const collected = [];

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          collected.push(event.candidate.candidate);
          console.log('ICE candidate:', event.candidate.candidate);
        }
      };

      const dc = pc.createDataChannel('probe');
      dc.onopen = () => dc.send('probe');

      pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .catch(console.error);

      setTimeout(() => {
        pc.close();
        resolve(collected);
      }, 8000); // wait 8s for ICE candidates
    });
  }, stunUrl);

  // Append to JSON file
  let existing = [];
  if (fs.existsSync(outputJson)) {
    existing = JSON.parse(fs.readFileSync(outputJson, 'utf8'));
  }
  existing.push({ url: stunUrl, candidates });
  fs.writeFileSync(outputJson, JSON.stringify(existing, null, 2));

  await browser.close();
})();
