#!/usr/bin/env node
'use strict';

/**
 * External / no-Dragonite-obfuscator release path:
 * 1) Embed release IKM + KAT + TLS SPKI into BuildFingerprint.class inside a JAR
 * 2) Register buildId + keyHalfB + jarSha256 with the auth server (RELEASE_REGISTRATION_TOKEN)
 *
 * Does not run Dragonite ASM obfuscation. Safe to use after a third-party obfuscator
 * as long as me/shedaniel/clothconfig2/internal/BuildFingerprint is still present.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const tls = require('tls');
const { hkdfSha256, mixIkmBytes } = require('../auth-proof-hmac');

const FINGERPRINT_ENTRY = 'me/shedaniel/clothconfig2/internal/BuildFingerprint.class';
const STRING_KEY_INFO = Buffer.from('cloth-string-key', 'utf8');

function die(msg) {
  console.error(msg);
  process.exit(1);
}

function xorEncryptToHex(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  for (let i = 0; i < bytes.length; i++) bytes[i] ^= 0x5f;
  return bytes.toString('hex');
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function resolveJavaBin() {
  const fromPath = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['java'], { encoding: 'utf8' });
  if (fromPath.status === 0 && fromPath.stdout.trim()) {
    return 'java';
  }
  if (process.env.JAVA_HOME) {
    const candidate = path.join(process.env.JAVA_HOME, 'bin', process.platform === 'win32' ? 'java.exe' : 'java');
    if (fs.existsSync(candidate)) return candidate;
  }
  die('Java is required (java/javac on PATH or JAVA_HOME).');
}

function resolveJavac(javaBin) {
  if (javaBin !== 'java') {
    const sibling = path.join(path.dirname(javaBin), process.platform === 'win32' ? 'javac.exe' : 'javac');
    if (fs.existsSync(sibling)) return sibling;
  }
  const fromPath = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['javac'], { encoding: 'utf8' });
  if (fromPath.status === 0 && fromPath.stdout.trim()) return 'javac';
  die('javac is required to embed BuildFingerprint into the JAR.');
}

function resolveJarTool(javaBin) {
  if (javaBin !== 'java') {
    const sibling = path.join(path.dirname(javaBin), process.platform === 'win32' ? 'jar.exe' : 'jar');
    if (fs.existsSync(sibling)) return sibling;
  }
  const fromPath = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['jar'], { encoding: 'utf8' });
  if (fromPath.status === 0 && fromPath.stdout.trim()) return 'jar';
  die('JDK jar tool is required to update the release JAR.');
}

function fetchSpkiSha256Hex(host, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: true }, () => {
      try {
        const peer = socket.getPeerCertificate(true);
        if (!peer || !peer.raw) {
          reject(new Error('No peer certificate'));
          socket.end();
          return;
        }
        const cert = new crypto.X509Certificate(peer.raw);
        const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
        const hex = crypto.createHash('sha256').update(spki).digest('hex');
        socket.end();
        resolve(hex);
      } catch (err) {
        socket.destroy();
        reject(err);
      }
    });
    socket.setTimeout(20000, () => {
      socket.destroy();
      reject(new Error(`TLS timeout for ${host}:${port}`));
    });
    socket.on('error', reject);
  });
}

function deriveKatExpectedHex(mixedIkm, saltInput) {
  const out = hkdfSha256(mixedIkm, Buffer.from(saltInput, 'utf8'), STRING_KEY_INFO, 32);
  return out.toString('hex');
}

function buildFingerprintSource(fields) {
  const q = (v) => JSON.stringify(String(v));
  return `package me.shedaniel.clothconfig2.internal;

public final class BuildFingerprint {
  public static String BUILD_DIGEST = ${q(fields.BUILD_DIGEST)};
  public static String BUILD_SALT_A = ${q(fields.BUILD_SALT_A)};
  public static String BUILD_SALT_B = ${q(fields.BUILD_SALT_B)};
  public static String AUTH_HOST = ${q(fields.AUTH_HOST)};
  public static String AUTH_SPKI_SHA256 = ${q(fields.AUTH_SPKI_SHA256)};
  public static String NATIVE_IKM_HEX = ${q(fields.NATIVE_IKM_HEX)};
  public static String ECDSA_SIGNING_RAW_HEX = ${q(fields.ECDSA_SIGNING_RAW_HEX)};
  public static String ECDSA_JVM_RAW_HEX = ${q(fields.ECDSA_JVM_RAW_HEX)};
  public static String ECDSA_PUBLIC_SPKI_B64 = ${q(fields.ECDSA_PUBLIC_SPKI_B64)};
  public static final String AUTH_RESPONSE_ED25519_PUBLIC_SPKI_B64 = ${q(fields.AUTH_RESPONSE_ED25519_PUBLIC_SPKI_B64)};
  public static String NATIVE_KAT_INPUT_A = ${q(fields.NATIVE_KAT_INPUT_A)};
  public static String NATIVE_KAT_INPUT_B = ${q(fields.NATIVE_KAT_INPUT_B)};
  public static String NATIVE_KAT_INPUT_C = ${q(fields.NATIVE_KAT_INPUT_C)};
  public static String NATIVE_KAT_EXPECTED_A = ${q(fields.NATIVE_KAT_EXPECTED_A)};
  public static String NATIVE_KAT_EXPECTED_B = ${q(fields.NATIVE_KAT_EXPECTED_B)};
  public static String NATIVE_KAT_EXPECTED_C = ${q(fields.NATIVE_KAT_EXPECTED_C)};

  private BuildFingerprint() {}

  public static String decrypt(String hex) {
      if (hex == null || hex.startsWith("__OBF_") || hex.length() % 2 != 0) {
          return hex;
      }
      try {
          int len = hex.length();
          byte[] data = new byte[len / 2];
          for (int i = 0; i < len; i += 2) {
              data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                   + Character.digit(hex.charAt(i+1), 16));
          }
          for (int i = 0; i < data.length; i++) {
              data[i] ^= 0x5F;
          }
          return new String(data, java.nio.charset.StandardCharsets.UTF_8);
      } catch (Exception e) {
          return hex;
      }
  }

  public static byte[] decryptToBytes(String hex) {
      if (hex == null || hex.startsWith("__OBF_") || hex.length() % 2 != 0) {
          return new byte[0];
      }
      try {
          int len = hex.length();
          byte[] data = new byte[len / 2];
          for (int i = 0; i < len; i += 2) {
              data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                   + Character.digit(hex.charAt(i+1), 16));
          }
          for (int i = 0; i < data.length; i++) {
              data[i] ^= 0x5F;
          }
          return data;
      } catch (Exception e) {
          return new byte[0];
      }
  }

  public static String getBuildTag() {
    return decrypt(BUILD_DIGEST);
  }

  public static String authHost() {
    return decrypt(AUTH_HOST);
  }

  public static byte[] authHostBytes() {
    return decryptToBytes(AUTH_HOST);
  }

  public static String authBaseHttps() {
    byte[] scheme = decryptToBytes("372b2b2f2c657070");
    byte[] host = decryptToBytes(AUTH_HOST);
    try {
      if (scheme == null || host == null || host.length == 0) {
        return decrypt("372b2b2f2c657070") + decrypt(AUTH_HOST);
      }
      byte[] out = new byte[scheme.length + host.length];
      System.arraycopy(scheme, 0, out, 0, scheme.length);
      System.arraycopy(host, 0, out, scheme.length, host.length);
      return new String(out, java.nio.charset.StandardCharsets.UTF_8);
    } finally {
      wipeBytes(scheme);
      wipeBytes(host);
    }
  }

  public static boolean hostEqualsIgnoreCase(byte[] expectedHost, String hostname) {
    if (expectedHost == null || hostname == null || expectedHost.length != hostname.length()) {
      return false;
    }
    for (int i = 0; i < expectedHost.length; i++) {
      int a = expectedHost[i] & 0xFF;
      int b = hostname.charAt(i) & 0xFF;
      if (a >= 'A' && a <= 'Z') {
        a += 32;
      }
      if (b >= 'A' && b <= 'Z') {
        a += 32;
      }
      if (a != b) {
        return false;
      }
    }
    return true;
  }

  public static void wipeBytes(byte[] data) {
    if (data != null) {
      java.util.Arrays.fill(data, (byte) 0);
    }
  }

  public static String authSpkiSha256Hex() {
    return decrypt(AUTH_SPKI_SHA256);
  }

  public static String ecdsaJvmRawHex() {
    return decrypt(ECDSA_JVM_RAW_HEX);
  }

  public static String ecdsaPublicSpkiB64() {
    return decrypt(ECDSA_PUBLIC_SPKI_B64);
  }

  public static String ecdsaSigningRawHex() {
    return decrypt(ECDSA_SIGNING_RAW_HEX);
  }

  public static String authResponseEd25519PublicSpkiB64() {
    return AUTH_RESPONSE_ED25519_PUBLIC_SPKI_B64;
  }

  public static boolean isReleaseBuild() {
    String host = authHost();
    String spki = authSpkiSha256Hex();
    return host != null
            && !host.startsWith("__OBF_")
            && spki != null
            && !spki.startsWith("__OBF_");
  }

  public static byte[] nativeIkmOrNull() {
    String ikmDec = decrypt(NATIVE_IKM_HEX);
    if (ikmDec == null || ikmDec.startsWith("__OBF_")
            || ikmDec.startsWith("__NATIVE") || ikmDec.length() < 32) {
      return null;
    }
    int len = ikmDec.length();
    if ((len & 1) != 0) {
      return null;
    }
    byte[] out = new byte[len / 2];
    for (int i = 0; i < out.length; i++) {
      int hi = Character.digit(ikmDec.charAt(i * 2), 16);
      int lo = Character.digit(ikmDec.charAt(i * 2 + 1), 16);
      if (hi < 0 || lo < 0) {
        return null;
      }
      out[i] = (byte) ((hi << 4) | lo);
    }
    return out;
  }

  public static int mixSeed(int slot) {
    String digest = decrypt(BUILD_DIGEST);
    String saltA = decrypt(BUILD_SALT_A);
    String saltB = decrypt(BUILD_SALT_B);
    int h = (digest != null ? digest.hashCode() : 0) ^ (saltA != null ? saltA.hashCode() : 0) ^ (saltB != null ? saltB.hashCode() : 0);
    return h ^ (slot * 0x9E3779B9);
  }

  public static String katInput(int vector) {
    return switch (Math.floorMod(vector, 3)) {
      case 1 -> decrypt(NATIVE_KAT_INPUT_B);
      case 2 -> decrypt(NATIVE_KAT_INPUT_C);
      default -> decrypt(NATIVE_KAT_INPUT_A);
    };
  }

  public static String katExpectedHex(int vector) {
    return switch (Math.floorMod(vector, 3)) {
      case 1 -> decrypt(NATIVE_KAT_EXPECTED_B);
      case 2 -> decrypt(NATIVE_KAT_EXPECTED_C);
      default -> decrypt(NATIVE_KAT_EXPECTED_A);
    };
  }
}
`;
}

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (result.status !== 0) {
    die(`${cmd} failed:\n${result.stdout || ''}\n${result.stderr || ''}`);
  }
  return result;
}

function jarHasFingerprint(jarPath, jarTool) {
  const listed = spawnSync(jarTool, ['tf', jarPath], { encoding: 'utf8' });
  if (listed.status !== 0) {
    die(`Could not list JAR entries: ${jarPath}`);
  }
  return listed.stdout.split(/\r?\n/).includes(FINGERPRINT_ENTRY);
}

function embedFingerprint(jarPath, fields, workDir, javaBin) {
  const javac = resolveJavac(javaBin);
  const jarTool = resolveJarTool(javaBin);
  if (!jarHasFingerprint(jarPath, jarTool)) {
    die(`JAR is missing ${FINGERPRINT_ENTRY}. External obfuscator must keep this class name.`);
  }

  const srcRoot = path.join(workDir, 'src');
  const classesRoot = path.join(workDir, 'classes');
  const pkgDir = path.join(srcRoot, 'me', 'shedaniel', 'clothconfig2', 'internal');
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.mkdirSync(classesRoot, { recursive: true });
  const javaFile = path.join(pkgDir, 'BuildFingerprint.java');
  fs.writeFileSync(javaFile, buildFingerprintSource(fields), 'utf8');

  run(javac, ['--release', '21', '-d', classesRoot, javaFile]);
  run(jarTool, ['uf', jarPath, '-C', classesRoot, FINGERPRINT_ENTRY]);
}

function postJson(url, token, body) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const parsed = new URL(url);
    const lib = parsed.protocol === 'http:' ? http : https;
    const req = lib.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': payload.length
      },
      timeout: 60000
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`HTTP ${res.statusCode}: ${text}`));
          return;
        }
        try {
          resolve(JSON.parse(text || '{}'));
        } catch {
          resolve({ raw: text });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('request timeout'));
    });
    req.write(payload);
    req.end();
  });
}

function parseArgs(argv) {
  const out = {
    jar: '',
    outJar: '',
    server: process.env.DRAGONITE_AUTH_URL || 'https://assets-delivery.site',
    token: process.env.DRAGONITE_RELEASE_REGISTRATION_TOKEN || process.env.RELEASE_REGISTRATION_TOKEN || '',
    ikm: (process.env.DRAGONITE_NATIVE_IKM_HEX || process.env.NATIVE_IKM_HEX || '').trim().toLowerCase(),
    spki: (process.env.DRAGONITE_AUTH_SPKI_PIN || '').trim().toLowerCase(),
    skipRegister: false,
    skipEmbed: false,
    ecdsaPublicSpkiB64: process.env.DRAGONITE_ECDSA_PUBLIC_SPKI_B64 || '',
    authResponseSpki: 'MCowBQYDK2VwAyEAXHwcSx4aiZr0mYVGKW3ufSHNxNGI7fWokp1edJ2oI+Y='
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = argv[i + 1];
    if (a === '--jar' && next) { out.jar = next; i++; }
    else if (a === '--out' && next) { out.outJar = next; i++; }
    else if (a === '--server' && next) { out.server = next; i++; }
    else if (a === '--token' && next) { out.token = next; i++; }
    else if (a === '--ikm' && next) { out.ikm = next.trim().toLowerCase(); i++; }
    else if (a === '--spki' && next) { out.spki = next.trim().toLowerCase(); i++; }
    else if (a === '--skip-register') out.skipRegister = true;
    else if (a === '--skip-embed') out.skipEmbed = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || !args.jar) {
    console.log(`Usage:
  node embed-and-register-release.js --jar <input.jar> [--out <output.jar>]

Env:
  DRAGONITE_RELEASE_REGISTRATION_TOKEN  (same as VPS RELEASE_REGISTRATION_TOKEN)
  NATIVE_IKM_HEX / DRAGONITE_NATIVE_IKM_HEX  (64 hex, same as VPS)
  DRAGONITE_AUTH_SPKI_PIN  (optional 64 hex; otherwise fetched live)
  DRAGONITE_AUTH_URL  (default https://assets-delivery.site)

Flags:
  --skip-embed      only hash + register (JAR already has release IKM)
  --skip-register   only embed keys locally`);
    process.exit(args.help ? 0 : 1);
  }

  const inputJar = path.resolve(args.jar);
  if (!fs.existsSync(inputJar)) die(`JAR not found: ${inputJar}`);

  const outJar = path.resolve(args.outJar || inputJar.replace(/\.jar$/i, '') + '-release.jar');
  fs.copyFileSync(inputJar, outJar);

  const serverUrl = args.server.includes('://') ? args.server : `https://${args.server}`;
  const host = new URL(serverUrl).hostname;
  let spki = args.spki;
  if (!args.skipEmbed) {
    if (!/^[a-f0-9]{64}$/.test(args.ikm)) {
      die('Set NATIVE_IKM_HEX / DRAGONITE_NATIVE_IKM_HEX to the same 64-hex value as the VPS .env');
    }
    if (!/^[a-f0-9]{64}$/.test(spki)) {
      console.log(`Fetching TLS SPKI pin for ${host}:443 ...`);
      spki = await fetchSpkiSha256Hex(host, 443);
    }
    if (!/^[a-f0-9]{64}$/.test(spki)) {
      die('Could not resolve AUTH SPKI pin. Pass --spki or DRAGONITE_AUTH_SPKI_PIN.');
    }

    const mixed = mixIkmBytes(Buffer.from(args.ikm, 'hex'));
    if (!mixed) die('IKM mix failed');
    const katA = 'cloth-kat-v1';
    const katB = 'cloth-kat-v2';
    const katC = 'cloth-kat-v3';
    const ecdsaPublic = args.ecdsaPublicSpkiB64 || '__LEGACY_DISABLED__';

    const fields = {
      BUILD_DIGEST: xorEncryptToHex(randomHex(32)),
      BUILD_SALT_A: xorEncryptToHex(randomHex(10)),
      BUILD_SALT_B: xorEncryptToHex(randomHex(14)),
      AUTH_HOST: xorEncryptToHex(host),
      AUTH_SPKI_SHA256: xorEncryptToHex(spki),
      NATIVE_IKM_HEX: xorEncryptToHex(args.ikm),
      ECDSA_SIGNING_RAW_HEX: xorEncryptToHex('__SERVER_ONLY__'),
      ECDSA_JVM_RAW_HEX: xorEncryptToHex('__OBF_ECDSA_JVM__'),
      ECDSA_PUBLIC_SPKI_B64: xorEncryptToHex(ecdsaPublic),
      AUTH_RESPONSE_ED25519_PUBLIC_SPKI_B64: args.authResponseSpki,
      NATIVE_KAT_INPUT_A: xorEncryptToHex(katA),
      NATIVE_KAT_INPUT_B: xorEncryptToHex(katB),
      NATIVE_KAT_INPUT_C: xorEncryptToHex(katC),
      NATIVE_KAT_EXPECTED_A: xorEncryptToHex(deriveKatExpectedHex(mixed, katA)),
      NATIVE_KAT_EXPECTED_B: xorEncryptToHex(deriveKatExpectedHex(mixed, katB)),
      NATIVE_KAT_EXPECTED_C: xorEncryptToHex(deriveKatExpectedHex(mixed, katC))
    };

    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dragonite-release-'));
    try {
      const javaBin = resolveJavaBin();
      console.log('Embedding release auth fingerprint (no obfuscation)...');
      embedFingerprint(outJar, fields, workDir, javaBin);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
    console.log(`Release JAR: ${outJar}`);
  } else if (outJar !== inputJar) {
    // already copied
  }

  const jarSha256 = sha256File(outJar);
  const buildId = `build-${Date.now()}`;
  const keyHalfB = randomHex(16);
  const createdAtUtc = new Date().toISOString();
  const payload = {
    buildId,
    keyId: buildId,
    keyHalfB,
    jarSha256,
    createdAtUtc
  };

  const outDir = path.join(path.dirname(outJar), 'release-output');
  fs.mkdirSync(outDir, { recursive: true });
  const payloadPath = path.join(outDir, `release-registration-${buildId}.json`);
  fs.writeFileSync(payloadPath, JSON.stringify(payload, null, 2));
  console.log(`JAR SHA-256: ${jarSha256}`);
  console.log(`Registration payload: ${payloadPath}`);

  if (args.skipRegister) {
    console.log('Skipped auth registration (--skip-register).');
    return;
  }
  if (!args.token) {
    die('Set DRAGONITE_RELEASE_REGISTRATION_TOKEN (same value as VPS RELEASE_REGISTRATION_TOKEN).');
  }
  if (!serverUrl.startsWith('https://')) {
    die('Release registration URL must use HTTPS.');
  }

  const registerUrl = `${serverUrl.replace(/\/$/, '')}/v1/release/register`;
  const verifyUrl = `${serverUrl.replace(/\/$/, '')}/v1/release/verify`;
  console.log(`Registering ${buildId} at ${registerUrl} ...`);
  await postJson(registerUrl, args.token, payload);
  await postJson(verifyUrl, args.token, payload);
  console.log('Release registration verified.');
  console.log(JSON.stringify({ buildId, jarSha256, outJar, payloadPath }, null, 2));
}

main().catch((err) => {
  die(err && err.stack ? err.stack : String(err));
});
