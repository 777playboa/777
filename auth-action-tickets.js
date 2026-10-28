'use strict';

const crypto = require('crypto');
const { hkdfSha256 } = require('./auth-proof-hmac');

const HB_INFO = Buffer.from('dragonite-hb-v2', 'utf8');

const PURPOSE_FEATURES = 'PURPOSE_FEATURES';
const PURPOSE_PROTECTED_ACTION = 'PURPOSE_PROTECTED_ACTION';

const FEATURES_TTL_MS = 3 * 60 * 1000;
const PROTECTED_ACTION_TTL_MS = 90 * 1000;

/** In-memory single-use / sliding tickets keyed by ticketId. */
const issuedTickets = new Map();

function normalizeJar(jarHash) {
    if (!jarHash) return '';
    return String(jarHash).trim().toLowerCase();
}

function normalizeHwid(hwid) {
    return hwid == null ? '' : String(hwid).trim().toLowerCase();
}

function deriveHeartbeatKey(sessionToken) {
    if (!sessionToken) return null;
    const tok = Buffer.from(String(sessionToken), 'utf8');
    return hkdfSha256(tok, Buffer.alloc(32), HB_INFO, 32);
}

/**
 * Client heartbeat proof: HMAC-SHA256(HKDF(sessionToken, dragonite-hb-v2),
 *   `${slot}|${jarHash}|${hwid}`) → base64
 */
function expectedHeartbeatProof(sessionToken, slot, jarHash, hwid) {
    const key = deriveHeartbeatKey(sessionToken);
    if (!key) return null;
    const msg = `${Number(slot)}|${normalizeJar(jarHash)}|${normalizeHwid(hwid)}`;
    return crypto.createHmac('sha256', key).update(msg, 'utf8').digest('base64');
}

/**
 * Accept current slot or previous minute only (clock skew). Rejects missing proof.
 */
function verifyHeartbeatProofV2(sessionToken, heartbeatProof, heartbeatSlot, jarHash, hwid) {
    if (heartbeatProof == null || heartbeatSlot == null) return false;
    const slot = Number(heartbeatSlot);
    if (!Number.isFinite(slot)) return false;
    const nowSlot = Math.floor(Date.now() / 60000);
    if (slot !== nowSlot && slot !== nowSlot - 1) {
        return false;
    }
    const expected = expectedHeartbeatProof(sessionToken, slot, jarHash, hwid);
    if (!expected) return false;
    return timingSafeEqualString(String(heartbeatProof), expected);
}

function timingSafeEqualString(a, b) {
    const ba = Buffer.from(String(a), 'utf8');
    const bb = Buffer.from(String(b), 'utf8');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

function signCanonical(signingKey, canonical) {
    if (!signingKey) return null;
    return crypto.sign(null, Buffer.from(canonical, 'utf8'), signingKey).toString('base64');
}

function verifyCanonical(publicKey, canonical, sigB64) {
    if (!publicKey || !sigB64) return false;
    try {
        return crypto.verify(
            null,
            Buffer.from(canonical, 'utf8'),
            publicKey,
            Buffer.from(String(sigB64), 'base64'));
    } catch {
        return false;
    }
}

function heartbeatSealCanonical(sessionToken, jar, hwid, slot, exp, purpose) {
    return `hb1|${sessionToken}|${jar}|${hwid}|${Number(slot)}|${exp}|${purpose}`;
}

function heartbeatSealCanonicalV2(sessionToken, jar, hwid, slot, exp, purpose, presentationSeed, moduleMask) {
    return `hb2|${sessionToken}|${jar}|${hwid}|${Number(slot)}|${exp}|${purpose}|${presentationSeed >>> 0}|${moduleMask >>> 0}`;
}

function ticketCanonical(ticketId, sessionToken, jar, hwid, purpose, nonce, exp) {
    return `tk1|${ticketId}|${sessionToken}|${jar}|${hwid}|${purpose}|${nonce}|${exp}`;
}

/**
 * Opaque heartbeat seal: base64(JSON{v,kind,exp,slot,jar,hwid,purpose,sig})
 * sig = Ed25519 over canonical fields (auth-response private key).
 */
function mintHeartbeatSeal(signingKey, sessionToken, jarHash, hwid, slot) {
    if (!signingKey) return null;
    const exp = Date.now() + FEATURES_TTL_MS;
    const jar = normalizeJar(jarHash);
    const hw = normalizeHwid(hwid);
    const purpose = PURPOSE_FEATURES;
    const presentationSeed = crypto.randomBytes(4).readUInt32BE(0) >>> 0;
    const moduleMask = 0xFFFFFFFF >>> 0;
    const canonical = heartbeatSealCanonicalV2(
        sessionToken, jar, hw, slot, exp, purpose, presentationSeed, moduleMask);
    const sig = signCanonical(signingKey, canonical);
    if (!sig) return null;
    const blob = {
        v: 2,
        kind: 'hb',
        exp,
        slot: Number(slot),
        jar,
        hwid: hw,
        purpose,
        presentationSeed,
        moduleMask,
        sig
    };
    return Buffer.from(JSON.stringify(blob), 'utf8').toString('base64');
}

function verifyHeartbeatSeal(publicKey, sealB64, sessionToken, jarHash, hwid) {
    const parsed = parseSealBlob(sealB64);
    if (!parsed || parsed.kind !== 'hb') return false;
    if (typeof parsed.exp !== 'number' || Date.now() > parsed.exp) return false;
    if (normalizeJar(parsed.jar) !== normalizeJar(jarHash)) return false;
    if (normalizeHwid(parsed.hwid) !== normalizeHwid(hwid)) return false;
    if (parsed.purpose !== PURPOSE_FEATURES) return false;
    let canonical;
    if (parsed.v === 2) {
        if (typeof parsed.presentationSeed !== 'number' || typeof parsed.moduleMask !== 'number') {
            return false;
        }
        canonical = heartbeatSealCanonicalV2(
            sessionToken, normalizeJar(jarHash), normalizeHwid(hwid),
            parsed.slot, parsed.exp, PURPOSE_FEATURES,
            parsed.presentationSeed, parsed.moduleMask);
    } else if (parsed.v === 1) {
        canonical = heartbeatSealCanonical(
            sessionToken, normalizeJar(jarHash), normalizeHwid(hwid),
            parsed.slot, parsed.exp, PURPOSE_FEATURES);
    } else {
        return false;
    }
    return verifyCanonical(publicKey, canonical, parsed.sig);
}

function mintActionTicket(signingKey, sessionToken, jarHash, hwid, purpose, { singleUse = false, ttlMs } = {}) {
    if (!signingKey) return null;
    const ticketId = crypto.randomBytes(16).toString('hex');
    const ttl = ttlMs != null ? ttlMs
        : (purpose === PURPOSE_PROTECTED_ACTION ? PROTECTED_ACTION_TTL_MS : FEATURES_TTL_MS);
    const exp = Date.now() + ttl;
    const jar = normalizeJar(jarHash);
    const hw = normalizeHwid(hwid);
    const nonce = crypto.randomBytes(8).toString('hex');
    const canonical = ticketCanonical(ticketId, sessionToken, jar, hw, purpose, nonce, exp);
    const sig = signCanonical(signingKey, canonical);
    if (!sig) return null;
    const record = {
        ticketId,
        sessionToken,
        jar,
        hwid: hw,
        purpose,
        nonce,
        exp,
        singleUse: !!singleUse,
        used: false
    };
    issuedTickets.set(ticketId, record);
    pruneExpiredTickets();
    const blob = {
        v: 1,
        kind: 'tk',
        ticketId,
        exp,
        jar,
        hwid: hw,
        purpose,
        nonce,
        sig
    };
    return {
        actionTicket: Buffer.from(JSON.stringify(blob), 'utf8').toString('base64'),
        ticketId,
        exp,
        purpose
    };
}

function parseSealBlob(sealB64) {
    if (!sealB64 || typeof sealB64 !== 'string') return null;
    try {
        const raw = Buffer.from(sealB64, 'base64').toString('utf8');
        return JSON.parse(raw);
    } catch {
        return null;
    }
}

/**
 * Cryptographic verify of an action ticket blob. Optionally marks single-use tickets used.
 */
function verifyActionTicket(publicKey, ticketB64, sessionToken, jarHash, hwid, expectedPurpose, { redeem = false } = {}) {
    const parsed = parseSealBlob(ticketB64);
    if (!parsed || parsed.kind !== 'tk' || parsed.v !== 1) {
        return { ok: false, reason: 'malformed' };
    }
    if (typeof parsed.exp !== 'number' || Date.now() > parsed.exp) {
        return { ok: false, reason: 'expired' };
    }
    if (expectedPurpose && parsed.purpose !== expectedPurpose) {
        return { ok: false, reason: 'purpose' };
    }
    if (normalizeJar(parsed.jar) !== normalizeJar(jarHash)) {
        return { ok: false, reason: 'jar' };
    }
    if (normalizeHwid(parsed.hwid) !== normalizeHwid(hwid)) {
        return { ok: false, reason: 'hwid' };
    }
    const canonical = ticketCanonical(
        parsed.ticketId, sessionToken, normalizeJar(jarHash), normalizeHwid(hwid),
        parsed.purpose, parsed.nonce, parsed.exp);
    if (!verifyCanonical(publicKey, canonical, parsed.sig)) {
        return { ok: false, reason: 'sig' };
    }
    const record = issuedTickets.get(parsed.ticketId);
    if (!record) {
        if (parsed.purpose === PURPOSE_PROTECTED_ACTION) {
            return { ok: false, reason: 'unknown' };
        }
        return { ok: true, record: null };
    }
    if (record.sessionToken !== sessionToken) {
        return { ok: false, reason: 'session' };
    }
    if (record.used) {
        return { ok: false, reason: 'used' };
    }
    if (redeem && record.singleUse) {
        record.used = true;
        issuedTickets.set(parsed.ticketId, record);
    }
    return { ok: true, record };
}

function pruneExpiredTickets() {
    const now = Date.now();
    for (const [id, rec] of issuedTickets) {
        if (!rec || rec.exp < now || rec.used) {
            issuedTickets.delete(id);
        }
    }
}

function clearTicketsForSession(sessionToken) {
    for (const [id, rec] of issuedTickets) {
        if (rec && rec.sessionToken === sessionToken) {
            issuedTickets.delete(id);
        }
    }
}

function _resetTicketsForTests() {
    issuedTickets.clear();
}

module.exports = {
    PURPOSE_FEATURES,
    PURPOSE_PROTECTED_ACTION,
    FEATURES_TTL_MS,
    PROTECTED_ACTION_TTL_MS,
    deriveHeartbeatKey,
    expectedHeartbeatProof,
    verifyHeartbeatProofV2,
    mintHeartbeatSeal,
    verifyHeartbeatSeal,
    mintActionTicket,
    verifyActionTicket,
    parseSealBlob,
    clearTicketsForSession,
    heartbeatSealCanonical,
    heartbeatSealCanonicalV2,
    _resetTicketsForTests
};
