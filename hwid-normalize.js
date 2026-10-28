'use strict';

const crypto = require('crypto');

const HWID_HEX_RE = /^[a-f0-9]{64}$/i;

function sha256Hex(value) {
    return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function isNormalizedHwidDigest(value) {
    return typeof value === 'string' && HWID_HEX_RE.test(value);
}

function rawHwidEquals(a, b) {
    if (a == null || b == null) return false;
    return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

/**
 * Canonical storage form: SHA-256 of trimmed lowercase raw HWID.
 * COMPUTERNAME is mixed-case on Windows; hashing the raw string made the
 * same PC look like a different machine across stub vs payload vs heartbeat.
 */
function normalizeHWID(hwid) {
    if (hwid == null) return '';
    const trimmed = String(hwid).trim();
    if (!trimmed) return '';
    if (isNormalizedHwidDigest(trimmed)) {
        return trimmed.toLowerCase();
    }
    return sha256Hex(trimmed.toLowerCase());
}

function hwidHashCandidates(rawClientHwid) {
    const hashes = new Set();
    if (rawClientHwid == null) return hashes;
    const s = String(rawClientHwid);
    const trimmed = s.trim();
    const lower = trimmed.toLowerCase();
    hashes.add(sha256Hex(s));
    hashes.add(sha256Hex(trimmed));
    hashes.add(sha256Hex(lower));
    if (isNormalizedHwidDigest(trimmed)) {
        hashes.add(trimmed.toLowerCase());
    }
    return hashes;
}

function licenseHwidMatches(storedHwid, rawClientHwid) {
    if (!storedHwid || rawClientHwid == null || rawClientHwid === '') return false;
    const stored = String(storedHwid).trim();
    const raw = String(rawClientHwid);
    if (stored === raw || rawHwidEquals(stored, raw)) return true;
    const candidates = hwidHashCandidates(raw);
    if (candidates.has(stored) || candidates.has(stored.toLowerCase())) return true;
    if (!isNormalizedHwidDigest(stored)) {
        return candidates.has(normalizeHWID(stored)) || hwidHashCandidates(stored).has(normalizeHWID(raw));
    }
    return false;
}

function hwidMatchesSession(session, rawClientHwid) {
    if (!session || rawClientHwid == null || rawClientHwid === '') return false;
    if (licenseHwidMatches(session.hwid, rawClientHwid)) return true;
    if (session.rawHwid && rawHwidEquals(session.rawHwid, rawClientHwid)) return true;
    return false;
}

function canonicalizeLicenseHwid(licenseData, rawClientHwid) {
    if (!licenseData || rawClientHwid == null || rawClientHwid === '') return false;
    const canonical = normalizeHWID(rawClientHwid);
    if (!canonical) return false;
    if (licenseData.hwid === canonical) return false;
    licenseData.hwid = canonical;
    return true;
}

function isPlaceholderMachineGuid(value) {
    if (value == null) return true;
    const n = String(value).trim().toLowerCase();
    return !n || n === 'unknown-guid' || n === 'unknown' || n === 'null' || n === 'undefined';
}

function machineGuidKey(value) {
    if (isPlaceholderMachineGuid(value)) return '';
    return String(value).trim().toLowerCase();
}

/**
 * Gatherer appends Windows MachineGuid to the raw HWID. VPN / NIC order
 * changes the MAC in the middle of that string, not the guid. IP is never
 * part of the fingerprint.
 */
function rawHwidContainsMachineGuid(rawHwid, storedGuid) {
    const guid = machineGuidKey(storedGuid);
    if (!guid || guid.length < 8) return false;
    if (rawHwid == null) return false;
    const raw = String(rawHwid);
    if (isNormalizedHwidDigest(raw)) return false;
    return raw.toLowerCase().includes(guid);
}

function sameWindowsInstall(storedGuid, rawHwid, submittedGuid) {
    const stored = machineGuidKey(storedGuid);
    if (!stored) return false;
    if (rawHwidContainsMachineGuid(rawHwid, stored)) return true;
    const submitted = machineGuidKey(submittedGuid);
    if (!submitted || submitted !== stored) return false;
    if (rawHwid != null && String(rawHwid).trim() !== '' && !isNormalizedHwidDigest(String(rawHwid))) {
        return false;
    }
    return true;
}

module.exports = {
    HWID_HEX_RE,
    sha256Hex,
    isNormalizedHwidDigest,
    rawHwidEquals,
    normalizeHWID,
    hwidHashCandidates,
    licenseHwidMatches,
    hwidMatchesSession,
    canonicalizeLicenseHwid,
    isPlaceholderMachineGuid,
    machineGuidKey,
    rawHwidContainsMachineGuid,
    sameWindowsInstall
};
