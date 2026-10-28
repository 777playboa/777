'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
    sha256Hex,
    normalizeHWID,
    licenseHwidMatches,
    hwidMatchesSession,
    canonicalizeLicenseHwid,
    rawHwidEquals,
    sameWindowsInstall,
    isPlaceholderMachineGuid
} = require('../hwid-normalize');

const mixed = 'a1b2c3d4-DESKTOP-Daniel-cpu-aabbccdd-guid';
const lower = mixed.toLowerCase();

test('canonical HWID hash is lowercase-stable', () => {
    assert.equal(normalizeHWID(mixed), normalizeHWID(lower));
    assert.equal(normalizeHWID(mixed), sha256Hex(lower));
    assert.notEqual(normalizeHWID(mixed), sha256Hex(mixed));
});

test('legacy mixed-case stored hash still matches mixed-case client', () => {
    const legacyStored = sha256Hex(mixed);
    assert.equal(licenseHwidMatches(legacyStored, mixed), true);
    assert.equal(licenseHwidMatches(normalizeHWID(mixed), mixed), true);
    assert.equal(licenseHwidMatches(normalizeHWID(mixed), lower), true);
});

test('different machines do not match', () => {
    assert.equal(licenseHwidMatches(normalizeHWID(mixed), 'ffff-OTHER-PC-cpu-mac-guid'), false);
});

test('heartbeat matches session even when stored hash used mixed case', () => {
    const session = {
        hwid: sha256Hex(mixed),
        rawHwid: mixed
    };
    assert.equal(hwidMatchesSession(session, lower), true);
    assert.equal(hwidMatchesSession(session, mixed), true);
    assert.equal(hwidMatchesSession(session, 'ffff-OTHER-PC-cpu-mac-guid'), false);
});

test('canonicalize migrates legacy hash without treating it as a new PC', () => {
    const licenseData = { hwid: sha256Hex(mixed), hwidChanges: 1 };
    assert.equal(licenseHwidMatches(licenseData.hwid, mixed), true);
    assert.equal(canonicalizeLicenseHwid(licenseData, mixed), true);
    assert.equal(licenseData.hwid, normalizeHWID(lower));
    assert.equal(licenseData.hwidChanges, 1);
    assert.equal(licenseHwidMatches(licenseData.hwid, mixed), true);
    assert.equal(canonicalizeLicenseHwid(licenseData, mixed), false);
});

test('raw compare is case-insensitive', () => {
    assert.equal(rawHwidEquals(mixed, lower), true);
    assert.equal(rawHwidEquals(mixed, 'nope'), false);
});

const guid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const hwidEthernet = `volserial-DESKTOP-PC-cpuid-aabbccddeeff-${guid}`;
const hwidVpnNic = `volserial-DESKTOP-PC-cpuid-112233445566-${guid}`;

test('same Windows install survives MAC/VPN NIC swap', () => {
    assert.equal(sameWindowsInstall(guid, hwidEthernet, guid), true);
    assert.equal(sameWindowsInstall(guid, hwidVpnNic, guid), true);
    assert.equal(sameWindowsInstall(guid, hwidVpnNic, null), true);
    assert.equal(licenseHwidMatches(normalizeHWID(hwidEthernet), hwidVpnNic), false);
});

test('different MachineGuid is a different PC', () => {
    const other = `volserial-DESKTOP-PC-cpuid-aabbccddeeff-ffffffff-ffff-ffff-ffff-ffffffffffff`;
    assert.equal(sameWindowsInstall(guid, other, 'ffffffff-ffff-ffff-ffff-ffffffffffff'), false);
});

test('spoofed machineGuid field without guid in raw HWID is rejected', () => {
    assert.equal(sameWindowsInstall(guid, 'vol-PC-cpu-mac-not-the-guid', guid), false);
});

test('placeholder machineGuid is not an identity', () => {
    assert.equal(isPlaceholderMachineGuid('unknown-guid'), true);
    assert.equal(sameWindowsInstall('unknown-guid', hwidEthernet, 'unknown-guid'), false);
});
