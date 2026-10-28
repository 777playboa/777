'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
    PURPOSE_FEATURES,
    PURPOSE_PROTECTED_ACTION,
    expectedHeartbeatProof,
    verifyHeartbeatProofV2,
    mintHeartbeatSeal,
    verifyHeartbeatSeal,
    mintActionTicket,
    verifyActionTicket,
    _resetTicketsForTests
} = require('../auth-action-tickets');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

test.beforeEach(() => {
    _resetTicketsForTests();
});

test('heartbeat proof v2 binds jar and hwid and rejects wrong slot', () => {
    const token = 'session-token-abc';
    const slot = Math.floor(Date.now() / 60000);
    const jar = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
    const hwid = 'hwid-1';
    const proof = expectedHeartbeatProof(token, slot, jar, hwid);
    assert.ok(proof);
    assert.equal(verifyHeartbeatProofV2(token, proof, slot, jar, hwid), true);
    assert.equal(verifyHeartbeatProofV2(token, proof, slot, jar, 'other-hwid'), false);
    assert.equal(verifyHeartbeatProofV2(token, proof, slot, '00'.repeat(32), hwid), false);
    assert.equal(verifyHeartbeatProofV2(token, proof, slot + 5, jar, hwid), false);
    assert.equal(verifyHeartbeatProofV2(token, null, slot, jar, hwid), false);
});

test('heartbeat proof v2 lowercases hwid like the Java client', () => {
    const token = 'session-token-abc';
    const slot = Math.floor(Date.now() / 60000);
    const jar = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
    const proof = expectedHeartbeatProof(token, slot, jar, 'DESKTOP-ABC');
    assert.equal(verifyHeartbeatProofV2(token, proof, slot, jar, 'DESKTOP-ABC'), true);
    assert.equal(verifyHeartbeatProofV2(token, proof, slot, jar, 'desktop-abc'), true);
});

test('heartbeat seal round-trip and rejects forged sig', () => {
    const token = 'sess-1';
    const jar = 'deadbeef'.repeat(8);
    const hwid = 'hw';
    const slot = 42;
    const seal = mintHeartbeatSeal(privateKey, token, jar, hwid, slot);
    assert.ok(seal);
    const parsed = JSON.parse(Buffer.from(seal, 'base64').toString('utf8'));
    assert.equal(parsed.v, 2);
    assert.ok(typeof parsed.presentationSeed === 'number');
    assert.ok(typeof parsed.moduleMask === 'number');
    assert.equal(verifyHeartbeatSeal(publicKey, seal, token, jar, hwid), true);
    assert.equal(verifyHeartbeatSeal(publicKey, seal, 'other', jar, hwid), false);
    const other = crypto.generateKeyPairSync('ed25519');
    assert.equal(verifyHeartbeatSeal(other.publicKey, seal, token, jar, hwid), false);
});

test('features ticket mints and verifies; protected action is single-use', () => {
    const token = 'sess-2';
    const jar = 'cafebabe'.repeat(8);
    const hwid = 'machine';
    const features = mintActionTicket(privateKey, token, jar, hwid, PURPOSE_FEATURES, { singleUse: false });
    assert.ok(features.actionTicket);
    const v1 = verifyActionTicket(publicKey, features.actionTicket, token, jar, hwid, PURPOSE_FEATURES);
    assert.equal(v1.ok, true);

    const action = mintActionTicket(privateKey, token, jar, hwid, PURPOSE_PROTECTED_ACTION, { singleUse: true });
    const first = verifyActionTicket(
        publicKey, action.actionTicket, token, jar, hwid, PURPOSE_PROTECTED_ACTION, { redeem: true });
    assert.equal(first.ok, true);
    const second = verifyActionTicket(
        publicKey, action.actionTicket, token, jar, hwid, PURPOSE_PROTECTED_ACTION, { redeem: true });
    assert.equal(second.ok, false);
    assert.equal(second.reason, 'used');
});

test('action ticket rejects purpose/jar mismatch', () => {
    const token = 'sess-3';
    const jar = '11223344'.repeat(8);
    const hwid = 'x';
    const minted = mintActionTicket(privateKey, token, jar, hwid, PURPOSE_FEATURES);
    const badPurpose = verifyActionTicket(
        publicKey, minted.actionTicket, token, jar, hwid, PURPOSE_PROTECTED_ACTION);
    assert.equal(badPurpose.ok, false);
    const badJar = verifyActionTicket(
        publicKey, minted.actionTicket, token, '00'.repeat(32), hwid, PURPOSE_FEATURES);
    assert.equal(badJar.ok, false);
});
