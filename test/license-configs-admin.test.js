'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const licenseAdmin = require('../license-admin');
const cfg = require('../license-configs-admin');

test('addLicenseTime keeps the same key and adds from remaining expiry', () => {
    const data = licenseAdmin.ensureLicenseShape({
        expiresAt: '2026-09-20T00:00:00.000Z',
        currentLicenseId: 7
    });
    const now = Date.parse('2026-09-10T00:00:00.000Z');
    const result = licenseAdmin.addLicenseTime(data, 10 * 86400000, now, '+10d');
    assert.equal(result.ok, true);
    assert.equal(result.expired, false);
    assert.equal(data.expiresAt, '2026-09-30T00:00:00.000Z');
    assert.equal(data.currentLicenseId, 7);
    assert.equal(data.adminHistory.at(-1).action, 'extend');
});

test('addLicenseTime on an expired key starts from now, not the dead date', () => {
    const data = licenseAdmin.ensureLicenseShape({
        expiresAt: '2026-08-01T00:00:00.000Z',
        currentLicenseId: 3
    });
    const now = Date.parse('2026-09-09T12:00:00.000Z');
    const result = licenseAdmin.addLicenseTime(data, 30 * 86400000, now);
    assert.equal(result.ok, true);
    assert.equal(result.expired, true);
    assert.equal(data.expiresAt, '2026-10-09T12:00:00.000Z');
});

test('addLicenseTime refuses lifetime keys', () => {
    const data = licenseAdmin.ensureLicenseShape({ expiresAt: null, currentLicenseId: 1 });
    const result = licenseAdmin.addLicenseTime(data, 86400000, Date.now());
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'lifetime');
    assert.equal(data.expiresAt, null);
});

test('linkConfigs moves the bucket onto the destination key', () => {
    const store = {
        AAAAAAAAAAAAAAAAAAAA: {
            activeId: 'autosave',
            configs: [
                { id: 'autosave', name: 'Autosave', snapshot: { v: 2 } },
                { id: 'rage', name: 'Rage', snapshot: { v: 2 } }
            ]
        }
    };
    const result = cfg.linkConfigs(store, 'AAAA-AAAA-AAAA-AAAA-AAAA', 'BBBBBBBBBBBBBBBBBBBB', { mode: 'move' });
    assert.equal(result.ok, true);
    assert.equal(result.fromCleared, true);
    assert.equal(store.AAAAAAAAAAAAAAAAAAAA, undefined);
    assert.equal(cfg.licenseConfigBucket(store, 'BBBBBBBBBBBBBBBBBBBB').configs.length, 2);
    assert.equal(result.summary.hasAutosave, true);
});

test('linkConfigs refuses a dest with configs unless overwrite', () => {
    const store = {
        AAAAAAAAAAAAAAAAAAAA: { configs: [{ id: 'autosave', name: 'Autosave' }] },
        BBBBBBBBBBBBBBBBBBBB: { configs: [{ id: 'autosave', name: 'Autosave' }] }
    };
    const blocked = cfg.linkConfigs(store, 'AAAAAAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBBBBBB');
    assert.equal(blocked.ok, false);
    const merged = cfg.linkConfigs(store, 'AAAAAAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBBBBBB', { overwrite: true, mode: 'move' });
    assert.equal(merged.ok, true);
    assert.equal(merged.summary.count, 1);
});

test('linkConfigs round-trips through a temp file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dn-cfg-'));
    const file = path.join(dir, 'license-configs.json');
    const store = {
        AAAAAAAAAAAAAAAAAAAA: { configs: [{ id: 'autosave', name: 'Autosave' }] }
    };
    cfg.saveLicenseConfigStore(store, file);
    const loaded = cfg.loadLicenseConfigStore(file);
    const result = cfg.linkConfigs(loaded, 'AAAAAAAAAAAAAAAAAAAA', 'CCCCCCCCCCCCCCCCCCCC', { mode: 'copy' });
    assert.equal(result.ok, true);
    assert.equal(result.fromCleared, false);
    cfg.saveLicenseConfigStore(loaded, file);
    const again = cfg.loadLicenseConfigStore(file);
    assert.equal(cfg.licenseConfigBucket(again, 'AAAAAAAAAAAAAAAAAAAA').configs.length, 1);
    assert.equal(cfg.licenseConfigBucket(again, 'CCCCCCCCCCCCCCCCCCCC').configs.length, 1);
    fs.rmSync(dir, { recursive: true, force: true });
});
