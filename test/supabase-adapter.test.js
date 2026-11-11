'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// Test the deduplication & lastLogin preservation logic
test('deduplicates hyphenated and clean keys, preserving revocation and timestamps', () => {
    const rawRows = [
        {
            license_key: '777T-POLO-0133-36TR-2026',
            hwid: null,
            type: 'lifetime_premium',
            active: true,
            discord_id: 'casca0004332',
            last_login: null
        },
        {
            license_key: '777TPOLO013336TR2026',
            hwid: 'e055ad83bac4c6bac801b18f459d6f7e',
            type: 'lifetime_premium',
            active: true,
            discord_id: '711994393703219232',
            last_login: '2026-11-10T19:40:23.801Z'
        },
        {
            license_key: 'ABZJ-OHB4-5EZG-3Z4C-BWZE',
            hwid: null,
            type: 'lifetime_premium',
            active: true,
            discord_id: null,
            last_login: null
        },
        {
            license_key: 'ABZJOHB45EZG3Z4CBWZE',
            hwid: '3639804ea44f6c19d9d66125a402f87',
            type: 'lifetime_premium',
            active: false, // REVOKED!
            discord_id: null,
            last_login: '2026-11-10T19:40:23.801Z'
        }
    ];

    const map = new Map();
    for (const row of rawRows) {
        const cleanKey = (row.license_key || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
        if (!cleanKey) continue;

        const existing = map.get(cleanKey);
        if (existing) {
            const isActive = existing.active && (row.active !== false);
            const rawKey = (row.license_key && row.license_key.includes('-'))
                ? row.license_key
                : (existing.rawKey || row.license_key);
            const hwid = row.hwid || existing.hwid || null;
            const discordId = row.discord_id || existing.discordId || null;
            const lastLogin = row.last_login || existing.lastLogin || null;

            map.set(cleanKey, {
                rawKey,
                hwid,
                active: isActive,
                discordId,
                lastLogin
            });
        } else {
            map.set(cleanKey, {
                rawKey: row.license_key || cleanKey,
                hwid: row.hwid || null,
                active: row.active !== false,
                discordId: row.discord_id || null,
                lastLogin: row.last_login || null
            });
        }
    }

    assert.equal(map.size, 2);

    const polo = map.get('777TPOLO013336TR2026');
    assert.equal(polo.rawKey, '777T-POLO-0133-36TR-2026');
    assert.equal(polo.hwid, 'e055ad83bac4c6bac801b18f459d6f7e');
    assert.equal(polo.active, true);
    assert.equal(polo.lastLogin, '2026-11-10T19:40:23.801Z');

    const abzj = map.get('ABZJOHB45EZG3Z4CBWZE');
    assert.equal(abzj.rawKey, 'ABZJ-OHB4-5EZG-3Z4C-BWZE');
    assert.equal(abzj.active, false, 'If any duplicate row was revoked, the merged record MUST be revoked');
    assert.equal(abzj.hwid, '3639804ea44f6c19d9d66125a402f87');
});
