'use strict';

const fs = require('fs');
const path = require('path');
const { normalizeLicenseKey } = require('./blacklist-cascade');

const LICENSE_CONFIGS_FILE = path.join(__dirname, 'data', 'license-configs.json');
const MAX_LICENSE_CONFIGS = 24;
const AUTOSAVE_ID = 'autosave';
const AUTOSAVE_NAME = 'Autosave';

function writeJsonAtomic(filePath, obj) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    const tmp = `${filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
    fs.renameSync(tmp, filePath);
}

function loadLicenseConfigStore(filePath) {
    const file = filePath || LICENSE_CONFIGS_FILE;
    try {
        if (!fs.existsSync(file)) return {};
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (e) {
        throw new Error('license-configs read failed: ' + e.message);
    }
}

function saveLicenseConfigStore(store, filePath) {
    writeJsonAtomic(filePath || LICENSE_CONFIGS_FILE, store);
}

function storeKey(input) {
    return normalizeLicenseKey(input);
}

function licenseConfigBucket(store, key) {
    const raw = store[key];
    if (Array.isArray(raw)) {
        return { activeId: null, configs: raw.filter((c) => c && c.id) };
    }
    if (raw && typeof raw === 'object') {
        return {
            activeId: typeof raw.activeId === 'string' ? raw.activeId : null,
            configs: Array.isArray(raw.configs) ? raw.configs.filter((c) => c && c.id) : []
        };
    }
    return { activeId: null, configs: [] };
}

function writeLicenseConfigBucket(store, key, bucket) {
    const incoming = Array.isArray(bucket.configs) ? bucket.configs.filter((c) => c && c.id) : [];
    const autosave = incoming.find((c) => c.id === AUTOSAVE_ID) || null;
    const rest = incoming.filter((c) => c.id !== AUTOSAVE_ID);
    const configs = autosave
        ? [autosave, ...rest.slice(0, MAX_LICENSE_CONFIGS - 1)]
        : rest.slice(0, MAX_LICENSE_CONFIGS);
    let activeId = typeof bucket.activeId === 'string' ? bucket.activeId : null;
    if (activeId && !configs.some((c) => c.id === activeId)) {
        activeId = autosave ? AUTOSAVE_ID : (configs[0] ? configs[0].id : null);
    }
    if (!activeId) {
        activeId = autosave ? AUTOSAVE_ID : (configs[0] ? configs[0].id : null);
    }
    store[key] = { activeId, configs };
}

function summarizeBucket(bucket) {
    const configs = bucket && Array.isArray(bucket.configs) ? bucket.configs : [];
    return {
        count: configs.length,
        hasAutosave: configs.some((c) => c && c.id === AUTOSAVE_ID),
        names: configs.map((c) => {
            if (!c) return '?';
            if (c.id === AUTOSAVE_ID) return AUTOSAVE_NAME;
            return String(c.name || c.id);
        })
    };
}

/**
 * Copy or move ClickGUI snapshots from one license key to another.
 * Store keys are 20-char normalized licenses (same as auth-server).
 */
function linkConfigs(store, fromInput, toInput, options) {
    const opts = options || {};
    const overwrite = opts.overwrite === true;
    const mode = opts.mode === 'copy' ? 'copy' : 'move';
    const from = storeKey(fromInput);
    const to = storeKey(toInput);
    if (from.length !== 20) {
        return { ok: false, error: 'Source key must be a 20-character license' };
    }
    if (to.length !== 20) {
        return { ok: false, error: 'Destination key must be a 20-character license' };
    }
    if (from === to) {
        return { ok: false, error: 'Source and destination are the same key' };
    }
    const src = licenseConfigBucket(store, from);
    if (!src.configs.length) {
        return { ok: false, error: 'No configs stored on the source key' };
    }
    const dest = licenseConfigBucket(store, to);
    if (dest.configs.length && !overwrite) {
        return {
            ok: false,
            error: 'Destination already has configs. Set overwrite to true to merge (source wins on the same id).'
        };
    }
    let merged;
    if (dest.configs.length && overwrite) {
        const byId = new Map();
        for (const c of dest.configs) byId.set(c.id, c);
        for (const c of src.configs) byId.set(c.id, c);
        merged = {
            activeId: src.activeId || dest.activeId,
            configs: [...byId.values()]
        };
    } else {
        merged = {
            activeId: src.activeId,
            configs: src.configs.map((c) => ({ ...c }))
        };
    }
    writeLicenseConfigBucket(store, to, merged);
    if (mode === 'move') {
        delete store[from];
    }
    return {
        ok: true,
        mode,
        from,
        to,
        fromCleared: mode === 'move',
        summary: summarizeBucket(licenseConfigBucket(store, to))
    };
}

function configsForKey(store, input) {
    const key = storeKey(input);
    if (key.length !== 20) {
        return { ok: false, error: 'License key must be 20 characters' };
    }
    return { ok: true, key, summary: summarizeBucket(licenseConfigBucket(store, key)) };
}

module.exports = {
    LICENSE_CONFIGS_FILE,
    MAX_LICENSE_CONFIGS,
    AUTOSAVE_ID,
    loadLicenseConfigStore,
    saveLicenseConfigStore,
    storeKey,
    licenseConfigBucket,
    writeLicenseConfigBucket,
    summarizeBucket,
    linkConfigs,
    configsForKey
};
