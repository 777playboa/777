'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LICENSES_FILE = path.join(__dirname, 'licenses.json');

// License prefixes:
// AA: Lifetime Normal
// AB: Lifetime Premium
// AC: Monthly (30 days)
// AD: Custom
const type = process.argv[2] || 'AB'; // default Lifetime Premium
const note = process.argv[3] || 'Generated via CLI for Client 777';

function generateRandomKey(prefix) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = prefix.toUpperCase();
    while (key.length < 20) {
        key += chars.charAt(crypto.randomInt(0, chars.length));
    }
    return key;
}

function formatKeyDisplay(key) {
    return `${key.slice(0, 4)}-${key.slice(4, 8)}-${key.slice(8, 12)}-${key.slice(12, 16)}-${key.slice(16, 20)}`;
}

let licenses = {};
if (fs.existsSync(LICENSES_FILE)) {
    try {
        licenses = JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8'));
    } catch (e) {
        licenses = {};
    }
}

const prefix = type.length >= 2 ? type.slice(0, 2).toUpperCase() : 'AA';
const key = generateRandomKey(prefix);

let licenseType = 'lifetime_premium';
let expiresAt = null;

if (prefix === 'AA') {
    licenseType = 'lifetime_normal';
} else if (prefix === 'AB') {
    licenseType = 'lifetime_premium';
} else if (prefix === 'AC') {
    licenseType = 'monthly';
    const d = new Date();
    d.setDate(d.getDate() + 30);
    expiresAt = d.toISOString();
}

licenses[key] = {
    licenseType,
    expiresAt,
    hwid: null,
    active: true,
    createdAt: new Date().toISOString(),
    note
};

fs.writeFileSync(LICENSES_FILE, JSON.stringify(licenses, null, 2), 'utf8');

console.log('========================================');
console.log('       777 Auth - License Created       ');
console.log('========================================');
console.log('Key (Plain):   ', key);
console.log('Key (Dashed):  ', formatKeyDisplay(key));
console.log('Type:          ', licenseType);
console.log('Expires:       ', expiresAt || 'Never (Lifetime)');
console.log('Note:          ', note);
console.log('Saved to:      ', LICENSES_FILE);
console.log('========================================');
