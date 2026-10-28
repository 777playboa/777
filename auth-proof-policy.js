'use strict';

function proofKind(proof) {
    if (typeof proof !== 'string') return 'missing';
    if (proof.startsWith('hmac2:')) return 'nonce-bound-hmac';
    if (proof.startsWith('ecdsa2:')) return 'nonce-bound-ecdsa';
    if (proof.startsWith('ecdsa:') || proof.startsWith('ed25519:')) return 'legacy';
    return 'unknown';
}

function proofFormatAllowed(proof, {
    production = false,
    allowLegacy = false,
    allowLegacyProofsProduction = false
} = {}) {
    const kind = proofKind(proof);
    if (kind === 'nonce-bound-hmac') return true;
    if (kind === 'nonce-bound-ecdsa') return production ? allowLegacyProofsProduction : true;
    if (kind === 'legacy') return !production && allowLegacy;
    return false;
}

module.exports = { proofKind, proofFormatAllowed };
