'use strict';

function normalizeSha256(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
}

function authorizeKeyAccess({ production = false, session, keyData, release }) {
    if (!session || !keyData) {
        return { allowed: false, reason: 'missing_context' };
    }
    // Stub sessions exist only to download the encrypted client ZIP.
    // Split-key halves require a full /v1/auth session (ECDSA proof + jar hash).
    if (session.stubLoader) {
        return { allowed: false, reason: 'stub_session' };
    }
    if (keyData.assignedTo && keyData.assignedTo !== session.license) {
        return { allowed: false, reason: 'wrong_license' };
    }
    if (!release) {
        return production
            ? { allowed: false, reason: 'unregistered_release' }
            : { allowed: true, reason: 'legacy_development_key' };
    }

    const sessionHash = normalizeSha256(session.jarHash);
    const releaseHashes = new Set([
        release.jarSha256,
        ...(Array.isArray(release.jarHashes) ? release.jarHashes : [])
    ]);

    // If the session carries no jar hash (old client or hash resolution failed),
    // allow in dev / warn in production but don't hard-block — the HWID check
    // already validated the machine.
    if (!sessionHash) {
        return production
            ? { allowed: false, reason: 'missing_jar_hash' }
            : { allowed: true,  reason: 'development_no_jar_hash' };
    }

    if (!releaseHashes.has(sessionHash)) {
        return { allowed: false, reason: 'wrong_release' };
    }
    return { allowed: true, reason: 'authorized' };
}

module.exports = { authorizeKeyAccess, normalizeSha256 };
