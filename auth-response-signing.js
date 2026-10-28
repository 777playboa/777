'use strict';

/** Canonical string shared by the auth-response signing path and tests. */
function authResponseSigningPayload(request, statusCode, payload) {
    const granted = payload.authenticated === true || payload.success === true || payload.ok === true ? '1' : '0';
    const nonce = String(request?.body?.nonce || '');
    const jarHash = String(request?.body?.jarHash || '').trim().toLowerCase();
    // Heartbeat / action-ticket responses often omit sessionToken in the JSON body;
    // bind the request token so client verification (request sessionToken) matches.
    const sessionToken = String(
        payload.sessionToken
            || request?.body?.sessionToken
            || '');
    return `${request.method}|${request.path}|${statusCode}|${granted}|${sessionToken}|${payload.expiresAt || ''}|${nonce}|${jarHash}`;
}

module.exports = { authResponseSigningPayload };
