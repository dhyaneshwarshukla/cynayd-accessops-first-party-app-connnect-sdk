"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.applicationAuthorizationEnabled = exports.ApplicationAccessError = void 0;
exports.configuredInstallation = configuredInstallation;
exports.checkApplicationAccess = checkApplicationAccess;
const crypto_1 = require("crypto");
class ApplicationAccessError extends Error {
    code;
    status;
    constructor(code, status) {
        super(status === 503 ? 'Application access check unavailable' : 'Application access denied');
        this.code = code;
        this.status = status;
    }
}
exports.ApplicationAccessError = ApplicationAccessError;
const applicationAuthorizationEnabled = () => process.env.ACCESSOPS_APPLICATION_AUTHORIZATION_ENABLED === 'true';
exports.applicationAuthorizationEnabled = applicationAuthorizationEnabled;
const deny = (code) => { throw new ApplicationAccessError(code, 403); };
const unavailable = () => { throw new ApplicationAccessError('ACCESS_DECISION_UNAVAILABLE', 503); };
const text = (value) => typeof value === 'string' ? value.trim() : '';
const validEpoch = (value) => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
function configuredInstallation(organizationId) {
    try {
        const raw = JSON.parse(process.env.ACCESSOPS_APPLICATION_INSTALLATIONS || '{}');
        return raw && typeof raw === 'object' && !Array.isArray(raw) &&
            Object.prototype.hasOwnProperty.call(raw, organizationId) ? text(raw[organizationId]) : '';
    }
    catch {
        return unavailable();
    }
}
async function checkApplicationAccess(applicationKey, scope, options = {}) {
    const organizationId = text(scope.organizationId), personId = text(scope.personId);
    if (!organizationId || !personId)
        return deny('SSO_SUBJECT_REQUIRED');
    const configured = configuredInstallation(organizationId);
    const claimed = text(scope.installedAppId);
    if (claimed && configured && claimed !== configured)
        return deny('APPLICATION_TARGET_MISMATCH');
    if (!configured)
        return deny('APPLICATION_INSTALLATION_REQUIRED');
    const installedAppId = configured;
    if (!installedAppId)
        return deny('APPLICATION_INSTALLATION_REQUIRED');
    if (!options.initial && (!claimed || !validEpoch(scope.launchAccessEpoch)))
        return deny('APPLICATION_SESSION_REAUTH_REQUIRED');
    const base = (process.env.ACCESSOPS_BASE_URL || process.env.ACCESSOPS_URL || '').trim().replace(/\/$/, '');
    try {
        const url = new URL(base);
        if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/')
            return unavailable();
    }
    catch {
        return unavailable();
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    try {
        const pem = process.env.SERVICE_AUTH_PRIVATE_KEY_PEM?.trim();
        const kid = process.env.SERVICE_AUTH_KID?.trim();
        if (!pem || !kid)
            return unavailable();
        const key = (0, crypto_1.createPrivateKey)(pem);
        if (key.asymmetricKeyType !== 'ed25519')
            return unavailable();
        const issuedAt = Math.floor(Date.now() / 1000);
        const claims = { serviceId: applicationKey, audience: 'accessops-service', organizationId,
            personId, installationId: installedAppId, applicationKey, scopes: ['accessops.launch.evaluate'],
            issuedAt, expiresAt: issuedAt + 30, kid, alg: 'EdDSA' };
        const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid })).toString('base64url');
        const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
        const data = `${header}.${payload}`;
        const token = `${data}.${(0, crypto_1.sign)(null, Buffer.from(data), key).toString('base64url')}`;
        const headers = { 'content-type': 'application/json', authorization: `Bearer ${token}` };
        const response = await (options.fetchImpl || fetch)(`${base}/api/v1/accessops/launch/product-evaluate`, {
            method: 'POST', headers, signal: controller.signal, redirect: 'error',
            body: JSON.stringify({ organizationId, userId: personId, installedAppId, applicationKey, permission: 'ACCESS', purpose: 'PRODUCT_API' }),
        });
        if (!response.ok)
            return unavailable();
        const body = await response.json();
        if (body.availability === 'UNAVAILABLE')
            return unavailable();
        if (body.decision === 'DENY')
            return deny('APPLICATION_ACCESS_DENIED');
        if (body.decision !== 'ALLOW' || body.availability !== 'AVAILABLE' || body.launchSource !== 'ACCESSOPS' || body.effectiveAccess !== true || body.launchReady !== true)
            return unavailable();
        const target = body.authorityTarget;
        if (!target || target.organizationId !== organizationId || target.personId !== personId ||
            target.installationId !== installedAppId || target.applicationId !== applicationKey || target.permission !== 'ACCESS' ||
            body.installedAppId !== installedAppId || !validEpoch(body.launchAccessEpoch))
            return unavailable();
        if (!options.initial && scope.launchAccessEpoch !== body.launchAccessEpoch)
            return deny('ACCESS_EPOCH_STALE');
        return { installedAppId, launchAccessEpoch: body.launchAccessEpoch };
    }
    catch (cause) {
        if (cause instanceof ApplicationAccessError)
            throw cause;
        return unavailable();
    }
    finally {
        clearTimeout(timeout);
    }
}
//# sourceMappingURL=application-authorization.js.map