import {createHmac,createPrivateKey,randomUUID,sign} from 'crypto';
/** Request-time whole-application authorization. No positive cache or role bypass.
 * The caller must verify its session credential before supplying this scope.
 * Keep the copies in Calendar, Vault and Forms identical (checked in release tests).
 */
export type ApplicationSession = { personId: string; organizationId: string;
  installedAppId?: unknown; launchAccessEpoch?: unknown };
export class ApplicationAccessError extends Error {
  constructor(public readonly code: string, public readonly status: number) {
    super(status === 503 ? 'Application access check unavailable' : 'Application access denied');
  }
}
export const applicationAuthorizationEnabled = () =>
  process.env.ACCESSOPS_APPLICATION_AUTHORIZATION_ENABLED === 'true';
const deny = (code: string): never => { throw new ApplicationAccessError(code, 403); };
const unavailable = (): never => { throw new ApplicationAccessError('ACCESS_DECISION_UNAVAILABLE', 503); };
const text = (value: unknown): string => typeof value === 'string' ? value.trim() : '';
const validEpoch = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
export function configuredInstallation(organizationId: string): string {
  try {
    const raw = JSON.parse(process.env.ACCESSOPS_APPLICATION_INSTALLATIONS || '{}');
    return raw && typeof raw === 'object' && !Array.isArray(raw) &&
      Object.prototype.hasOwnProperty.call(raw, organizationId) ? text(raw[organizationId]) : '';
  } catch { return unavailable(); }
}
export async function checkApplicationAccess(applicationKey: string, scope: ApplicationSession,
  options: {initial?: boolean; fetchImpl?: typeof fetch} = {}): Promise<{installedAppId: string; launchAccessEpoch: number}> {
  const organizationId = text(scope.organizationId), personId = text(scope.personId);
  if (!organizationId || !personId) return deny('SSO_SUBJECT_REQUIRED');
  const configured = configuredInstallation(organizationId);
  const claimed = text(scope.installedAppId);
  if (claimed && configured && claimed !== configured) return deny('APPLICATION_TARGET_MISMATCH');
  const installedAppId = claimed || configured;
  if (!installedAppId) return deny('APPLICATION_INSTALLATION_REQUIRED');
  if (!options.initial && (!claimed || !validEpoch(scope.launchAccessEpoch))) return deny('APPLICATION_SESSION_REAUTH_REQUIRED');
  const base = (process.env.ACCESSOPS_BASE_URL || process.env.ACCESSOPS_URL || '').trim().replace(/\/$/, '');
  if (!base) return unavailable();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3000);
  try {
    const headers: Record<string,string> = {'content-type':'application/json',
      'x-organization-id':organizationId,'x-user-id':personId,'x-platform-role':'USER'};
    const requestId=randomUUID();
    headers['x-request-id']=requestId;
    const trust=process.env.GATEWAY_ACTOR_TRUST_SECRET?.trim();
    if(trust) headers['x-gateway-actor-proof']=createHmac('sha256',trust).update(`${organizationId}\n${personId}\n${requestId}`).digest('hex');
    let token=process.env.ACCESSOPS_SERVICE_TOKEN?.trim();
    if(!token){
      const pem=process.env.SERVICE_AUTH_PRIVATE_KEY_PEM?.trim();
      const secret=process.env.SERVICE_AUTH_SECRET?.trim();
      if(!pem && !secret)return unavailable();
      const issuedAt=Math.floor(Date.now()/1000),kid=process.env.SERVICE_AUTH_KID || applicationKey;
      const claims={serviceId:applicationKey,audience:'accessops-service',organizationId,
        personId,installationId:installedAppId,applicationKey,scopes:['accessops.launch.evaluate'],issuedAt,expiresAt:issuedAt+30,kid,alg:pem?'EdDSA':'HS256'};
      const payload=Buffer.from(JSON.stringify(claims)).toString('base64url');
      if(pem){const header=Buffer.from(JSON.stringify({alg:'EdDSA',typ:'JWT',kid})).toString('base64url');
        const data=`${header}.${payload}`;token=`${data}.${sign(null,Buffer.from(data),createPrivateKey(pem)).toString('base64url')}`;
      }else token=`${payload}.${createHmac('sha256',secret!).update(payload).digest('base64url')}`;
    }
    headers.authorization=`Bearer ${token}`;
    const response = await (options.fetchImpl || fetch)(`${base}/api/v1/accessops/launch/product-evaluate`, {
      method:'POST', headers, signal:controller.signal,
      body:JSON.stringify({organizationId,userId:personId,installedAppId,applicationKey,permission:'ACCESS',purpose:'PRODUCT_API'}),
    });
    if (!response.ok) return unavailable();
    const body = await response.json() as Record<string,unknown>;
    if (body.availability === 'UNAVAILABLE') return unavailable();
    if (body.decision === 'DENY') return deny('APPLICATION_ACCESS_DENIED');
    if (body.decision !== 'ALLOW' || body.availability !== 'AVAILABLE' || body.launchSource !== 'ACCESSOPS' || body.effectiveAccess !== true || body.launchReady !== true) return unavailable();
    const target = body.authorityTarget as Record<string,unknown> | undefined;
    if (!target || target.organizationId !== organizationId || target.personId !== personId ||
      target.installationId !== installedAppId || target.applicationId !== applicationKey || target.permission !== 'ACCESS' ||
      body.installedAppId !== installedAppId || !validEpoch(body.launchAccessEpoch)) return unavailable();
    if (!options.initial && scope.launchAccessEpoch !== body.launchAccessEpoch) return deny('ACCESS_EPOCH_STALE');
    return {installedAppId,launchAccessEpoch:body.launchAccessEpoch};
  } catch (cause) {
    if (cause instanceof ApplicationAccessError) throw cause;
    return unavailable();
  } finally { clearTimeout(timeout); }
}