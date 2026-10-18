import {generateKeyPairSync,verify} from 'crypto';
import {checkApplicationAccess,ApplicationAccessError} from '../src/application-authorization';
const scope={personId:'person',organizationId:'org',installedAppId:'installation',launchAccessEpoch:4};
const allow=()=>({decision:'ALLOW',availability:'AVAILABLE',launchSource:'ACCESSOPS',effectiveAccess:true,launchReady:true,installedAppId:'installation',launchAccessEpoch:4,
 authorityTarget:{personId:'person',organizationId:'org',installationId:'installation',applicationId:'cynayd-vault',permission:'ACCESS'}});
const denial=()=>({...allow(),decision:'DENY',effectiveAccess:false,launchReady:false});
const fetcher=(body:unknown,status=200)=>jest.fn(async()=>({ok:status===200,json:async()=>body})) as unknown as typeof fetch;
beforeEach(()=>{process.env.ACCESSOPS_BASE_URL='http://authority.test';process.env.SERVICE_AUTH_SECRET='synthetic-test-secret';delete process.env.ACCESSOPS_APPLICATION_INSTALLATIONS;});
afterEach(()=>{delete process.env.ACCESSOPS_BASE_URL;delete process.env.SERVICE_AUTH_SECRET;delete process.env.ACCESSOPS_APPLICATION_INSTALLATIONS;delete process.env.GATEWAY_ACTOR_TRUST_SECRET;});
it('allows only exact current target and sends scoped service credentials, never a privileged role',async()=>{
 const f=fetcher(allow());process.env.GATEWAY_ACTOR_TRUST_SECRET='test-proof';
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).resolves.toEqual({installedAppId:'installation',launchAccessEpoch:4});
 const init=(f as jest.Mock).mock.calls[0][1];expect(init.headers['x-platform-role']).toBe('USER');expect(init.headers['x-gateway-actor-proof']).toMatch(/^[0-9a-f]{64}$/);expect(init.headers.authorization).toMatch(/^Bearer /);
 const claims=JSON.parse(Buffer.from(init.headers.authorization.slice(7).split('.')[0],'base64url').toString());expect(claims.organizationId).toBe('org');expect(claims.scopes).not.toContain('accessops.grants.write');
});
it.each(['organizationId','personId','installationId','applicationId','permission'])('rejects mismatched decision %s',async key=>{
 const b=allow();(b.authorityTarget as any)[key]='other';await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:fetcher(b)})).rejects.toMatchObject({status:503});
});
it.each([undefined,null,'4',0,-1,NaN,Infinity,4.5])('requires a positive integer session epoch: %s',async launchAccessEpoch=>{
 const f=fetcher(allow());await expect(checkApplicationAccess('cynayd-vault',{...scope,launchAccessEpoch},{fetchImpl:f})).rejects.toMatchObject({code:'APPLICATION_SESSION_REAUTH_REQUIRED'});expect(f).not.toHaveBeenCalled();
});
it.each([3,5])('rejects stale and future session epochs: %s',async launchAccessEpoch=>{
 await expect(checkApplicationAccess('cynayd-vault',{...scope,launchAccessEpoch},{fetchImpl:fetcher(allow())})).rejects.toMatchObject({code:'ACCESS_EPOCH_STALE'});
});
it('does not infer an installation from an app slug or tenant',async()=>{
 await expect(checkApplicationAccess('cynayd-vault',{...scope,installedAppId:undefined},{initial:true,fetchImpl:fetcher(allow())})).rejects.toMatchObject({code:'APPLICATION_INSTALLATION_REQUIRED'});
 process.env.ACCESSOPS_APPLICATION_INSTALLATIONS=JSON.stringify({org:'installation'});
 await expect(checkApplicationAccess('cynayd-vault',{...scope,installedAppId:undefined,launchAccessEpoch:undefined},{initial:true,fetchImpl:fetcher(allow())})).resolves.toMatchObject({installedAppId:'installation'});
 await expect(checkApplicationAccess('cynayd-vault',{...scope,installedAppId:'other'},{fetchImpl:fetcher(allow())})).rejects.toMatchObject({code:'APPLICATION_TARGET_MISMATCH'});
});
it('rechecks every request and rejects a revoke immediately even with the previous allowed token',async()=>{
 const f=jest.fn().mockResolvedValueOnce({ok:true,json:async()=>allow()}).mockResolvedValueOnce({ok:true,json:async()=>denial()});
 await checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f});
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).rejects.toMatchObject({status:403});expect(f).toHaveBeenCalledTimes(2);
});
it.each([{}, {decision:'ALLOW'}, {...allow(),launchAccessEpoch:'4'}, {...allow(),availability:'UNAVAILABLE'}])('fails closed on incomplete or unavailable proof',async body=>{
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:fetcher(body)})).rejects.toBeInstanceOf(ApplicationAccessError);
});
it('fails closed on transport failure without exposing provider errors',async()=>{
 const f=jest.fn().mockRejectedValue(new Error('private service error'));
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).rejects.toMatchObject({code:'ACCESS_DECISION_UNAVAILABLE',status:503});
});
it.each([null, [], {decision:'DENY'}, {...denial(),availability:undefined}, {...denial(),availability:'UNAVAILABLE'},
 {...denial(),availability:'OTHER'}, {...denial(),launchSource:undefined}, {...denial(),launchSource:'PRODUCT'},
 {...denial(),authorityTarget:undefined}, {...denial(),installedAppId:undefined}, {...denial(),installedAppId:'other'},
 {...denial(),effectiveAccess:true}, {...denial(),launchReady:true}])('treats malformed or contradictory DENY as unavailable, not authoritative denial: %p',async body=>{
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:fetcher(body)})).rejects.toMatchObject({status:503,code:'ACCESS_DECISION_UNAVAILABLE'});
});
it.each(['organizationId','personId','installationId','applicationId','permission'])('requires exact %s on DENY',async key=>{
 const b=denial();(b.authorityTarget as Record<string,unknown>)[key]='other';
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:fetcher(b)})).rejects.toMatchObject({status:503,code:'ACCESS_DECISION_UNAVAILABLE'});
});
it.each(['ALLOW','DENY'])('rejects resource targets for whole-app %s',async decision=>{
 const b={...(decision==='DENY'?denial():allow()),authorityTarget:{...allow().authorityTarget,resourceId:'resource'}};
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:fetcher(b)})).rejects.toMatchObject({status:503});
});
it('accepts an exact AVAILABLE authority denial without minting or requiring a new session epoch',async()=>{
 const b:Record<string,unknown>=denial();delete b.launchAccessEpoch;
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:fetcher(b)})).rejects.toMatchObject({status:403,code:'APPLICATION_ACCESS_DENIED'});
});
it('a malformed DENY cannot be mistaken for revocation after an earlier ALLOW',async()=>{
 const f=jest.fn().mockResolvedValueOnce({ok:true,json:async()=>allow()}).mockResolvedValueOnce({ok:true,json:async()=>({decision:'DENY'})});
 await checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f});
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).rejects.toMatchObject({status:503,code:'ACCESS_DECISION_UNAVAILABLE'});
});
it('mints a verifiable EdDSA token with the explicit KID and exact service/tenant/person/installation scope',async()=>{
 const pair=generateKeyPairSync('ed25519');
 process.env.SERVICE_AUTH_PRIVATE_KEY_PEM=pair.privateKey.export({format:'pem',type:'pkcs8'}).toString();
 process.env.SERVICE_AUTH_KID='synthetic-reviewed-key';
 try {
  const b=allow();b.authorityTarget.applicationId='cynayd-connect';const f=fetcher(b);
  await checkApplicationAccess('cynayd-connect',scope,{fetchImpl:f});
  const token=(f as jest.Mock).mock.calls[0][1].headers.authorization.slice(7);const parts=token.split('.');
  expect(parts).toHaveLength(3);
  expect(JSON.parse(Buffer.from(parts[0],'base64url').toString())).toEqual({alg:'EdDSA',typ:'JWT',kid:'synthetic-reviewed-key'});
  const claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());
  expect(claims).toMatchObject({serviceId:'cynayd-connect',applicationKey:'cynayd-connect',audience:'accessops-service',organizationId:'org',personId:'person',installationId:'installation',kid:'synthetic-reviewed-key',alg:'EdDSA',scopes:['accessops.launch.evaluate']});
  expect(claims.expiresAt-claims.issuedAt).toBe(30);
  expect(verify(null,Buffer.from(parts.slice(0,2).join('.')),pair.publicKey,Buffer.from(parts[2],'base64url'))).toBe(true);
 } finally {delete process.env.SERVICE_AUTH_PRIVATE_KEY_PEM;delete process.env.SERVICE_AUTH_KID;}
});
