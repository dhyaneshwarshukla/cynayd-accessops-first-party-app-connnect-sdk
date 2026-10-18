import {checkApplicationAccess,ApplicationAccessError} from '../src/application-authorization';
const scope={personId:'person',organizationId:'org',installedAppId:'installation',launchAccessEpoch:4};
const allow=()=>({decision:'ALLOW',availability:'AVAILABLE',launchSource:'ACCESSOPS',effectiveAccess:true,launchReady:true,installedAppId:'installation',launchAccessEpoch:4,
 authorityTarget:{personId:'person',organizationId:'org',installationId:'installation',applicationId:'cynayd-vault',permission:'ACCESS'}});
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
 const f=jest.fn().mockResolvedValueOnce({ok:true,json:async()=>allow()}).mockResolvedValueOnce({ok:true,json:async()=>({decision:'DENY'})});
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