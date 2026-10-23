import {generateKeyPairSync,verify} from 'crypto';
const signing=generateKeyPairSync('ed25519');
import {checkApplicationAccess,ApplicationAccessError} from '../src/application-authorization';
const scope={personId:'person',organizationId:'org',installedAppId:'installation',launchAccessEpoch:4};
const allow=()=>({decision:'ALLOW',availability:'AVAILABLE',launchSource:'ACCESSOPS',effectiveAccess:true,launchReady:true,installedAppId:'installation',launchAccessEpoch:4,
 authorityTarget:{personId:'person',organizationId:'org',installationId:'installation',applicationId:'cynayd-vault',permission:'ACCESS'}});
const fetcher=(body:unknown,status=200)=>jest.fn(async()=>({ok:status===200,json:async()=>body})) as unknown as typeof fetch;
beforeEach(()=>{process.env.ACCESSOPS_BASE_URL='https://authority.test';process.env.SERVICE_AUTH_PRIVATE_KEY_PEM=signing.privateKey.export({format:'pem',type:'pkcs8'}).toString();process.env.SERVICE_AUTH_KID='fixture-kid';process.env.ACCESSOPS_APPLICATION_INSTALLATIONS=JSON.stringify({org:'installation'});});
afterEach(()=>{delete process.env.ACCESSOPS_BASE_URL;delete process.env.SERVICE_AUTH_PRIVATE_KEY_PEM;delete process.env.SERVICE_AUTH_KID;delete process.env.ACCESSOPS_APPLICATION_INSTALLATIONS;delete process.env.GATEWAY_ACTOR_TRUST_SECRET;});
it('allows only exact current target and sends scoped service credentials, never a privileged role',async()=>{
 const f=fetcher(allow());process.env.GATEWAY_ACTOR_TRUST_SECRET='test-proof';
 await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).resolves.toEqual({installedAppId:'installation',launchAccessEpoch:4});
 const init=(f as jest.Mock).mock.calls[0][1];expect(init.headers['x-platform-role']).toBeUndefined();expect(init.headers['x-gateway-actor-proof']).toBeUndefined();expect(init.redirect).toBe('error');expect(init.headers.authorization).toMatch(/^Bearer /);
 const parts=init.headers.authorization.slice(7).split('.');expect(verify(null,Buffer.from(parts.slice(0,2).join('.')),signing.publicKey,Buffer.from(parts[2],'base64url'))).toBe(true);const claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());expect(claims.expiresAt-claims.issuedAt).toBe(30);expect(claims.organizationId).toBe('org');expect(claims.scopes).not.toContain('accessops.grants.write');
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
 delete process.env.ACCESSOPS_APPLICATION_INSTALLATIONS;
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
it('rejects claimed installations outside the configured allowlist',async()=>{
 delete process.env.ACCESSOPS_APPLICATION_INSTALLATIONS;
 const f=fetcher(allow());await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).rejects.toMatchObject({status:403});expect(f).not.toHaveBeenCalled();
});
it.each(['http://authority.test','https://authority.test/path','https://user:pass@authority.test','https://authority.test/?q=1'])('rejects noncanonical HTTPS origin %s',async base=>{
 process.env.ACCESSOPS_BASE_URL=base;const f=fetcher(allow());await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).rejects.toMatchObject({status:503});expect(f).not.toHaveBeenCalled();
});
it('does not use legacy HMAC or static service tokens',async()=>{
 delete process.env.SERVICE_AUTH_PRIVATE_KEY_PEM;process.env.SERVICE_AUTH_SECRET='fixture';process.env.ACCESSOPS_SERVICE_TOKEN='fixture';
 try{const f=fetcher(allow());await expect(checkApplicationAccess('cynayd-vault',scope,{fetchImpl:f})).rejects.toMatchObject({status:503});expect(f).not.toHaveBeenCalled();}finally{delete process.env.SERVICE_AUTH_SECRET;delete process.env.ACCESSOPS_SERVICE_TOKEN;}
});

it.each(['cynayd-drive','cynayd-mail','cynayd-docs'])('uses the exact signed service identity for %s',async applicationKey=>{
 const body=allow();body.authorityTarget.applicationId=applicationKey;
 const f=fetcher(body);await checkApplicationAccess(applicationKey,scope,{fetchImpl:f});
 const init=(f as jest.Mock).mock.calls[0][1];
 const claims=JSON.parse(Buffer.from(init.headers.authorization.slice(7).split('.')[1],'base64url').toString());
 expect(claims).toMatchObject({serviceId:applicationKey,applicationKey,audience:'accessops-service',installationId:'installation',organizationId:'org',personId:'person',scopes:['accessops.launch.evaluate']});
 expect(JSON.parse(init.body)).toEqual({organizationId:'org',userId:'person',installedAppId:'installation',applicationKey,permission:'ACCESS',purpose:'PRODUCT_API'});
});
