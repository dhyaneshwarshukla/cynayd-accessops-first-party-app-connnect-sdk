/** Request-time whole-application authorization. No positive cache or role bypass.
 * The caller must verify its session credential before supplying this scope.
 * EdDSA product-evaluate contract; app resource ACLs remain separate.
 */
export type ApplicationSession = {
    personId: string;
    organizationId: string;
    installedAppId?: unknown;
    launchAccessEpoch?: unknown;
};
export declare class ApplicationAccessError extends Error {
    readonly code: string;
    readonly status: number;
    constructor(code: string, status: number);
}
export declare const applicationAuthorizationEnabled: () => boolean;
export declare function configuredInstallation(organizationId: string): string;
export declare function checkApplicationAccess(applicationKey: string, scope: ApplicationSession, options?: {
    initial?: boolean;
    fetchImpl?: typeof fetch;
}): Promise<{
    installedAppId: string;
    launchAccessEpoch: number;
}>;
//# sourceMappingURL=application-authorization.d.ts.map