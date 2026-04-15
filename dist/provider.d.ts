import { Response } from "express";
import { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InMemoryClientStore } from "./client-store.js";
import { FieldDefinition } from "./types.js";
export declare class OpenAuthProvider implements OAuthServerProvider {
    private serviceName;
    private fields;
    readonly clientsStore: InMemoryClientStore;
    private pending;
    private codes;
    private tokenCredentials;
    private tokens;
    constructor(serviceName: string, fields: FieldDefinition[]);
    authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void>;
    completePendingAuth(pendingId: string, credentials: Record<string, string>): {
        redirectUrl: string;
    } | null;
    challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string>;
    exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<OAuthTokens>;
    exchangeRefreshToken(client: OAuthClientInformationFull): Promise<OAuthTokens>;
    verifyAccessToken(token: string): Promise<AuthInfo>;
    revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void>;
    getCredentials(accessToken: string): Record<string, string> | undefined;
}
//# sourceMappingURL=provider.d.ts.map