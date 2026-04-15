import { Response } from "express";
import { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ClientStore } from "./client-store.js";
import { FieldDefinition } from "./types.js";
export declare class OpenAuthProvider implements OAuthServerProvider {
    private serviceName;
    private fields;
    readonly clientsStore: ClientStore;
    private fileStore?;
    private pending;
    private codes;
    private memTokenCredentials;
    private memRefreshTokenCredentials;
    private memTokens;
    constructor(serviceName: string, fields: FieldDefinition[], storagePath?: string);
    private getToken;
    private setToken;
    private deleteToken;
    private getTokenCreds;
    private setTokenCreds;
    private deleteTokenCreds;
    private getRefreshCreds;
    private setRefreshCreds;
    private deleteRefreshCreds;
    authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void>;
    completePendingAuth(pendingId: string, credentials: Record<string, string>): {
        redirectUrl: string;
    } | null;
    challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string>;
    exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<OAuthTokens>;
    exchangeRefreshToken(client: OAuthClientInformationFull, oldRefreshToken: string): Promise<OAuthTokens>;
    verifyAccessToken(token: string): Promise<AuthInfo>;
    revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void>;
    getCredentials(accessToken: string): Record<string, string> | undefined;
}
//# sourceMappingURL=provider.d.ts.map