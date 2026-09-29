import { Response } from "express";
import { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ClientStore } from "./client-store.js";
import { Credentials } from "./store.js";
import { FieldDefinition } from "./types.js";
export declare class OpenAuthProvider implements OAuthServerProvider {
    private serviceName;
    private fields;
    readonly clientsStore: ClientStore;
    private store;
    private pending;
    private codes;
    constructor(serviceName: string, fields: FieldDefinition[], storagePath?: string);
    authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void>;
    completePendingAuth(pendingId: string, credentials: Credentials): {
        redirectUrl: string;
    } | null;
    private getCode;
    challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string>;
    exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string, _codeVerifier?: string, redirectUri?: string): Promise<OAuthTokens>;
    exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens>;
    private issueTokens;
    verifyAccessToken(token: string): Promise<AuthInfo>;
    revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void>;
    getCredentials(accessToken: string): Credentials | undefined;
}
//# sourceMappingURL=provider.d.ts.map