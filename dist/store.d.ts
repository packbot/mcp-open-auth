import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
export interface StoreData {
    clients: Record<string, OAuthClientInformationFull>;
    tokens: Record<string, AuthInfo>;
    tokenCredentials: Record<string, Record<string, string>>;
    refreshTokenCredentials: Record<string, Record<string, string>>;
}
export declare class FileStore {
    private filePath;
    private data;
    constructor(filePath: string);
    private load;
    private save;
    getClient(clientId: string): OAuthClientInformationFull | undefined;
    setClient(clientId: string, client: OAuthClientInformationFull): void;
    getToken(token: string): AuthInfo | undefined;
    setToken(token: string, info: AuthInfo): void;
    deleteToken(token: string): void;
    getTokenCredentials(token: string): Record<string, string> | undefined;
    setTokenCredentials(token: string, creds: Record<string, string>): void;
    deleteTokenCredentials(token: string): void;
    getRefreshTokenCredentials(token: string): Record<string, string> | undefined;
    setRefreshTokenCredentials(token: string, creds: Record<string, string>): void;
    deleteRefreshTokenCredentials(token: string): void;
}
//# sourceMappingURL=store.d.ts.map