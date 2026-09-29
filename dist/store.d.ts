import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
export type Credentials = Record<string, string>;
export interface TokenInfo {
    /** Client the token was issued to. Missing only on refresh tokens migrated from the v1 format. */
    clientId?: string;
    scopes: string[];
    /** Epoch seconds */
    expiresAt: number;
}
export interface TokenEntry extends TokenInfo {
    credentials: Credentials;
}
/** Holds clients and tokens; persists them to `filePath` when given, otherwise memory only. */
export declare class Store {
    private filePath;
    private legacyRefreshTtl;
    private data;
    constructor(filePath: string | undefined, legacyRefreshTtl: number);
    private load;
    private migrate;
    private save;
    getClient(clientId: string): OAuthClientInformationFull | undefined;
    setClient(client: OAuthClientInformationFull): void;
    getAccessToken(token: string): TokenEntry | undefined;
    setAccessToken(token: string, entry: TokenEntry): void;
    deleteAccessToken(token: string): void;
    getRefreshToken(token: string): TokenEntry | undefined;
    setRefreshToken(token: string, entry: TokenEntry): void;
    deleteRefreshToken(token: string): void;
    private get;
    private set;
    private delete;
}
//# sourceMappingURL=store.d.ts.map