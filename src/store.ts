import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export interface StoreData {
  clients: Record<string, OAuthClientInformationFull>;
  tokens: Record<string, AuthInfo>;
  tokenCredentials: Record<string, Record<string, string>>;
  refreshTokenCredentials: Record<string, Record<string, string>>;
}

const EMPTY_STORE: StoreData = {
  clients: {},
  tokens: {},
  tokenCredentials: {},
  refreshTokenCredentials: {},
};

export class FileStore {
  private data: StoreData;

  constructor(private filePath: string) {
    mkdirSync(dirname(filePath), { recursive: true });
    this.data = this.load();
  }

  private load(): StoreData {
    try {
      const raw = readFileSync(this.filePath, "utf-8");
      const parsed = JSON.parse(raw);
      return { ...EMPTY_STORE, ...parsed };
    } catch {
      return { ...EMPTY_STORE };
    }
  }

  private save(): void {
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
  }

  // Clients
  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.data.clients[clientId];
  }

  setClient(clientId: string, client: OAuthClientInformationFull): void {
    this.data.clients[clientId] = client;
    this.save();
  }

  // Tokens
  getToken(token: string): AuthInfo | undefined {
    return this.data.tokens[token];
  }

  setToken(token: string, info: AuthInfo): void {
    this.data.tokens[token] = info;
    this.save();
  }

  deleteToken(token: string): void {
    delete this.data.tokens[token];
    this.save();
  }

  // Token credentials
  getTokenCredentials(token: string): Record<string, string> | undefined {
    return this.data.tokenCredentials[token];
  }

  setTokenCredentials(token: string, creds: Record<string, string>): void {
    this.data.tokenCredentials[token] = creds;
    this.save();
  }

  deleteTokenCredentials(token: string): void {
    delete this.data.tokenCredentials[token];
    this.save();
  }

  // Refresh token credentials
  getRefreshTokenCredentials(token: string): Record<string, string> | undefined {
    return this.data.refreshTokenCredentials[token];
  }

  setRefreshTokenCredentials(token: string, creds: Record<string, string>): void {
    this.data.refreshTokenCredentials[token] = creds;
    this.save();
  }

  deleteRefreshTokenCredentials(token: string): void {
    delete this.data.refreshTokenCredentials[token];
    this.save();
  }
}
