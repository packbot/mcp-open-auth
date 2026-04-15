import { randomBytes } from "crypto";
import { Response } from "express";
import {
  OAuthServerProvider,
  AuthorizationParams,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ClientStore } from "./client-store.js";
import { FileStore } from "./store.js";
import { FieldDefinition } from "./types.js";
import { renderForm } from "./form.js";

interface PendingAuth {
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
}

const TOKEN_TTL = 3600 * 24 * 30; // 30 days

export class OpenAuthProvider implements OAuthServerProvider {
  readonly clientsStore: ClientStore;
  private fileStore?: FileStore;

  // Ephemeral — no persistence needed
  private pending = new Map<string, PendingAuth>();
  private codes = new Map<
    string,
    {
      codeChallenge: string;
      redirectUri: string;
      clientId: string;
      credentials: Record<string, string>;
    }
  >();

  // Persisted when fileStore is set, otherwise in-memory
  private memTokenCredentials = new Map<string, Record<string, string>>();
  private memRefreshTokenCredentials = new Map<string, Record<string, string>>();
  private memTokens = new Map<string, AuthInfo>();

  constructor(
    private serviceName: string,
    private fields: FieldDefinition[],
    storagePath?: string,
  ) {
    if (storagePath) {
      this.fileStore = new FileStore(storagePath);
    }
    this.clientsStore = new ClientStore(this.fileStore);
  }

  // --- Storage helpers ---

  private getToken(token: string): AuthInfo | undefined {
    return this.fileStore ? this.fileStore.getToken(token) : this.memTokens.get(token);
  }

  private setToken(token: string, info: AuthInfo): void {
    if (this.fileStore) {
      this.fileStore.setToken(token, info);
    } else {
      this.memTokens.set(token, info);
    }
  }

  private deleteToken(token: string): void {
    if (this.fileStore) {
      this.fileStore.deleteToken(token);
    } else {
      this.memTokens.delete(token);
    }
  }

  private getTokenCreds(token: string): Record<string, string> | undefined {
    return this.fileStore
      ? this.fileStore.getTokenCredentials(token)
      : this.memTokenCredentials.get(token);
  }

  private setTokenCreds(token: string, creds: Record<string, string>): void {
    if (this.fileStore) {
      this.fileStore.setTokenCredentials(token, creds);
    } else {
      this.memTokenCredentials.set(token, creds);
    }
  }

  private deleteTokenCreds(token: string): void {
    if (this.fileStore) {
      this.fileStore.deleteTokenCredentials(token);
    } else {
      this.memTokenCredentials.delete(token);
    }
  }

  private getRefreshCreds(token: string): Record<string, string> | undefined {
    return this.fileStore
      ? this.fileStore.getRefreshTokenCredentials(token)
      : this.memRefreshTokenCredentials.get(token);
  }

  private setRefreshCreds(token: string, creds: Record<string, string>): void {
    if (this.fileStore) {
      this.fileStore.setRefreshTokenCredentials(token, creds);
    } else {
      this.memRefreshTokenCredentials.set(token, creds);
    }
  }

  private deleteRefreshCreds(token: string): void {
    if (this.fileStore) {
      this.fileStore.deleteRefreshTokenCredentials(token);
    } else {
      this.memRefreshTokenCredentials.delete(token);
    }
  }

  // --- OAuth flow ---

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    const pendingId = randomBytes(16).toString("hex");
    this.pending.set(pendingId, { client, params });
    setTimeout(() => this.pending.delete(pendingId), 10 * 60 * 1000);

    res.setHeader("Content-Type", "text/html");
    res.send(renderForm(this.serviceName, this.fields, pendingId));
  }

  completePendingAuth(
    pendingId: string,
    credentials: Record<string, string>,
  ): { redirectUrl: string } | null {
    const pending = this.pending.get(pendingId);
    if (!pending) return null;
    this.pending.delete(pendingId);

    const code = randomBytes(32).toString("hex");
    this.codes.set(code, {
      codeChallenge: pending.params.codeChallenge,
      redirectUri: pending.params.redirectUri,
      clientId: pending.client.client_id,
      credentials,
    });

    const redirectUrl = new URL(pending.params.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (pending.params.state) {
      redirectUrl.searchParams.set("state", pending.params.state);
    }
    return { redirectUrl: redirectUrl.toString() };
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const entry = this.codes.get(authorizationCode);
    if (!entry) throw new Error("Invalid authorization code");
    return entry.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<OAuthTokens> {
    const entry = this.codes.get(authorizationCode);
    if (!entry) throw new Error("Invalid authorization code");
    this.codes.delete(authorizationCode);

    const accessToken = randomBytes(32).toString("hex");
    const refreshToken = randomBytes(32).toString("hex");

    this.setTokenCreds(accessToken, entry.credentials);
    this.setRefreshCreds(refreshToken, entry.credentials);
    this.setToken(accessToken, {
      token: accessToken,
      clientId: client.client_id,
      scopes: [],
      expiresAt: Math.floor(Date.now() / 1000) + TOKEN_TTL,
    });

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL,
      refresh_token: refreshToken,
    };
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    oldRefreshToken: string,
  ): Promise<OAuthTokens> {
    const credentials = this.getRefreshCreds(oldRefreshToken);
    this.deleteRefreshCreds(oldRefreshToken);

    const accessToken = randomBytes(32).toString("hex");
    const refreshToken = randomBytes(32).toString("hex");

    if (credentials) {
      this.setTokenCreds(accessToken, credentials);
      this.setRefreshCreds(refreshToken, credentials);
    }

    this.setToken(accessToken, {
      token: accessToken,
      clientId: client.client_id,
      scopes: [],
      expiresAt: Math.floor(Date.now() / 1000) + TOKEN_TTL,
    });

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL,
      refresh_token: refreshToken,
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const info = this.getToken(token);
    if (!info) throw new Error("Invalid access token");
    if (info.expiresAt && info.expiresAt < Math.floor(Date.now() / 1000)) {
      this.deleteToken(token);
      this.deleteTokenCreds(token);
      throw new Error("Access token expired");
    }
    return info;
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    this.deleteToken(request.token);
    this.deleteTokenCreds(request.token);
  }

  getCredentials(accessToken: string): Record<string, string> | undefined {
    return this.getTokenCreds(accessToken);
  }
}
