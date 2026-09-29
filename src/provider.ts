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
import {
  InvalidGrantError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { ClientStore } from "./client-store.js";
import { Credentials, Store } from "./store.js";
import { FieldDefinition } from "./types.js";
import { renderForm } from "./form.js";

interface PendingAuth {
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
}

interface AuthorizationCode {
  codeChallenge: string;
  redirectUri: string;
  clientId: string;
  credentials: Credentials;
}

const TOKEN_TTL = 3600 * 24 * 30; // 30 days
// Sliding: every refresh issues a new refresh token with a fresh lifetime
const REFRESH_TOKEN_TTL = 3600 * 24 * 90; // 90 days
const PENDING_TTL_MS = 10 * 60 * 1000;

export class OpenAuthProvider implements OAuthServerProvider {
  readonly clientsStore: ClientStore;
  private store: Store;

  // Short-lived, so memory is enough
  private pending = new Map<string, PendingAuth>();
  private codes = new Map<string, AuthorizationCode>();

  constructor(
    private serviceName: string,
    private fields: FieldDefinition[],
    storagePath?: string,
  ) {
    this.store = new Store(storagePath, REFRESH_TOKEN_TTL);
    this.clientsStore = new ClientStore(this.store);
  }

  // --- OAuth flow ---

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    const pendingId = randomBytes(16).toString("hex");
    this.pending.set(pendingId, { client, params });
    setTimeout(() => this.pending.delete(pendingId), PENDING_TTL_MS).unref();

    res.setHeader("Content-Type", "text/html");
    res.send(renderForm(this.serviceName, this.fields, pendingId));
  }

  completePendingAuth(
    pendingId: string,
    credentials: Credentials,
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
    setTimeout(() => this.codes.delete(code), PENDING_TTL_MS).unref();

    const redirectUrl = new URL(pending.params.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (pending.params.state) {
      redirectUrl.searchParams.set("state", pending.params.state);
    }
    return { redirectUrl: redirectUrl.toString() };
  }

  private getCode(client: OAuthClientInformationFull, code: string): AuthorizationCode {
    const entry = this.codes.get(code);
    if (!entry || entry.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code");
    }
    return entry;
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    return this.getCode(client, authorizationCode).codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    const entry = this.getCode(client, authorizationCode);
    if (redirectUri !== undefined && redirectUri !== entry.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }
    this.codes.delete(authorizationCode);
    return this.issueTokens(client.client_id, entry.credentials);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
  ): Promise<OAuthTokens> {
    const entry = this.store.getRefreshToken(refreshToken);
    // Refresh tokens migrated from the v1 store have no client and are accepted from any
    if (!entry || (entry.clientId && entry.clientId !== client.client_id)) {
      throw new InvalidGrantError("Invalid refresh token");
    }
    this.store.deleteRefreshToken(refreshToken);
    return this.issueTokens(client.client_id, entry.credentials);
  }

  private issueTokens(clientId: string, credentials: Credentials): OAuthTokens {
    const accessToken = randomBytes(32).toString("hex");
    const refreshToken = randomBytes(32).toString("hex");
    const now = Math.floor(Date.now() / 1000);

    this.store.setAccessToken(accessToken, {
      clientId,
      scopes: [],
      expiresAt: now + TOKEN_TTL,
      credentials,
    });
    this.store.setRefreshToken(refreshToken, {
      clientId,
      scopes: [],
      expiresAt: now + REFRESH_TOKEN_TTL,
      credentials,
    });

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL,
      refresh_token: refreshToken,
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const entry = this.store.getAccessToken(token);
    if (!entry?.clientId) throw new InvalidTokenError("Invalid or expired access token");
    return {
      token,
      clientId: entry.clientId,
      scopes: entry.scopes,
      expiresAt: entry.expiresAt,
    };
  }

  // The token type hint is optional, so try both kinds
  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    this.store.deleteAccessToken(request.token);
    this.store.deleteRefreshToken(request.token);
  }

  getCredentials(accessToken: string): Credentials | undefined {
    return this.store.getAccessToken(accessToken)?.credentials;
  }
}
