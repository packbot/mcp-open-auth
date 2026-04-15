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
import { InMemoryClientStore } from "./client-store.js";
import { FieldDefinition } from "./types.js";
import { renderForm } from "./form.js";

interface PendingAuth {
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
}

const TOKEN_TTL = 3600 * 24 * 30; // 30 days

export class OpenAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientStore();

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
  private tokenCredentials = new Map<string, Record<string, string>>();
  private tokens = new Map<string, AuthInfo>();

  constructor(
    private serviceName: string,
    private fields: FieldDefinition[],
  ) {}

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

    this.tokenCredentials.set(accessToken, entry.credentials);
    this.tokens.set(accessToken, {
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

  async exchangeRefreshToken(client: OAuthClientInformationFull): Promise<OAuthTokens> {
    const accessToken = randomBytes(32).toString("hex");
    const refreshToken = randomBytes(32).toString("hex");

    this.tokens.set(accessToken, {
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
    const info = this.tokens.get(token);
    if (!info) throw new Error("Invalid access token");
    if (info.expiresAt && info.expiresAt < Math.floor(Date.now() / 1000)) {
      this.tokens.delete(token);
      this.tokenCredentials.delete(token);
      throw new Error("Access token expired");
    }
    return info;
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    this.tokens.delete(request.token);
    this.tokenCredentials.delete(request.token);
  }

  getCredentials(accessToken: string): Record<string, string> | undefined {
    return this.tokenCredentials.get(accessToken);
  }
}
