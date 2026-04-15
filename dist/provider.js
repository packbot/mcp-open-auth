import { randomBytes } from "crypto";
import { InMemoryClientStore } from "./client-store.js";
import { renderForm } from "./form.js";
const TOKEN_TTL = 3600 * 24 * 30; // 30 days
export class OpenAuthProvider {
    serviceName;
    fields;
    clientsStore = new InMemoryClientStore();
    pending = new Map();
    codes = new Map();
    tokenCredentials = new Map();
    tokens = new Map();
    constructor(serviceName, fields) {
        this.serviceName = serviceName;
        this.fields = fields;
    }
    async authorize(client, params, res) {
        const pendingId = randomBytes(16).toString("hex");
        this.pending.set(pendingId, { client, params });
        setTimeout(() => this.pending.delete(pendingId), 10 * 60 * 1000);
        res.setHeader("Content-Type", "text/html");
        res.send(renderForm(this.serviceName, this.fields, pendingId));
    }
    completePendingAuth(pendingId, credentials) {
        const pending = this.pending.get(pendingId);
        if (!pending)
            return null;
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
    async challengeForAuthorizationCode(_client, authorizationCode) {
        const entry = this.codes.get(authorizationCode);
        if (!entry)
            throw new Error("Invalid authorization code");
        return entry.codeChallenge;
    }
    async exchangeAuthorizationCode(client, authorizationCode) {
        const entry = this.codes.get(authorizationCode);
        if (!entry)
            throw new Error("Invalid authorization code");
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
    async exchangeRefreshToken(client) {
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
    async verifyAccessToken(token) {
        const info = this.tokens.get(token);
        if (!info)
            throw new Error("Invalid access token");
        if (info.expiresAt && info.expiresAt < Math.floor(Date.now() / 1000)) {
            this.tokens.delete(token);
            this.tokenCredentials.delete(token);
            throw new Error("Access token expired");
        }
        return info;
    }
    async revokeToken(_client, request) {
        this.tokens.delete(request.token);
        this.tokenCredentials.delete(request.token);
    }
    getCredentials(accessToken) {
        return this.tokenCredentials.get(accessToken);
    }
}
//# sourceMappingURL=provider.js.map