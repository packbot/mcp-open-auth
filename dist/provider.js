import { randomBytes } from "crypto";
import { ClientStore } from "./client-store.js";
import { FileStore } from "./store.js";
import { renderForm } from "./form.js";
const TOKEN_TTL = 3600 * 24 * 30; // 30 days
export class OpenAuthProvider {
    serviceName;
    fields;
    clientsStore;
    fileStore;
    // Ephemeral — no persistence needed
    pending = new Map();
    codes = new Map();
    // Persisted when fileStore is set, otherwise in-memory
    memTokenCredentials = new Map();
    memRefreshTokenCredentials = new Map();
    memTokens = new Map();
    constructor(serviceName, fields, storagePath) {
        this.serviceName = serviceName;
        this.fields = fields;
        if (storagePath) {
            this.fileStore = new FileStore(storagePath);
        }
        this.clientsStore = new ClientStore(this.fileStore);
    }
    // --- Storage helpers ---
    getToken(token) {
        return this.fileStore ? this.fileStore.getToken(token) : this.memTokens.get(token);
    }
    setToken(token, info) {
        if (this.fileStore) {
            this.fileStore.setToken(token, info);
        }
        else {
            this.memTokens.set(token, info);
        }
    }
    deleteToken(token) {
        if (this.fileStore) {
            this.fileStore.deleteToken(token);
        }
        else {
            this.memTokens.delete(token);
        }
    }
    getTokenCreds(token) {
        return this.fileStore
            ? this.fileStore.getTokenCredentials(token)
            : this.memTokenCredentials.get(token);
    }
    setTokenCreds(token, creds) {
        if (this.fileStore) {
            this.fileStore.setTokenCredentials(token, creds);
        }
        else {
            this.memTokenCredentials.set(token, creds);
        }
    }
    deleteTokenCreds(token) {
        if (this.fileStore) {
            this.fileStore.deleteTokenCredentials(token);
        }
        else {
            this.memTokenCredentials.delete(token);
        }
    }
    getRefreshCreds(token) {
        return this.fileStore
            ? this.fileStore.getRefreshTokenCredentials(token)
            : this.memRefreshTokenCredentials.get(token);
    }
    setRefreshCreds(token, creds) {
        if (this.fileStore) {
            this.fileStore.setRefreshTokenCredentials(token, creds);
        }
        else {
            this.memRefreshTokenCredentials.set(token, creds);
        }
    }
    deleteRefreshCreds(token) {
        if (this.fileStore) {
            this.fileStore.deleteRefreshTokenCredentials(token);
        }
        else {
            this.memRefreshTokenCredentials.delete(token);
        }
    }
    // --- OAuth flow ---
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
    async exchangeRefreshToken(client, oldRefreshToken) {
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
    async verifyAccessToken(token) {
        const info = this.getToken(token);
        if (!info)
            throw new Error("Invalid access token");
        if (info.expiresAt && info.expiresAt < Math.floor(Date.now() / 1000)) {
            this.deleteToken(token);
            this.deleteTokenCreds(token);
            throw new Error("Access token expired");
        }
        return info;
    }
    async revokeToken(_client, request) {
        this.deleteToken(request.token);
        this.deleteTokenCreds(request.token);
    }
    getCredentials(accessToken) {
        return this.getTokenCreds(accessToken);
    }
}
//# sourceMappingURL=provider.js.map