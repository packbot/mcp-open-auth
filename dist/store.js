import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, } from "crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { dirname } from "path";
function lookupKey(token) {
    return createHash("sha256").update(token).digest("hex");
}
function sealingKey(token) {
    return Buffer.from(hkdfSync("sha256", token, "mcp-open-auth", "credentials", 32));
}
function seal(token, credentials) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", sealingKey(token), iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(credentials), "utf8"), cipher.final()]);
    return {
        iv: iv.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
        data: data.toString("base64"),
    };
}
function unseal(token, sealed) {
    try {
        const decipher = createDecipheriv("aes-256-gcm", sealingKey(token), Buffer.from(sealed.iv, "base64"));
        decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
        const plain = Buffer.concat([
            decipher.update(Buffer.from(sealed.data, "base64")),
            decipher.final(),
        ]);
        return JSON.parse(plain.toString("utf8"));
    }
    catch {
        return undefined;
    }
}
const now = () => Math.floor(Date.now() / 1000);
/** Holds clients and tokens; persists them to `filePath` when given, otherwise memory only. */
export class Store {
    filePath;
    legacyRefreshTtl;
    data;
    constructor(filePath, legacyRefreshTtl) {
        this.filePath = filePath;
        this.legacyRefreshTtl = legacyRefreshTtl;
        if (filePath)
            mkdirSync(dirname(filePath), { recursive: true });
        this.data = this.load();
        this.save();
    }
    load() {
        const empty = { version: 2, clients: {}, accessTokens: {}, refreshTokens: {} };
        if (!this.filePath || !existsSync(this.filePath))
            return empty;
        const parsed = JSON.parse(readFileSync(this.filePath, "utf-8"));
        const data = parsed.version === 2 ? { ...empty, ...parsed } : this.migrate(parsed, empty);
        for (const tokens of [data.accessTokens, data.refreshTokens]) {
            for (const [key, entry] of Object.entries(tokens)) {
                if (entry.expiresAt < now())
                    delete tokens[key];
            }
        }
        return data;
    }
    migrate(legacy, data) {
        data.clients = legacy.clients ?? {};
        for (const [token, info] of Object.entries(legacy.tokens ?? {})) {
            const credentials = legacy.tokenCredentials?.[token];
            if (!credentials || !info.expiresAt)
                continue;
            data.accessTokens[lookupKey(token)] = {
                clientId: info.clientId,
                scopes: info.scopes ?? [],
                expiresAt: info.expiresAt,
                credentials: seal(token, credentials),
            };
        }
        for (const [token, credentials] of Object.entries(legacy.refreshTokenCredentials ?? {})) {
            data.refreshTokens[lookupKey(token)] = {
                scopes: [],
                expiresAt: now() + this.legacyRefreshTtl,
                credentials: seal(token, credentials),
            };
        }
        return data;
    }
    // Write to a temp file and rename, so a crash never leaves a half-written store behind
    save() {
        if (!this.filePath)
            return;
        const tmp = `${this.filePath}.tmp`;
        writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
        renameSync(tmp, this.filePath);
        chmodSync(this.filePath, 0o600);
    }
    // Clients
    getClient(clientId) {
        return this.data.clients[clientId];
    }
    setClient(client) {
        this.data.clients[client.client_id] = client;
        this.save();
    }
    // Tokens
    getAccessToken(token) {
        return this.get(this.data.accessTokens, token);
    }
    setAccessToken(token, entry) {
        this.set(this.data.accessTokens, token, entry);
    }
    deleteAccessToken(token) {
        this.delete(this.data.accessTokens, token);
    }
    getRefreshToken(token) {
        return this.get(this.data.refreshTokens, token);
    }
    setRefreshToken(token, entry) {
        this.set(this.data.refreshTokens, token, entry);
    }
    deleteRefreshToken(token) {
        this.delete(this.data.refreshTokens, token);
    }
    get(tokens, token) {
        const key = lookupKey(token);
        const stored = tokens[key];
        if (!stored)
            return undefined;
        if (stored.expiresAt < now()) {
            delete tokens[key];
            this.save();
            return undefined;
        }
        const credentials = unseal(token, stored.credentials);
        if (!credentials)
            return undefined;
        return { ...stored, credentials };
    }
    set(tokens, token, entry) {
        tokens[lookupKey(token)] = { ...entry, credentials: seal(token, entry.credentials) };
        this.save();
    }
    delete(tokens, token) {
        const key = lookupKey(token);
        if (!(key in tokens))
            return;
        delete tokens[key];
        this.save();
    }
}
//# sourceMappingURL=store.js.map