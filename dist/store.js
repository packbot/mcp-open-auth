import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";
const EMPTY_STORE = {
    clients: {},
    tokens: {},
    tokenCredentials: {},
    refreshTokenCredentials: {},
};
export class FileStore {
    filePath;
    data;
    constructor(filePath) {
        this.filePath = filePath;
        mkdirSync(dirname(filePath), { recursive: true });
        this.data = this.load();
    }
    load() {
        try {
            const raw = readFileSync(this.filePath, "utf-8");
            const parsed = JSON.parse(raw);
            return { ...EMPTY_STORE, ...parsed };
        }
        catch {
            return { ...EMPTY_STORE };
        }
    }
    save() {
        writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
    }
    // Clients
    getClient(clientId) {
        return this.data.clients[clientId];
    }
    setClient(clientId, client) {
        this.data.clients[clientId] = client;
        this.save();
    }
    // Tokens
    getToken(token) {
        return this.data.tokens[token];
    }
    setToken(token, info) {
        this.data.tokens[token] = info;
        this.save();
    }
    deleteToken(token) {
        delete this.data.tokens[token];
        this.save();
    }
    // Token credentials
    getTokenCredentials(token) {
        return this.data.tokenCredentials[token];
    }
    setTokenCredentials(token, creds) {
        this.data.tokenCredentials[token] = creds;
        this.save();
    }
    deleteTokenCredentials(token) {
        delete this.data.tokenCredentials[token];
        this.save();
    }
    // Refresh token credentials
    getRefreshTokenCredentials(token) {
        return this.data.refreshTokenCredentials[token];
    }
    setRefreshTokenCredentials(token, creds) {
        this.data.refreshTokenCredentials[token] = creds;
        this.save();
    }
    deleteRefreshTokenCredentials(token) {
        delete this.data.refreshTokenCredentials[token];
        this.save();
    }
}
//# sourceMappingURL=store.js.map