import { randomBytes } from "crypto";
export class InMemoryClientStore {
    clients = new Map();
    getClient(clientId) {
        return this.clients.get(clientId);
    }
    registerClient(client) {
        const full = {
            ...client,
            client_id: `mcp-${randomBytes(16).toString("hex")}`,
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_secret: randomBytes(32).toString("hex"),
            client_secret_expires_at: 0,
        };
        this.clients.set(full.client_id, full);
        return full;
    }
}
//# sourceMappingURL=client-store.js.map