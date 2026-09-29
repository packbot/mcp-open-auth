import { randomBytes } from "crypto";
export class ClientStore {
    store;
    constructor(store) {
        this.store = store;
    }
    getClient(clientId) {
        return this.store.getClient(clientId);
    }
    registerClient(client) {
        const full = {
            ...client,
            client_id: `mcp-${randomBytes(16).toString("hex")}`,
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_secret: randomBytes(32).toString("hex"),
            client_secret_expires_at: 0,
        };
        this.store.setClient(full);
        return full;
    }
}
//# sourceMappingURL=client-store.js.map