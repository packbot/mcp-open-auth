import { randomBytes } from "crypto";
export class ClientStore {
    fileStore;
    memory = new Map();
    constructor(fileStore) {
        this.fileStore = fileStore;
    }
    getClient(clientId) {
        if (this.fileStore) {
            return this.fileStore.getClient(clientId);
        }
        return this.memory.get(clientId);
    }
    registerClient(client) {
        const full = {
            ...client,
            client_id: `mcp-${randomBytes(16).toString("hex")}`,
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_secret: randomBytes(32).toString("hex"),
            client_secret_expires_at: 0,
        };
        if (this.fileStore) {
            this.fileStore.setClient(full.client_id, full);
        }
        else {
            this.memory.set(full.client_id, full);
        }
        return full;
    }
}
//# sourceMappingURL=client-store.js.map