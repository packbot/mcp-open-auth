import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { FileStore } from "./store.js";
export declare class ClientStore implements OAuthRegisteredClientsStore {
    private fileStore?;
    private memory;
    constructor(fileStore?: FileStore | undefined);
    getClient(clientId: string): OAuthClientInformationFull | undefined;
    registerClient(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): OAuthClientInformationFull;
}
//# sourceMappingURL=client-store.d.ts.map