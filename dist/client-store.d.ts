import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
export declare class InMemoryClientStore implements OAuthRegisteredClientsStore {
    private clients;
    getClient(clientId: string): OAuthClientInformationFull | undefined;
    registerClient(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): OAuthClientInformationFull;
}
//# sourceMappingURL=client-store.d.ts.map