import { randomBytes } from "crypto";
import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { FileStore } from "./store.js";

export class ClientStore implements OAuthRegisteredClientsStore {
  private memory = new Map<string, OAuthClientInformationFull>();

  constructor(private fileStore?: FileStore) {}

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    if (this.fileStore) {
      return this.fileStore.getClient(clientId);
    }
    return this.memory.get(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): OAuthClientInformationFull {
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: `mcp-${randomBytes(16).toString("hex")}`,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret: randomBytes(32).toString("hex"),
      client_secret_expires_at: 0,
    };
    if (this.fileStore) {
      this.fileStore.setClient(full.client_id, full);
    } else {
      this.memory.set(full.client_id, full);
    }
    return full;
  }
}
