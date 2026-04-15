import { randomBytes } from "crypto";
import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export class InMemoryClientStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
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
    this.clients.set(full.client_id, full);
    return full;
  }
}
