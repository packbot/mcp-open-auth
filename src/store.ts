import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
} from "crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { dirname } from "path";
import { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export type Credentials = Record<string, string>;

export interface TokenInfo {
  /** Client the token was issued to. Missing only on refresh tokens migrated from the v1 format. */
  clientId?: string;
  scopes: string[];
  /** Epoch seconds */
  expiresAt: number;
}

export interface TokenEntry extends TokenInfo {
  credentials: Credentials;
}

// AES-256-GCM ciphertext of the credentials, keyed by the token they belong to
interface Sealed {
  iv: string;
  tag: string;
  data: string;
}

interface StoredToken extends TokenInfo {
  credentials: Sealed;
}

// Tokens are stored under their SHA-256 hash and the credentials are encrypted with a key derived
// from the token itself, so the file alone reveals neither the tokens nor the credentials.
interface StoreData {
  version: 2;
  clients: Record<string, OAuthClientInformationFull>;
  accessTokens: Record<string, StoredToken>;
  refreshTokens: Record<string, StoredToken>;
}

// Layout written before v2: raw tokens as keys, plaintext credentials
interface LegacyStoreData {
  clients?: Record<string, OAuthClientInformationFull>;
  tokens?: Record<string, { clientId: string; scopes: string[]; expiresAt?: number }>;
  tokenCredentials?: Record<string, Credentials>;
  refreshTokenCredentials?: Record<string, Credentials>;
}

function lookupKey(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function sealingKey(token: string): Buffer {
  return Buffer.from(hkdfSync("sha256", token, "mcp-open-auth", "credentials", 32));
}

function seal(token: string, credentials: Credentials): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", sealingKey(token), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(credentials), "utf8"), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function unseal(token: string, sealed: Sealed): Credentials | undefined {
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      sealingKey(token),
      Buffer.from(sealed.iv, "base64"),
    );
    decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(sealed.data, "base64")),
      decipher.final(),
    ]);
    return JSON.parse(plain.toString("utf8"));
  } catch {
    return undefined;
  }
}

const now = () => Math.floor(Date.now() / 1000);

/** Holds clients and tokens; persists them to `filePath` when given, otherwise memory only. */
export class Store {
  private data: StoreData;

  constructor(
    private filePath: string | undefined,
    private legacyRefreshTtl: number,
  ) {
    if (filePath) mkdirSync(dirname(filePath), { recursive: true });
    this.data = this.load();
    this.save();
  }

  private load(): StoreData {
    const empty: StoreData = { version: 2, clients: {}, accessTokens: {}, refreshTokens: {} };
    if (!this.filePath || !existsSync(this.filePath)) return empty;

    const parsed = JSON.parse(readFileSync(this.filePath, "utf-8"));
    const data: StoreData =
      parsed.version === 2 ? { ...empty, ...parsed } : this.migrate(parsed, empty);
    for (const tokens of [data.accessTokens, data.refreshTokens]) {
      for (const [key, entry] of Object.entries(tokens)) {
        if (entry.expiresAt < now()) delete tokens[key];
      }
    }
    return data;
  }

  private migrate(legacy: LegacyStoreData, data: StoreData): StoreData {
    data.clients = legacy.clients ?? {};
    for (const [token, info] of Object.entries(legacy.tokens ?? {})) {
      const credentials = legacy.tokenCredentials?.[token];
      if (!credentials || !info.expiresAt) continue;
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
  private save(): void {
    if (!this.filePath) return;
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    renameSync(tmp, this.filePath);
    chmodSync(this.filePath, 0o600);
  }

  // Clients

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.data.clients[clientId];
  }

  setClient(client: OAuthClientInformationFull): void {
    this.data.clients[client.client_id] = client;
    this.save();
  }

  // Tokens

  getAccessToken(token: string): TokenEntry | undefined {
    return this.get(this.data.accessTokens, token);
  }

  setAccessToken(token: string, entry: TokenEntry): void {
    this.set(this.data.accessTokens, token, entry);
  }

  deleteAccessToken(token: string): void {
    this.delete(this.data.accessTokens, token);
  }

  getRefreshToken(token: string): TokenEntry | undefined {
    return this.get(this.data.refreshTokens, token);
  }

  setRefreshToken(token: string, entry: TokenEntry): void {
    this.set(this.data.refreshTokens, token, entry);
  }

  deleteRefreshToken(token: string): void {
    this.delete(this.data.refreshTokens, token);
  }

  private get(tokens: Record<string, StoredToken>, token: string): TokenEntry | undefined {
    const key = lookupKey(token);
    const stored = tokens[key];
    if (!stored) return undefined;
    if (stored.expiresAt < now()) {
      delete tokens[key];
      this.save();
      return undefined;
    }
    const credentials = unseal(token, stored.credentials);
    if (!credentials) return undefined;
    return { ...stored, credentials };
  }

  private set(tokens: Record<string, StoredToken>, token: string, entry: TokenEntry): void {
    tokens[lookupKey(token)] = { ...entry, credentials: seal(token, entry.credentials) };
    this.save();
  }

  private delete(tokens: Record<string, StoredToken>, token: string): void {
    const key = lookupKey(token);
    if (!(key in tokens)) return;
    delete tokens[key];
    this.save();
  }
}
