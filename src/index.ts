import { OpenAuthOptions, OpenAuthResult } from "./types.js";
import { OpenAuthProvider } from "./provider.js";
import { createRouter, createBearerMiddleware } from "./router.js";

export type { OpenAuthOptions, OpenAuthResult, FieldDefinition } from "./types.js";

export function createOpenAuth(options: OpenAuthOptions): OpenAuthResult {
  const provider = new OpenAuthProvider(options.serviceName, options.fields, options.storagePath);

  return {
    router: () => createRouter(provider, options),
    middleware: () => createBearerMiddleware(provider, options.serverUrl),
    getCredentials: (accessToken: string) => provider.getCredentials(accessToken),
  };
}
