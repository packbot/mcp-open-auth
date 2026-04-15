import { OpenAuthProvider } from "./provider.js";
import { createRouter, createBearerMiddleware } from "./router.js";
export function createOpenAuth(options) {
    const provider = new OpenAuthProvider(options.serviceName, options.fields, options.storagePath);
    return {
        router: () => createRouter(provider, options),
        middleware: () => createBearerMiddleware(provider, options.serverUrl),
        getCredentials: (accessToken) => provider.getCredentials(accessToken),
    };
}
//# sourceMappingURL=index.js.map