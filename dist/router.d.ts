import { RequestHandler } from "express";
import { OpenAuthProvider } from "./provider.js";
import { OpenAuthOptions } from "./types.js";
export declare function createRouter(provider: OpenAuthProvider, options: OpenAuthOptions): RequestHandler;
export declare function createBearerMiddleware(provider: OpenAuthProvider, serverUrl: string): RequestHandler;
//# sourceMappingURL=router.d.ts.map