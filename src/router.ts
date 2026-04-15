import { Router, Request, Response, RequestHandler } from "express";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { OpenAuthProvider } from "./provider.js";
import { OpenAuthOptions } from "./types.js";
import { renderForm } from "./form.js";

export function createRouter(
  provider: OpenAuthProvider,
  options: OpenAuthOptions,
): RequestHandler {
  const serverUrl = new URL(options.serverUrl);
  const resourceServerUrl = new URL("/mcp", options.serverUrl);

  const router = Router();

  // Mount the MCP SDK's standard OAuth routes
  router.use(
    mcpAuthRouter({
      provider,
      issuerUrl: serverUrl,
      resourceServerUrl,
      serviceDocumentationUrl: serverUrl,
    }),
  );

  // Handle credential form submission
  router.post("/authorize/complete", async (req: Request, res: Response) => {
    const pendingId = req.body?.pending_id;
    if (!pendingId) {
      res.status(400).send("Missing pending_id");
      return;
    }

    // Extract credential values from form body
    const credentials: Record<string, string> = {};
    for (const field of options.fields) {
      const value = req.body?.[field.name];
      if (field.required !== false && !value) {
        res.status(400).send(`Missing required field: ${field.label}`);
        return;
      }
      if (value) {
        credentials[field.name] = value;
      }
    }

    // Validate credentials using the consumer's validator
    try {
      await options.validate(credentials);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Validation failed. Please check your credentials.";

      res.setHeader("Content-Type", "text/html");
      res.send(
        renderForm(options.serviceName, options.fields, pendingId, message, credentials),
      );
      return;
    }

    // Credentials valid — complete the OAuth flow
    const result = provider.completePendingAuth(pendingId, credentials);
    if (!result) {
      res.status(400).send("Authorization request expired. Please try again.");
      return;
    }

    res.redirect(result.redirectUrl);
  });

  return router;
}

export function createBearerMiddleware(
  provider: OpenAuthProvider,
  serverUrl: string,
): RequestHandler {
  return requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: `${serverUrl}/.well-known/oauth-protected-resource/mcp`,
  });
}
