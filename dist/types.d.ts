import { RequestHandler } from "express";
export interface FieldDefinition {
    /** Form field name (used as the HTML name attribute and credential key) */
    name: string;
    /** Human-readable label shown above the input */
    label: string;
    /** HTML input type: "text", "url", "password", "email", etc. */
    type: string;
    /** Placeholder text for the input */
    placeholder?: string;
    /** Whether the field is required (default: true) */
    required?: boolean;
}
export interface OpenAuthOptions {
    /** Public URL of the MCP server (e.g. "https://example.com") */
    serverUrl: string;
    /** Service name shown in the form heading (e.g. "YouTrack") */
    serviceName: string;
    /** Form field definitions */
    fields: FieldDefinition[];
    /**
     * Validate credentials entered by the user.
     * Throw an Error with a user-facing message if validation fails.
     */
    validate: (credentials: Record<string, string>) => Promise<void>;
}
export interface OpenAuthResult {
    /** Express middleware that mounts all OAuth routes + /authorize/complete */
    router: () => RequestHandler;
    /** Express middleware that requires a valid bearer token */
    middleware: () => RequestHandler;
    /** Look up the credentials entered during authorization for a given access token */
    getCredentials: (accessToken: string) => Record<string, string> | undefined;
}
//# sourceMappingURL=types.d.ts.map