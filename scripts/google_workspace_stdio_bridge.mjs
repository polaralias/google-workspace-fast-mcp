import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const legacyRoot = process.env.GOOGLE_WORKSPACE_LEGACY_REPO
  ? path.resolve(process.env.GOOGLE_WORKSPACE_LEGACY_REPO)
  : path.resolve(__dirname, "..", "..", "google-workspace-mcp");

if (!process.env.DOTENV_CONFIG_QUIET) {
  process.env.DOTENV_CONFIG_QUIET = "true";
}

const mcpModulePath = path.join(legacyRoot, "dist", "mcp.js");
const { GoogleMcpServer } = await import(pathToFileURL(mcpModulePath).href);

const server = new GoogleMcpServer();
await server.startStdio();
