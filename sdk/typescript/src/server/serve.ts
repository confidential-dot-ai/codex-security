import { startFindingsServer } from "./server.js";
import { SqliteFindingsStore } from "./sqlite-store.js";
import { OpenAiFindingEmbedder } from "./embeddings.js";
import { ScanRunner } from "./scans.js";
import type { ScanRouteOptions } from "./routes.js";

export async function serveFindings(
  environment: NodeJS.ProcessEnv = process.env,
  output: Pick<NodeJS.WriteStream, "write"> = process.stdout,
): Promise<void> {
  const host = environment["HOST"] ?? "127.0.0.1";
  const port = Number(environment["PORT"] ?? 3000);
  let scans: ScanRouteOptions | undefined;
  if (environment["CODEX_SECURITY_ENABLE_SCANS"] === "1") {
    const apiToken = environment["CODEX_SECURITY_API_TOKEN"];
    if (apiToken === undefined || apiToken === "") {
      throw new Error(
        "CODEX_SECURITY_ENABLE_SCANS=1 requires CODEX_SECURITY_API_TOKEN; scan submission runs code from submitted repositories and must not be exposed unauthenticated.",
      );
    }
    scans = { runner: new ScanRunner(environment), apiToken };
  }
  const server = await startFindingsServer({
    store: new SqliteFindingsStore(environment),
    embeddings: new OpenAiFindingEmbedder(
      environment["OPENAI_API_KEY"] ?? environment["CODEX_API_KEY"],
      fetch,
      environment["CODEX_SECURITY_EMBEDDINGS_URL"] || undefined,
    ),
    host,
    port,
    scans,
  });
  const address = server.address();
  if (address !== null && typeof address !== "string") {
    output.write(
      `Findings service listening on ${address.address}:${address.port}\n`,
    );
    if (scans !== undefined)
      output.write("Scan submission enabled at POST /v1/scans\n");
  }

  const shutdown = () => {
    server.close((error) => {
      if (error !== undefined) {
        console.error(error);
        process.exitCode = 1;
      }
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
