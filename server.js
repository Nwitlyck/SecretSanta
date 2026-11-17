import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './src/app.js';
import { loadConfig } from './src/config.js';

dotenv.config({ path: path.join(path.dirname(fileURLToPath(import.meta.url)), '.env'), quiet: true });

try {
  const config = loadConfig();
  const app = createApp(config);
  const server = app.listen(config.port, '0.0.0.0', () => {
    console.log(`Secret Santa is listening on port ${config.port}.`);
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  const shutdown = () => {
    server.close(() => {
      app.locals.closeDatabase();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
} catch (error) {
  console.error(`Startup failed: ${error.message}`);
  process.exit(1);
}
