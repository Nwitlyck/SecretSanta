import 'dotenv/config';
import { createApp } from './src/app.js';
import { loadConfig } from './src/config.js';

try {
  const config = loadConfig();
  const server = createApp(config).listen(config.port, '0.0.0.0', () => {
    console.log(`Secret Santa is listening on port ${config.port}.`);
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
} catch (error) {
  console.error(`Startup failed: ${error.message}`);
  process.exit(1);
}
