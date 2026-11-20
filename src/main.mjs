import { readConfig } from './config.mjs';
import { createLilauth } from './server.mjs';

let config;
try {
  config = readConfig(process.env);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

const server = createLilauth(config);
server.once('error', () => {
  console.error('Lilauth could not start its HTTP listener.');
  process.exit(1);
});
server.listen(config.port, config.host, () => console.log('Lilauth is listening.'));
