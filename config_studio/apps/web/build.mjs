import { mkdir, copyFile } from 'node:fs/promises';
import path from 'node:path';

const root = new URL('.', import.meta.url).pathname;
const outDir = path.join(root, 'out');
await mkdir(outDir, { recursive: true });
for (const filename of ['index.html', 'ui_helpers.js', 'batch_queue_ui.js', 'quick_pass_ui.js', 'theme_ui.js']) {
  await copyFile(path.join(root, filename), path.join(outDir, filename));
}
console.log('Built static web app to apps/web/out');
