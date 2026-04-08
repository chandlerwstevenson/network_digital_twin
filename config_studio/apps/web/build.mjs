import { mkdir, copyFile } from 'node:fs/promises';
import path from 'node:path';

const root = new URL('.', import.meta.url).pathname;
const outDir = path.join(root, 'out');
await mkdir(outDir, { recursive: true });
await copyFile(path.join(root, 'index.html'), path.join(outDir, 'index.html'));
console.log('Built static web app to apps/web/out');
