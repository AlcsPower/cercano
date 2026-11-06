// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(__dirname, '../src');

function walk(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      results = results.concat(walk(fullPath));
    } else if (/\.(tsx?|css|html)$/.test(file)) {
      results.push(fullPath);
    }
  }
  return results;
}

const invalidTokens = /\b(border-3|py-0\.2|black\/8|white\/12)\b/;
const files = walk(srcDir);
const errors = [];

for (const file of files) {
  const relPath = path.relative(path.resolve(__dirname, '..'), file);
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, index) => {
    if (invalidTokens.test(line)) {
      errors.push(`${relPath}:${index + 1}: ${line.trim()}`);
    }
  });
}

if (errors.length > 0) {
  console.error('❌ Se encontraron tokens o clases no soportadas de Tailwind:');
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
} else {
  console.log('✅ Chequeo de tokens de diseño completado sin hallazgos.');
}
