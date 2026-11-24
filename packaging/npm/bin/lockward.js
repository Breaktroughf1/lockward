#!/usr/bin/env node
// Runs the Lockward binary for this platform, fetching and verifying it on
// first use (see lib/install.js). Exit codes are Lockward's own.
'use strict';
const { spawnSync } = require('node:child_process');
const { ensureBinary } = require('../lib/install.js');

(async () => {
  let bin;
  try {
    bin = await ensureBinary();
  } catch (err) {
    process.stderr.write(`lockward (npm): ${err.message}\n`);
    process.exit(4);
  }
  const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
  if (r.error) {
    process.stderr.write(`lockward (npm): ${r.error.message}\n`);
    process.exit(4);
  }
  process.exit(r.status === null ? 4 : r.status);
})();
