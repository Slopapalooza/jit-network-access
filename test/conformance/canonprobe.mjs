// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later

// Exposes the browser reference's canonicalizers to differential.py.
// The extension ships jitcrypto.js unchanged, so this probe tests the real thing.
//
//   node canonprobe.mjs cases.json
//
// Only canon_server_name: the extension never canonicalizes a client IP, so
// there is no JS canonIp to compare.

import { readFileSync } from "node:fs";
import { canonServerName } from "../../extension/src/jitcrypto.js";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
process.stdout.write(
  JSON.stringify({ server_names: cases.server_names.map(canonServerName) }),
);
