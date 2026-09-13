// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
import { AiMemoryClient } from "../src/client.js";
import type { WriteReceipt } from "../src/types.js";

test.each<WriteReceipt["durability_class"]>(["local-only", "quorum 2-of-3", "replicated+backup"])(
  "store receipt retains %s (#3555)", async (durability_class) => {
    const receipt = { id: "receipt3555", durability_class, fsync: "per-commit" };
    const fetchImpl = async () => ({ ok: true, status: 201, headers: { get: () => "application/json" }, json: async () => receipt });
    // The mock implements only the transport members consumed by call().
    const client = new AiMemoryClient({ baseUrl: "http://localhost:9077" }, fetchImpl as never);
    const result = await client.store({ title: "receipt", content: "observation" });
    const evidence: WriteReceipt = result;
    expect(evidence.durability_class).toBe(durability_class);
    expect(evidence.fsync).toBe("per-commit");
  },
);
