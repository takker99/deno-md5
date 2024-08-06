// Copyright 2018-2022 the Deno authors. All rights reserved. MIT license.
// This module is browser compatible.

/**
 * The following functions come from deno_std/hash (https://deno.land/std@0.160.0/hash/md5_test.ts)
 * released under the MIT license, see https://deno.land/std@0.160.0/LICENSE
 */

import { encodeHex } from "@std/encoding/hex";
import { assertEquals } from "@std/assert";
import { md5 } from "./mod.ts";

const millionAs = "a".repeat(1000000);

const testSetHex = [
  ["", "d41d8cd98f00b204e9800998ecf8427e"],
  ["abc", "900150983cd24fb0d6963f7d28e17f72"],
  ["deno", "c8772b401bc911da102a5291cc4ec83b"],
  [
    "The quick brown fox jumps over the lazy dog",
    "9e107d9d372bb6826bd81d3542a419d6",
  ],
  [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "3b0c8ac703f828b04c6c197006d17218",
  ],
  [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "014842d480b571495a4a0363793f7367",
  ],
  [millionAs, "7707d6ae4e027c70eea2a935c2296f21"],
];

Deno.test("md5()", () => {
  for (const [input, output] of testSetHex) {
    assertEquals(encodeHex(md5(input)), output);
  }
});
