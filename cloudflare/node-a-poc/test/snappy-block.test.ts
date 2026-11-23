import { describe, expect, it } from "vitest";
import { decodeSnappyBlock } from "../src/snappy-block";

describe("bounded raw Snappy block decoder", () => {
  it("decodes literals", () => {
    expect(new TextDecoder().decode(decodeSnappyBlock(new Uint8Array([3, 8, 97, 98, 99]), 16))).toBe("abc");
  });

  it("decodes overlapping copy references", () => {
    expect(new TextDecoder().decode(decodeSnappyBlock(new Uint8Array([5, 0, 97, 5, 1]), 16))).toBe("aaaaa");
  });

  it("rejects oversized, truncated, non-minimal, and invalid back-references", () => {
    expect(() => decodeSnappyBlock(new Uint8Array([5, 0, 97]), 4)).toThrow("excessive");
    expect(() => decodeSnappyBlock(new Uint8Array([3, 8, 97]), 16)).toThrow("truncated");
    expect(() => decodeSnappyBlock(new Uint8Array([1, 0xf0, 0]), 16)).toThrow();
    expect(() => decodeSnappyBlock(new Uint8Array([4, 1, 0]), 16)).toThrow("invalid");
  });
});
