import { describe, expect, it } from "vitest";
import { formatBytes } from "./format.js";

describe("formatBytes", () => {
  it("formats small and large values", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GiB");
  });
  it("rejects invalid input", () => {
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes(NaN)).toBe("—");
  });
});
