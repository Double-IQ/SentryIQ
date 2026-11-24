/** Strict decoder for GitHub's raw Snappy-block attestation bundle payloads. */
const HARD_OUTPUT_LIMIT = 8_000_000;
export function decodeSnappyBlock(input: Uint8Array, maximumOutputBytes: number): Uint8Array {
  if (!(input instanceof Uint8Array) || input.byteLength < 2 ||
      !Number.isSafeInteger(maximumOutputBytes) || maximumOutputBytes < 1 || maximumOutputBytes > HARD_OUTPUT_LIMIT) {
    throw new Error("Snappy block is empty or has an invalid output limit");
  }
  let offset = 0;
  const declared = readVarint(input, () => offset, (next) => { offset = next; });
  if (declared < 1 || declared > maximumOutputBytes) {
    throw new Error("Snappy block declares an invalid or excessive uncompressed length");
  }
  const output = new Uint8Array(declared);
  let written = 0;
  while (offset < input.byteLength) {
    const tag = input[offset++]!;
    const type = tag & 3;
    if (type === 0) {
      const encodedLength = tag >>> 2;
      let length: number;
      if (encodedLength < 60) {
        length = encodedLength + 1;
      } else {
        const lengthBytes = encodedLength - 59;
        if (lengthBytes < 1 || lengthBytes > 4 || offset + lengthBytes > input.byteLength) {
          throw new Error("Snappy literal length is malformed or truncated");
        }
        let minusOne = 0;
        for (let i = 0; i < lengthBytes; i++) minusOne += input[offset++]! * (2 ** (8 * i));
        length = minusOne + 1;
        if ((lengthBytes === 1 && minusOne < 60) ||
            (lengthBytes > 1 && minusOne < 2 ** (8 * (lengthBytes - 1)))) {
          throw new Error("Snappy literal length is not minimally encoded");
        }
      }
      if (offset + length > input.byteLength || written + length > declared) {
        throw new Error("Snappy literal exceeds its input or declared output length");
      }
      output.set(input.subarray(offset, offset + length), written);
      offset += length;
      written += length;
      continue;
    }

    let length: number;
    let copyOffset: number;
    if (type === 1) {
      if (offset >= input.byteLength) throw new Error("Snappy one-byte copy offset is truncated");
      length = 4 + ((tag >>> 2) & 7);
      copyOffset = ((tag & 0xe0) << 3) | input[offset++]!;
    } else if (type === 2) {
      if (offset + 2 > input.byteLength) throw new Error("Snappy two-byte copy offset is truncated");
      length = 1 + (tag >>> 2);
      copyOffset = input[offset]! | (input[offset + 1]! << 8);
      offset += 2;
    } else {
      if (offset + 4 > input.byteLength) throw new Error("Snappy four-byte copy offset is truncated");
      length = 1 + (tag >>> 2);
      copyOffset = input[offset]! | (input[offset + 1]! << 8) |
        (input[offset + 2]! << 16) | (input[offset + 3]! << 24);
      offset += 4;
    }
    if (copyOffset < 1 || copyOffset > written || written + length > declared) {
      throw new Error("Snappy copy operation references invalid or excessive output");
    }
    for (let i = 0; i < length; i++) {
      output[written] = output[written - copyOffset]!;
      written++;
    }
  }
  if (written !== declared) throw new Error("Snappy block output length does not match its declaration");
  return output;
}

function readVarint(
  input: Uint8Array,
  getOffset: () => number,
  setOffset: (value: number) => void
): number {
  let offset = getOffset();
  let value = 0;
  for (let i = 0; i < 5; i++) {
    if (offset >= input.byteLength) throw new Error("Snappy uncompressed length varint is truncated");
    const byte = input[offset++]!;
    const payload = byte & 0x7f;
    if (i === 4 && payload > 0x0f) throw new Error("Snappy uncompressed length varint overflows 32 bits");
    value += payload * (2 ** (7 * i));
    if ((byte & 0x80) === 0) {
      if (i > 0 && payload === 0) throw new Error("Snappy uncompressed length varint is not minimally encoded");
      setOffset(offset);
      return value;
    }
  }
  throw new Error("Snappy uncompressed length varint is too long");
}
