/**
 * SipHash-2-4: Cryptographically secure 64-bit PRF / hash function (RFC 7693).
 * Designed by Jean-Philippe Aumasson and Daniel J. Bernstein to defend against HashDoS attacks.
 */

function rotl64(x: bigint, b: bigint): bigint {
	return ((x << b) | (x >> (64n - b))) & 0xffffffffffffffffn;
}

function sipRound(v: bigint[]) {
	v[0] = (v[0] + v[1]) & 0xffffffffffffffffn;
	v[1] = rotl64(v[1], 13n) ^ v[0];
	v[0] = rotl64(v[0], 32n);

	v[2] = (v[2] + v[3]) & 0xffffffffffffffffn;
	v[3] = rotl64(v[3], 16n) ^ v[2];

	v[0] = (v[0] + v[3]) & 0xffffffffffffffffn;
	v[3] = rotl64(v[3], 21n) ^ v[0];

	v[2] = (v[2] + v[1]) & 0xffffffffffffffffn;
	v[1] = rotl64(v[1], 17n) ^ v[2];
	v[2] = rotl64(v[2], 32n);
}

/**
 * Calculates 64-bit SipHash-2-4 for input data using 128-bit key.
 * @param key 16-byte (128-bit) secret key
 * @param data Input data string or byte array
 * @returns 16-character hex string (64-bit hash)
 */
export function sipHash24(key: Uint8Array, data: Uint8Array | string): string {
	if (key.length !== 16) throw new Error("SipHash key must be 16 bytes (128 bits)");

	const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
	const keyView = new DataView(key.buffer, key.byteOffset, 16);
	const k0 = keyView.getBigUint64(0, true);
	const k1 = keyView.getBigUint64(8, true);

	const v: bigint[] = [
		k0 ^ 0x736f6d6570736575n,
		k1 ^ 0x646f72616e646f6dn,
		k0 ^ 0x6c7967656e657261n,
		k1 ^ 0x7465646279746573n,
	];

	const len = input.length;
	const fullWords = len >> 3;

	// Process full 64-bit words
	const inputView = new DataView(input.buffer, input.byteOffset, input.byteLength);
	for (let i = 0; i < fullWords; i++) {
		const m = inputView.getBigUint64(i * 8, true);
		v[3] ^= m;
		sipRound(v);
		sipRound(v);
		v[0] ^= m;
	}

	// Last block with length byte appended
	let last = BigInt(len & 0xff) << 56n;
	const remainder = len & 7;
	const offset = fullWords * 8;
	for (let i = 0; i < remainder; i++) {
		last |= BigInt(input[offset + i]) << BigInt(i * 8);
	}

	v[3] ^= last;
	sipRound(v);
	sipRound(v);
	v[0] ^= last;

	// Finalization (4 rounds)
	v[2] ^= 0xffn;
	sipRound(v);
	sipRound(v);
	sipRound(v);
	sipRound(v);

	const out = v[0] ^ v[1] ^ v[2] ^ v[3];
	return out.toString(16).padStart(16, "0");
}
