/**
 * MurmurHash3 (Austin Appleby)
 * Fast non-cryptographic hash function widely used in Bloom filters, distributed systems, and hash tables.
 */

function rotl32(x: number, r: number): number {
	return ((x << r) | (x >>> (32 - r))) >>> 0;
}

function fmix32(h: number): number {
	h ^= h >>> 16;
	h = Math.imul(h, 0x85ebca6b);
	h ^= h >>> 13;
	h = Math.imul(h, 0xc2b2ae35);
	h ^= h >>> 16;
	return h >>> 0;
}

/**
 * Calculates 32-bit MurmurHash3
 * @param key Input data string or byte array
 * @param seed Optional 32-bit integer seed (defaults to 0)
 * @returns 32-bit unsigned integer hash
 */
export function murmurHash3_32(key: Uint8Array | string, seed: number = 0): number {
	const data = typeof key === "string" ? new TextEncoder().encode(key) : key;
	const c1 = 0xcc9e2d51;
	const c2 = 0x1b873593;

	let h1 = seed >>> 0;
	const len = data.length;
	const nblocks = len >> 2;

	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	for (let i = 0; i < nblocks; i++) {
		let k1 = view.getUint32(i * 4, true);
		k1 = Math.imul(k1, c1);
		k1 = rotl32(k1, 15);
		k1 = Math.imul(k1, c2);

		h1 ^= k1;
		h1 = rotl32(h1, 13);
		h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
	}

	let k1 = 0;
	const tail = nblocks * 4;
	switch (len & 3) {
		case 3:
			k1 ^= data[tail + 2] << 16;
		// falls through
		case 2:
			k1 ^= data[tail + 1] << 8;
		// falls through
		case 1:
			k1 ^= data[tail];
			k1 = Math.imul(k1, c1);
			k1 = rotl32(k1, 15);
			k1 = Math.imul(k1, c2);
			h1 ^= k1;
	}

	h1 ^= len;
	return fmix32(h1);
}

/**
 * Calculates 128-bit MurmurHash3
 * @param key Input data string or byte array
 * @param seed Optional 32-bit integer seed (defaults to 0)
 * @returns 32-character hex string representing 128-bit hash
 */
export function murmurHash3_128(key: Uint8Array | string, seed: number = 0): string {
	const data = typeof key === "string" ? new TextEncoder().encode(key) : key;
	const len = data.length;
	const nblocks = len >> 4;

	let h1 = seed >>> 0;
	let h2 = seed >>> 0;
	let h3 = seed >>> 0;
	let h4 = seed >>> 0;

	const c1 = 0x239b961b;
	const c2 = 0xab0e9789;
	const c3 = 0x38b34ae5;
	const c4 = 0xa1e38b93;

	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	for (let i = 0; i < nblocks; i++) {
		let k1 = view.getUint32(i * 16, true);
		let k2 = view.getUint32(i * 16 + 4, true);
		let k3 = view.getUint32(i * 16 + 8, true);
		let k4 = view.getUint32(i * 16 + 12, true);

		k1 = Math.imul(k1, c1); k1 = rotl32(k1, 15); k1 = Math.imul(k1, c2); h1 ^= k1;
		h1 = rotl32(h1, 19); h1 = (h1 + h2) >>> 0; h1 = (Math.imul(h1, 5) + 0x561ccd1b) >>> 0;

		k2 = Math.imul(k2, c2); k2 = rotl32(k2, 16); k2 = Math.imul(k2, c3); h2 ^= k2;
		h2 = rotl32(h2, 17); h2 = (h2 + h3) >>> 0; h2 = (Math.imul(h2, 5) + 0x0bcaa747) >>> 0;

		k3 = Math.imul(k3, c3); k3 = rotl32(k3, 17); k3 = Math.imul(k3, c4); h3 ^= k3;
		h3 = rotl32(h3, 15); h3 = (h3 + h4) >>> 0; h3 = (Math.imul(h3, 5) + 0x96cd1c35) >>> 0;

		k4 = Math.imul(k4, c4); k4 = rotl32(k4, 18); k4 = Math.imul(k4, c1); h4 ^= k4;
		h4 = rotl32(h4, 13); h4 = (h4 + h1) >>> 0; h4 = (Math.imul(h4, 5) + 0x32ac3b17) >>> 0;
	}

	h1 ^= len; h2 ^= len; h3 ^= len; h4 ^= len;
	h1 = (h1 + h2 + h3 + h4) >>> 0;
	h2 = (h2 + h1) >>> 0;
	h3 = (h3 + h1) >>> 0;
	h4 = (h4 + h1) >>> 0;

	h1 = fmix32(h1);
	h2 = fmix32(h2);
	h3 = fmix32(h3);
	h4 = fmix32(h4);

	return [h1, h2, h3, h4].map(h => h.toString(16).padStart(8, "0")).join("");
}
