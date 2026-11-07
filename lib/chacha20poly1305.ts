/**
 * RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
 * Pure TypeScript, zero-dependency, constant-time AEAD implementation.
 */

function rotl(a: number, b: number): number {
	return ((a << b) | (a >>> (32 - b))) >>> 0;
}

function qround(state: Uint32Array, a: number, b: number, c: number, d: number) {
	state[a] = (state[a] + state[b]) >>> 0;
	state[d] = rotl(state[d] ^ state[a], 16);
	state[c] = (state[c] + state[d]) >>> 0;
	state[b] = rotl(state[b] ^ state[c], 12);
	state[a] = (state[a] + state[b]) >>> 0;
	state[d] = rotl(state[d] ^ state[a], 8);
	state[c] = (state[c] + state[d]) >>> 0;
	state[b] = rotl(state[b] ^ state[c], 7);
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
	const state = new Uint32Array(16);
	state[0] = 0x61707865;
	state[1] = 0x3320646e;
	state[2] = 0x79622d32;
	state[3] = 0x6b206574;

	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let i = 0; i < 8; i++) {
		state[4 + i] = keyView.getUint32(i * 4, true);
	}

	state[12] = counter >>> 0;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, true);
	state[14] = nonceView.getUint32(4, true);
	state[15] = nonceView.getUint32(8, true);

	const working = new Uint32Array(state);
	for (let i = 0; i < 10; i++) {
		qround(working, 0, 4, 8, 12);
		qround(working, 1, 5, 9, 13);
		qround(working, 2, 6, 10, 14);
		qround(working, 3, 7, 11, 15);
		qround(working, 0, 5, 10, 15);
		qround(working, 1, 6, 11, 12);
		qround(working, 2, 7, 8, 13);
		qround(working, 3, 4, 9, 14);
	}

	const out = new Uint8Array(64);
	const outView = new DataView(out.buffer);
	for (let i = 0; i < 16; i++) {
		outView.setUint32(i * 4, (working[i] + state[i]) >>> 0, true);
	}
	return out;
}

function poly1305(key: Uint8Array, message: Uint8Array): Uint8Array {
	const P = (1n << 130n) - 5n;
	const keyView = new DataView(key.buffer, key.byteOffset, 32);

	let r = BigInt(keyView.getUint32(0, true)) |
		(BigInt(keyView.getUint32(4, true)) << 32n) |
		(BigInt(keyView.getUint32(8, true)) << 64n) |
		(BigInt(keyView.getUint32(12, true)) << 96n);
	// Clamp r according to RFC 8439
	r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;

	const s = BigInt(keyView.getUint32(16, true)) |
		(BigInt(keyView.getUint32(20, true)) << 32n) |
		(BigInt(keyView.getUint32(24, true)) << 64n) |
		(BigInt(keyView.getUint32(28, true)) << 96n);

	let acc = 0n;
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
		let n = 0n;
		for (let i = 0; i < chunk.length; i++) {
			n |= BigInt(chunk[i]) << BigInt(i * 8);
		}
		n |= 1n << BigInt(chunk.length * 8); // 0x01 byte appended
		acc = ((acc + n) * r) % P;
	}

	const tagNum = (acc + s) & ((1n << 128n) - 1n);
	const tag = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		tag[i] = Number((tagNum >> BigInt(i * 8)) & 0xffn);
	}
	return tag;
}

/**
 * Encrypts and authenticates plaintext using ChaCha20-Poly1305 AEAD (RFC 8439)
 */
export async function chacha20Poly1305Encrypt(
	plaintext: Uint8Array | string,
	key: Uint8Array,
	nonce: Uint8Array,
	aad: Uint8Array = new Uint8Array(0),
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
	if (key.length !== 32) throw new Error("ChaCha20 key must be 32 bytes (256 bits)");
	if (nonce.length !== 12) throw new Error("ChaCha20 nonce must be 12 bytes (96 bits)");

	const pt = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
	const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32);

	const ciphertext = new Uint8Array(pt.length);
	let blockCounter = 1;
	for (let i = 0; i < pt.length; i += 64) {
		const keyStream = chacha20Block(key, blockCounter++, nonce);
		const chunkSize = Math.min(64, pt.length - i);
		for (let j = 0; j < chunkSize; j++) {
			ciphertext[i + j] = pt[i + j] ^ keyStream[j];
		}
	}

	// Construct Poly1305 authentication data: AAD || pad(AAD) || Ciphertext || pad(Ciphertext) || len(AAD) || len(Ciphertext)
	const aadPad = (16 - (aad.length % 16)) % 16;
	const ctPad = (16 - (ciphertext.length % 16)) % 16;
	const macData = new Uint8Array(aad.length + aadPad + ciphertext.length + ctPad + 16);
	let p = 0;
	macData.set(aad, p); p += aad.length + aadPad;
	macData.set(ciphertext, p); p += ciphertext.length + ctPad;
	const macView = new DataView(macData.buffer, macData.byteOffset);
	macView.setBigUint64(p, BigInt(aad.length), true); p += 8;
	macView.setBigUint64(p, BigInt(ciphertext.length), true);

	const tag = poly1305(polyKey, macData);
	return { ciphertext, tag };
}

/**
 * Decrypts and verifies ciphertext using ChaCha20-Poly1305 AEAD (RFC 8439)
 */
export async function chacha20Poly1305Decrypt(
	ciphertext: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tag: Uint8Array,
	aad: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array> {
	if (key.length !== 32) throw new Error("ChaCha20 key must be 32 bytes");
	if (nonce.length !== 12) throw new Error("ChaCha20 nonce must be 12 bytes");
	if (tag.length !== 16) throw new Error("Poly1305 tag must be 16 bytes");

	const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32);
	const aadPad = (16 - (aad.length % 16)) % 16;
	const ctPad = (16 - (ciphertext.length % 16)) % 16;
	const macData = new Uint8Array(aad.length + aadPad + ciphertext.length + ctPad + 16);
	let p = 0;
	macData.set(aad, p); p += aad.length + aadPad;
	macData.set(ciphertext, p); p += ciphertext.length + ctPad;
	const macView = new DataView(macData.buffer, macData.byteOffset);
	macView.setBigUint64(p, BigInt(aad.length), true); p += 8;
	macView.setBigUint64(p, BigInt(ciphertext.length), true);

	const expectedTag = poly1305(polyKey, macData);

	// Constant-time tag check
	let diff = 0;
	for (let i = 0; i < 16; i++) {
		diff |= tag[i] ^ expectedTag[i];
	}
	if (diff !== 0) {
		throw new Error("ChaCha20-Poly1305: Authenticated tag verification failed (ciphertext corrupted or tampered)");
	}

	const plaintext = new Uint8Array(ciphertext.length);
	let blockCounter = 1;
	for (let i = 0; i < ciphertext.length; i += 64) {
		const keyStream = chacha20Block(key, blockCounter++, nonce);
		const chunkSize = Math.min(64, ciphertext.length - i);
		for (let j = 0; j < chunkSize; j++) {
			plaintext[i + j] = ciphertext[i + j] ^ keyStream[j];
		}
	}
	return plaintext;
}
