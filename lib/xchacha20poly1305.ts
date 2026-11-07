/**
 * XChaCha20-Poly1305 (IETF draft-irtf-cfrg-xchacha)
 * Extended-nonce (192-bit / 24-byte nonce) Authenticated Encryption with Associated Data (AEAD).
 * Completely eliminates nonce reuse risks from random nonce generation.
 */

import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from "./chacha20poly1305";

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

/**
 * HChaCha20 core function: derives a 32-byte subkey from a 32-byte key and 16-byte nonce.
 */
export function hchacha20(key: Uint8Array, nonce: Uint8Array): Uint8Array {
	if (key.length !== 32) throw new Error("HChaCha20 key must be 32 bytes");
	if (nonce.length !== 16) throw new Error("HChaCha20 nonce must be 16 bytes");

	const state = new Uint32Array(16);
	state[0] = 0x61707865;
	state[1] = 0x3320646e;
	state[2] = 0x79622d32;
	state[3] = 0x6b206574;

	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let i = 0; i < 8; i++) {
		state[4 + i] = keyView.getUint32(i * 4, true);
	}

	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	for (let i = 0; i < 4; i++) {
		state[12 + i] = nonceView.getUint32(i * 4, true);
	}

	for (let i = 0; i < 10; i++) {
		qround(state, 0, 4, 8, 12);
		qround(state, 1, 5, 9, 13);
		qround(state, 2, 6, 10, 14);
		qround(state, 3, 7, 11, 15);
		qround(state, 0, 5, 10, 15);
		qround(state, 1, 6, 11, 12);
		qround(state, 2, 7, 8, 13);
		qround(state, 3, 4, 9, 14);
	}

	// Output: state[0..3] and state[12..15]
	const subkey = new Uint8Array(32);
	const subkeyView = new DataView(subkey.buffer);
	for (let i = 0; i < 4; i++) {
		subkeyView.setUint32(i * 4, state[i], true);
		subkeyView.setUint32(16 + i * 4, state[12 + i], true);
	}
	return subkey;
}

/**
 * Encrypts and authenticates plaintext using XChaCha20-Poly1305 (24-byte extended nonce AEAD).
 * @param plaintext Plaintext string or byte array
 * @param key 32-byte secret key
 * @param nonce 24-byte extended nonce
 * @param aad Optional authenticated associated data
 */
export async function xchacha20Poly1305Encrypt(
	plaintext: Uint8Array | string,
	key: Uint8Array,
	nonce: Uint8Array,
	aad: Uint8Array = new Uint8Array(0),
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
	if (key.length !== 32) throw new Error("XChaCha20 key must be 32 bytes (256 bits)");
	if (nonce.length !== 24) throw new Error("XChaCha20 nonce must be 24 bytes (192 bits)");

	// Derive 32-byte subkey using HChaCha20 on first 16 bytes of nonce
	const subkey = hchacha20(key, nonce.subarray(0, 16));

	// Construct 12-byte subnonce: 4 zero bytes + last 8 bytes of nonce
	const subnonce = new Uint8Array(12);
	subnonce.set(nonce.subarray(16, 24), 4);

	return chacha20Poly1305Encrypt(plaintext, subkey, subnonce, aad);
}

/**
 * Decrypts and verifies ciphertext using XChaCha20-Poly1305 (24-byte extended nonce AEAD).
 */
export async function xchacha20Poly1305Decrypt(
	ciphertext: Uint8Array,
	key: Uint8Array,
	nonce: Uint8Array,
	tag: Uint8Array,
	aad: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array> {
	if (key.length !== 32) throw new Error("XChaCha20 key must be 32 bytes");
	if (nonce.length !== 24) throw new Error("XChaCha20 nonce must be 24 bytes");

	const subkey = hchacha20(key, nonce.subarray(0, 16));
	const subnonce = new Uint8Array(12);
	subnonce.set(nonce.subarray(16, 24), 4);

	return chacha20Poly1305Decrypt(ciphertext, subkey, subnonce, tag, aad);
}
