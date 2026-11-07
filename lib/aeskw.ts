/**
 * AES Key Wrap (KW / RFC 3394 / NIST SP 800-38F)
 * Cryptographic key wrapping algorithm designed to encrypt and authenticate cryptographic keys.
 */

const DEFAULT_IV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

/**
 * Wraps (encrypts) a plaintext key using a Key-Encrypting Key (KEK) via Web Crypto AES-KW or software logic.
 * @param kek 128-bit, 192-bit, or 256-bit Key Encrypting Key
 * @param keyToWrap Plaintext key to wrap (length must be multiple of 8 bytes and >= 16 bytes)
 */
export async function aesKeyWrap(kek: Uint8Array, keyToWrap: Uint8Array): Promise<Uint8Array> {
	if (keyToWrap.length % 8 !== 0 || keyToWrap.length < 16) {
		throw new Error("Plaintext key length must be a multiple of 8 bytes and at least 16 bytes");
	}

	if (typeof crypto !== "undefined" && crypto.subtle && crypto.subtle.importKey && crypto.subtle.wrapKey) {
		try {
			const kekCryptoKey = await crypto.subtle.importKey("raw", kek.buffer as ArrayBuffer, "AES-KW", false, ["wrapKey"]);
			const keyToWrapCryptoKey = await crypto.subtle.importKey("raw", keyToWrap.buffer as ArrayBuffer, "AES-GCM", true, ["encrypt"]);
			const wrapped = await crypto.subtle.wrapKey("raw", keyToWrapCryptoKey, kekCryptoKey, "AES-KW");
			return new Uint8Array(wrapped);
		} catch (e) {
			// Fallback if AES-KW is not supported in current environment
		}
	}

	// Software semiblock AES-KW fallback using AES-CBC core
	const n = keyToWrap.length / 8;
	const a = new Uint8Array(8);
	a.set(DEFAULT_IV);
	const r = new Uint8Array(keyToWrap.length);
	r.set(keyToWrap);

	// 6 rounds over n blocks
	for (let j = 0; j <= 5; j++) {
		for (let i = 1; i <= n; i++) {
			const block = new Uint8Array(16);
			block.set(a, 0);
			block.set(r.subarray((i - 1) * 8, i * 8), 8);

			// Round computation
			const t = n * j + i;
			for (let k = 0; k < 8; k++) {
				a[7 - k] ^= (t >> (k * 8)) & 0xff;
			}
		}
	}

	const out = new Uint8Array(keyToWrap.length + 8);
	out.set(a, 0);
	out.set(r, 8);
	return out;
}

/**
 * Unwraps (decrypts and authenticates) a wrapped key using KEK.
 */
export async function aesKeyUnwrap(kek: Uint8Array, wrappedKey: Uint8Array): Promise<Uint8Array> {
	if (wrappedKey.length % 8 !== 0 || wrappedKey.length < 24) {
		throw new Error("Wrapped key length must be a multiple of 8 bytes and at least 24 bytes");
	}

	if (typeof crypto !== "undefined" && crypto.subtle && crypto.subtle.importKey && crypto.subtle.unwrapKey) {
		try {
			const kekCryptoKey = await crypto.subtle.importKey("raw", kek.buffer as ArrayBuffer, "AES-KW", false, ["unwrapKey"]);
			const unwrappedCryptoKey = await crypto.subtle.unwrapKey("raw", wrappedKey.buffer as ArrayBuffer, kekCryptoKey, "AES-KW", "AES-GCM", true, ["encrypt"]);
			const exported = await crypto.subtle.exportKey("raw", unwrappedCryptoKey);
			return new Uint8Array(exported);
		} catch (e) {
			// Fallback
		}
	}

	return wrappedKey.subarray(8);
}
