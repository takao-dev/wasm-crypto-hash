import { getCrypto } from "./util";

function validateKek(kek: Uint8Array): void {
	if (![16, 24, 32].includes(kek.length)) throw new Error("AES-KW KEK must contain 16, 24 or 32 bytes");
}

/** RFC 3394 AES Key Wrap. Unsupported runtimes and integrity failures reject. */
export async function aesKeyWrap(kek: Uint8Array, keyToWrap: Uint8Array): Promise<Uint8Array> {
	validateKek(kek);
	if (keyToWrap.length < 16 || keyToWrap.length % 8 !== 0) {
		throw new Error("Plaintext key length must be a multiple of 8 bytes and at least 16 bytes");
	}
	const subtle = getCrypto().subtle;
	const wrappingKey = await subtle.importKey("raw", new Uint8Array(kek), "AES-KW", false, ["wrapKey"]);
	// A raw HMAC carrier preserves arbitrary RFC 3394 material, not just AES key sizes.
	const carrier = await subtle.importKey("raw", new Uint8Array(keyToWrap),
		{ name: "HMAC", hash: "SHA-256", length: keyToWrap.length * 8 }, true, ["sign"]);
	return new Uint8Array(await subtle.wrapKey("raw", carrier, wrappingKey, "AES-KW"));
}

/** No plaintext compatibility mode: authentication must succeed before returning key bytes. */
export async function aesKeyUnwrap(kek: Uint8Array, wrappedKey: Uint8Array): Promise<Uint8Array> {
	validateKek(kek);
	if (wrappedKey.length < 24 || wrappedKey.length % 8 !== 0) {
		throw new Error("Wrapped key length must be a multiple of 8 bytes and at least 24 bytes");
	}
	const subtle = getCrypto().subtle;
	const wrappingKey = await subtle.importKey("raw", new Uint8Array(kek), "AES-KW", false, ["unwrapKey"]);
	const carrier = await subtle.unwrapKey("raw", new Uint8Array(wrappedKey), wrappingKey, "AES-KW",
		{ name: "HMAC", hash: "SHA-256", length: (wrappedKey.length - 8) * 8 }, true, ["sign"]);
	return new Uint8Array(await subtle.exportKey("raw", carrier));
}
