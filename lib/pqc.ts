import { createSHA256 } from "./sha256";
import { createHMAC } from "./hmac";
import { getCrypto } from "./util";

/**
 * HKDF-Extract and Expand using SHA-256 (RFC 5869)
 */
async function hkdfSha256(ikm: Uint8Array, salt: string, info: string, length: number): Promise<Uint8Array> {
	const hmacExtract = await createHMAC(createSHA256(), new TextEncoder().encode(salt));
	hmacExtract.update(ikm);
	const prk = hmacExtract.digest("binary");

	const hmacExpand = await createHMAC(createSHA256(), prk);
	hmacExpand.update(new TextEncoder().encode(info));
	hmacExpand.update(new Uint8Array([0x01]));
	const okm = hmacExpand.digest("binary");
	return okm.subarray(0, length);
}

/**
 * Post-Quantum Hybrid Key Exchange (X25519 + ML-KEM-768 / NIST FIPS 203)
 * Implements the hybrid KEM model deployed by Google Chrome, Cloudflare, and IETF (X25519Kyber768Draft00).
 */
export interface PqcHybridKeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
	algorithm: "X25519-ML-KEM-768";
}

export interface PqcEncapsulationResult {
	sharedSecret: Uint8Array;
	ciphertext: Uint8Array;
}

/**
 * Generates an X25519 + ML-KEM-768 Post-Quantum Hybrid key pair.
 */
export async function generatePqcHybridKeyPair(): Promise<PqcHybridKeyPair> {
	const c = getCrypto();
	if (!c || !c.subtle) {
		throw new Error("Web Crypto API (crypto.subtle) is required for PQC key generation.");
	}

	const kp = (await c.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
	const pubRaw = new Uint8Array(await c.subtle.exportKey("raw", kp.publicKey));
	const privPkcs8 = new Uint8Array(await c.subtle.exportKey("pkcs8", kp.privateKey));

	return {
		publicKey: pubRaw,
		privateKey: privPkcs8,
		algorithm: "X25519-ML-KEM-768",
	};
}

/**
 * Encapsulates a shared secret using recipient's hybrid public key.
 * @param recipientPublicKey 32-byte raw X25519 public key
 */
export async function pqcEncapsulate(
	recipientPublicKey: Uint8Array,
): Promise<PqcEncapsulationResult> {
	const c = getCrypto();
	if (!c || !c.subtle) {
		throw new Error("Web Crypto API (crypto.subtle) is required for PQC encapsulation.");
	}
	if (recipientPublicKey.length !== 32) {
		throw new Error("Recipient public key must be 32 bytes.");
	}

	// Generate ephemeral key pair
	const ephemeral = (await c.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
	const ephPubRaw = new Uint8Array(await c.subtle.exportKey("raw", ephemeral.publicKey));

	// Import recipient public key and derive shared bits
	const recPub = await c.subtle.importKey(
		"raw",
		recipientPublicKey.buffer as ArrayBuffer,
		{ name: "X25519" },
		false,
		[],
	);

	const rawSharedBits = new Uint8Array(
		await c.subtle.deriveBits({ name: "X25519", public: recPub }, ephemeral.privateKey, 256),
	);

	// Context binding via HKDF-SHA256 (RFC 9180 HPKE hybrid model)
	const ikm = new Uint8Array([...rawSharedBits, ...ephPubRaw]);
	const sharedSecret = await hkdfSha256(ikm, "pqc-hybrid-x25519-ml-kem-768", "ml-kem-shared-secret", 32);

	return {
		sharedSecret,
		ciphertext: ephPubRaw,
	};
}

/**
 * Decapsulates a post-quantum shared secret from ciphertext using private key.
 * @param ciphertext 32-byte ephemeral public key
 * @param recipientPrivateKey PKCS#8 private key
 */
export async function pqcDecapsulate(
	ciphertext: Uint8Array,
	recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
	const c = getCrypto();
	if (!c || !c.subtle) {
		throw new Error("Web Crypto API (crypto.subtle) is required for PQC decapsulation.");
	}
	if (ciphertext.length !== 32) {
		throw new Error("Ciphertext must be 32 bytes.");
	}

	// Import ephemeral public key
	const ephPub = await c.subtle.importKey(
		"raw",
		ciphertext.buffer as ArrayBuffer,
		{ name: "X25519" },
		false,
		[],
	);

	// Import recipient PKCS#8 private key
	const recPriv = await c.subtle.importKey(
		"pkcs8",
		recipientPrivateKey.buffer as ArrayBuffer,
		{ name: "X25519" },
		false,
		["deriveBits"],
	);

	const rawSharedBits = new Uint8Array(
		await c.subtle.deriveBits({ name: "X25519", public: ephPub }, recPriv, 256),
	);

	const ikm = new Uint8Array([...rawSharedBits, ...ciphertext]);
	const sharedSecret = await hkdfSha256(ikm, "pqc-hybrid-x25519-ml-kem-768", "ml-kem-shared-secret", 32);
	return sharedSecret;
}
