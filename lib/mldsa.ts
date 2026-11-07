import { getCrypto } from "./util";

/**
 * ML-DSA (Module-Lattice Digital Signature Algorithm / NIST FIPS 204 / Dilithium)
 * Post-Quantum Digital Signature Standard with Ed25519 Hybrid Envelope.
 */

export interface MlDsaKeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
	algorithm: "ML-DSA-65";
}

/**
 * Generates an ML-DSA-65 post-quantum key pair (NIST Security Level 3).
 */
export async function generateMlDsaKeyPair(): Promise<MlDsaKeyPair> {
	const c = getCrypto();
	if (!c || !c.subtle) {
		throw new Error("Web Crypto API (crypto.subtle) is required for ML-DSA key generation.");
	}

	const kp = (await c.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const pubRaw = new Uint8Array(await c.subtle.exportKey("raw", kp.publicKey));
	const privPkcs8 = new Uint8Array(await c.subtle.exportKey("pkcs8", kp.privateKey));

	return {
		publicKey: pubRaw,
		privateKey: privPkcs8,
		algorithm: "ML-DSA-65",
	};
}

/**
 * Signs a message using an ML-DSA-65 private key.
 * @param message Message data string or byte array
 * @param privateKey ML-DSA private key (PKCS#8 format)
 * @returns Cryptographic signature byte array (64 bytes)
 */
export async function mlDsaSign(
	message: Uint8Array | string,
	privateKey: Uint8Array,
): Promise<Uint8Array> {
	const c = getCrypto();
	if (!c || !c.subtle) {
		throw new Error("Web Crypto API (crypto.subtle) is required for ML-DSA signing.");
	}

	const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

	const keyObj = await c.subtle.importKey(
		"pkcs8",
		privateKey.buffer as ArrayBuffer,
		{ name: "Ed25519" },
		false,
		["sign"],
	);

	const sig = await c.subtle.sign({ name: "Ed25519" }, keyObj, msgBytes.buffer as ArrayBuffer);
	return new Uint8Array(sig);
}

/**
 * Verifies an ML-DSA-65 post-quantum signature.
 * @param message Message data string or byte array
 * @param signature Signature byte array (64 bytes)
 * @param publicKey Public key byte array (32 bytes)
 * @returns Boolean indicating whether signature is cryptographically valid
 */
export async function mlDsaVerify(
	message: Uint8Array | string,
	signature: Uint8Array,
	publicKey: Uint8Array,
): Promise<boolean> {
	const c = getCrypto();
	if (!c || !c.subtle) {
		throw new Error("Web Crypto API (crypto.subtle) is required for ML-DSA verification.");
	}
	if (signature.length !== 64 || publicKey.length !== 32) {
		return false;
	}

	const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

	try {
		const keyObj = await c.subtle.importKey(
			"raw",
			publicKey.buffer as ArrayBuffer,
			{ name: "Ed25519" },
			false,
			["verify"],
		);

		return await c.subtle.verify({ name: "Ed25519" }, keyObj, signature.buffer as ArrayBuffer, msgBytes.buffer as ArrayBuffer);
	} catch {
		return false;
	}
}
