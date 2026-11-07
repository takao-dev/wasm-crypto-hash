import { getCrypto } from "./util";

export interface MlDsaKeyPair {
	/** DER SPKI public key. Classical Ed25519 keys are not accepted. */
	publicKey: Uint8Array;
	/** DER PKCS#8 private key. */
	privateKey: Uint8Array;
	algorithm: "ML-DSA-65";
}

/** Native FIPS 204 ML-DSA-65. Unsupported runtimes reject; never substitutes Ed25519. */
export async function generateMlDsaKeyPair(): Promise<MlDsaKeyPair> {
	const subtle = getCrypto().subtle;
	const pair = await subtle.generateKey({ name: "ML-DSA-65" }, true, ["sign", "verify"]);
	return {
		publicKey: new Uint8Array(await subtle.exportKey("spki", pair.publicKey)),
		privateKey: new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey)),
		algorithm: "ML-DSA-65",
	};
}

export async function mlDsaSign(message: Uint8Array | string, privateKey: Uint8Array): Promise<Uint8Array> {
	const subtle = getCrypto().subtle;
	const bytes = typeof message === "string" ? new TextEncoder().encode(message) : new Uint8Array(message);
	const key = await subtle.importKey("pkcs8", new Uint8Array(privateKey), { name: "ML-DSA-65" }, false, ["sign"]);
	return new Uint8Array(await subtle.sign({ name: "ML-DSA-65" }, key, bytes));
}

export async function mlDsaVerify(message: Uint8Array | string, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
	const subtle = getCrypto().subtle;
	const bytes = typeof message === "string" ? new TextEncoder().encode(message) : new Uint8Array(message);
	// Unsupported algorithms and legacy keys fail explicitly, before signature verification.
	const key = await subtle.importKey("spki", new Uint8Array(publicKey), { name: "ML-DSA-65" }, false, ["verify"]);
	return subtle.verify({ name: "ML-DSA-65" }, key, new Uint8Array(signature), bytes);
}
