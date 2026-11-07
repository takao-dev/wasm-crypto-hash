import { getCrypto } from "./util";

export interface PqcHybridKeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
	algorithm: "X25519-ML-KEM-768";
}
export interface PqcEncapsulationResult {
	sharedSecret: Uint8Array;
	ciphertext: Uint8Array;
}

// Versioned package-specific envelopes, not a TLS/IETF wire format.
function pack(tag: string, first: Uint8Array, second: Uint8Array): Uint8Array {
	const out = new Uint8Array(10 + first.length + second.length);
	out.set(new TextEncoder().encode(tag));
	new DataView(out.buffer).setUint32(6, first.length);
	out.set(first, 10);
	out.set(second, 10 + first.length);
	return out;
}
function unpack(tag: string, input: Uint8Array): [Uint8Array, Uint8Array] {
	const bytes = new Uint8Array(input);
	if (bytes.length < 12 || bytes.length > 16384 || new TextDecoder().decode(bytes.subarray(0, 6)) !== tag) {
		throw new Error("Invalid or legacy hybrid envelope");
	}
	const length = new DataView(bytes.buffer).getUint32(6);
	if (length === 0 || length >= bytes.length - 10) throw new Error("Invalid hybrid envelope length");
	return [bytes.slice(10, 10 + length), bytes.slice(10 + length)];
}
function kemSubtle(): any {
	const subtle = getCrypto().subtle;
	if (!subtle?.encapsulateBits || !subtle?.decapsulateBits) {
		throw new Error("Native ML-KEM-768 Web Crypto support is required; no classical fallback is available");
	}
	return subtle;
}
async function combine(xSecret: ArrayBuffer, pqSecret: ArrayBuffer, ciphertext: Uint8Array): Promise<Uint8Array> {
	const subtle = kemSubtle();
	const ikm = new Uint8Array(xSecret.byteLength + pqSecret.byteLength);
	ikm.set(new Uint8Array(xSecret));
	ikm.set(new Uint8Array(pqSecret), xSecret.byteLength);
	const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
	const context = new TextEncoder().encode("wasm-crypto-hash/hybrid-v1/X25519/ML-KEM-768");
	const transcript = new Uint8Array(await subtle.digest("SHA-256", new Uint8Array(ciphertext)));
	const info = new Uint8Array(context.length + transcript.length);
	info.set(context);
	info.set(transcript, context.length);
	return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, key, 256));
}

/** Actual X25519 + native ML-KEM-768 combined with HKDF-SHA256; unsupported runtimes reject. */
export async function generatePqcHybridKeyPair(): Promise<PqcHybridKeyPair> {
	const subtle = kemSubtle();
	const pq = await subtle.generateKey({ name: "ML-KEM-768" }, true, ["encapsulateBits", "decapsulateBits"]);
	const x = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
	return {
		publicKey: pack("WCHPK1", new Uint8Array(await subtle.exportKey("raw", x.publicKey)), new Uint8Array(await subtle.exportKey("spki", pq.publicKey))),
		privateKey: pack("WCHSK1", new Uint8Array(await subtle.exportKey("pkcs8", x.privateKey)), new Uint8Array(await subtle.exportKey("pkcs8", pq.privateKey))),
		algorithm: "X25519-ML-KEM-768",
	};
}
export async function pqcEncapsulate(recipientPublicKey: Uint8Array): Promise<PqcEncapsulationResult> {
	const subtle = kemSubtle();
	const [xBytes, pqBytes] = unpack("WCHPK1", recipientPublicKey);
	if (xBytes.length !== 32) throw new Error("Invalid X25519 public key length");
	const xPublic = await subtle.importKey("raw", xBytes, "X25519", false, []);
	const pqPublic = await subtle.importKey("spki", pqBytes, "ML-KEM-768", false, ["encapsulateBits"]);
	const ephemeral = await subtle.generateKey("X25519", true, ["deriveBits"]);
	const xSecret = await subtle.deriveBits({ name: "X25519", public: xPublic }, ephemeral.privateKey, 256);
	const pq = await subtle.encapsulateBits("ML-KEM-768", pqPublic);
	const ciphertext = pack("WCHCT1", new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey)), new Uint8Array(pq.ciphertext));
	return { ciphertext, sharedSecret: await combine(xSecret, pq.sharedKey, ciphertext) };
}
export async function pqcDecapsulate(ciphertext: Uint8Array, recipientPrivateKey: Uint8Array): Promise<Uint8Array> {
	const subtle = kemSubtle();
	const [xPrivateBytes, pqPrivateBytes] = unpack("WCHSK1", recipientPrivateKey);
	const [xBytes, pqBytes] = unpack("WCHCT1", ciphertext);
	if (xBytes.length !== 32 || pqBytes.length !== 1088) throw new Error("Invalid hybrid ciphertext length");
	const xPublic = await subtle.importKey("raw", xBytes, "X25519", false, []);
	const xPrivate = await subtle.importKey("pkcs8", xPrivateBytes, "X25519", false, ["deriveBits"]);
	const pqPrivate = await subtle.importKey("pkcs8", pqPrivateBytes, "ML-KEM-768", false, ["decapsulateBits"]);
	const xSecret = await subtle.deriveBits({ name: "X25519", public: xPublic }, xPrivate, 256);
	const pqSecret = await subtle.decapsulateBits("ML-KEM-768", pqPrivate, pqBytes);
	return combine(xSecret, pqSecret, new Uint8Array(ciphertext));
}
