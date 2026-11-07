import { getCrypto } from "./util";

/**
 * Shamir's Secret Sharing Scheme over Galois Field GF(2^8)
 * Rijndael polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b)
 */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

// Precompute log/exp tables for GF(2^8) with generator 3
(() => {
	function mul3(a: number): number {
		const hi = a & 0x80;
		const a2 = (a << 1) & 0xff;
		return (hi ? a2 ^ 0x1b : a2) ^ a;
	}

	let x = 1;
	for (let i = 0; i < 255; i++) {
		EXP[i] = x;
		EXP[i + 255] = x;
		LOG[x] = i;
		x = mul3(x);
	}
})();

function gfMul(a: number, b: number): number {
	if (a === 0 || b === 0) return 0;
	return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a: number, b: number): number {
	if (b === 0) throw new Error("Division by zero in GF(2^8)");
	if (a === 0) return 0;
	return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
	const len = hex.length >> 1;
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	}
	return out;
}

export interface SecretShare {
	index: number;
	share: string; // Hex-encoded share bytes
}

/**
 * Splits a secret byte array or string into N shares with threshold K.
 * Any K shares can reconstruct the original secret.
 * @param secret Original secret to split
 * @param parts Total number of shares to generate (N <= 255)
 * @param threshold Minimum number of shares required to reconstruct (K <= N)
 */
export function shamirSplit(
	secret: Uint8Array | string,
	parts: number,
	threshold: number,
): SecretShare[] {
	if (threshold < 2) throw new Error("Threshold must be >= 2");
	if (parts < threshold) throw new Error("Parts must be >= threshold");
	if (parts > 255) throw new Error("Maximum 255 parts in GF(2^8)");
	const c = getCrypto();
	if (!c || !c.getRandomValues) {
		throw new Error("Cryptographically secure random number generator (crypto.getRandomValues) is required.");
	}

	const sec = typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
	const shares: Uint8Array[] = Array.from({ length: parts }, () => new Uint8Array(sec.length));

	for (let b = 0; b < sec.length; b++) {
		const coeff = new Uint8Array(threshold);
		coeff[0] = sec[b];
		c.getRandomValues(coeff.subarray(1));

		// Evaluate polynomial at x = 1..parts
		for (let p = 1; p <= parts; p++) {
			let acc = 0;
			for (let deg = 0; deg < threshold; deg++) {
				let xPow = 1;
				for (let e = 0; e < deg; e++) xPow = gfMul(xPow, p);
				acc ^= gfMul(coeff[deg], xPow);
			}
			shares[p - 1][b] = acc;
		}
	}

	return shares.map((buf, i) => ({
		index: i + 1,
		share: bytesToHex(buf),
	}));
}

/**
 * Reconstructs the original secret from any K shares using Lagrange interpolation.
 */
export function shamirCombine(shares: SecretShare[]): Uint8Array {
	if (shares.length < 2) throw new Error("At least 2 shares required to reconstruct");

	const decodedShares = shares.map((s) => ({
		x: s.index,
		bytes: hexToBytes(s.share),
	}));

	const len = decodedShares[0].bytes.length;
	const k = decodedShares.length;
	const secret = new Uint8Array(len);

	for (let b = 0; b < len; b++) {
		let acc = 0;
		for (let i = 0; i < k; i++) {
			const xi = decodedShares[i].x;
			const yi = decodedShares[i].bytes[b];

			let basis = 1;
			for (let j = 0; j < k; j++) {
				if (i === j) continue;
				const xj = decodedShares[j].x;
				basis = gfMul(basis, gfDiv(xj, xi ^ xj));
			}
			acc ^= gfMul(yi, basis);
		}
		secret[b] = acc;
	}

	return secret;
}
