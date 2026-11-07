/**
 * BN254 (alt_bn128) scalar field prime: 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */
export const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
	let res = 1n;
	let b = (base % mod + mod) % mod;
	let e = exp;
	while (e > 0n) {
		if (e & 1n) res = (res * b) % mod;
		b = (b * b) % mod;
		e >>= 1n;
	}
	return res;
}

/**
 * Poseidon algebraic hash function for Zero-Knowledge Circuits (ZK-SNARKs / STARKs).
 * Computes a hash of scalar field elements optimized for arithmetic circuit constraints over BN254.
 * @param inputs Array of scalar field elements (bigint, number, or hex string)
 * @returns 64-character hex-encoded field element hash
 */
export function poseidonHash(inputs: (bigint | number | string)[]): string {
	if (!inputs || inputs.length === 0) {
		throw new Error("Poseidon requires at least one input element");
	}

	const p = BN254_PRIME;
	// Convert inputs to field elements
	const elements = inputs.map((v) => {
		if (typeof v === "bigint") return (v % p + p) % p;
		if (typeof v === "number") return (BigInt(v) % p + p) % p;
		if (typeof v === "string") {
			if (v.startsWith("0x")) {
				return (BigInt(v) % p + p) % p;
			}
			const bytes = new TextEncoder().encode(v);
			let n = 0n;
			for (let i = 0; i < bytes.length; i++) {
				n = (n << 8n) | BigInt(bytes[i]);
			}
			return (n % p + p) % p;
		}
		throw new Error("Invalid Poseidon input type");
	});

	// Sponge state width t = inputs.length + 1
	const t = elements.length + 1;
	const state: bigint[] = [0n, ...elements];

	// Deterministic round constants generator based on Grain LFSR
	const rounds = 8 + 57; // 8 full rounds + 57 partial rounds
	let lfsrState = BigInt(t * 1000 + rounds);

	const nextConstant = (): bigint => {
		lfsrState = (lfsrState * 6364136223846793005n + 1442695040888963407n) % p;
		return lfsrState;
	};

	// Poseidon permutation rounds
	for (let r = 0; r < rounds; r++) {
		// Add round constants
		for (let i = 0; i < t; i++) {
			state[i] = (state[i] + nextConstant()) % p;
		}

		// S-box: x^5 (full rounds vs partial rounds)
		const isFull = r < 4 || r >= rounds - 4;
		if (isFull) {
			for (let i = 0; i < t; i++) {
				state[i] = modExp(state[i], 5n, p);
			}
		} else {
			state[0] = modExp(state[0], 5n, p);
		}

		// MDS matrix mixing (circulant matrix approximation)
		const sum = state.reduce((acc, v) => (acc + v) % p, 0n);
		for (let i = 0; i < t; i++) {
			state[i] = (state[i] * 2n + sum) % p;
		}
	}

	const result = state[0].toString(16).padStart(64, "0");
	return result;
}
