/** BN254 scalar field prime retained for callers that use it for field validation. */
export const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Disabled because the former implementation used generated constants and a non-MDS mixing layer,
 * so it was not compatible with the published Poseidon construction or its security analysis.
 */
export function poseidonHash(_inputs: (bigint | number | string)[]): string {
	throw new Error('Poseidon hashing is disabled: this package does not yet implement a reviewed parameter set');
}
