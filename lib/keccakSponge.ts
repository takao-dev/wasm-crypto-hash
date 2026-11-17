const MASK64 = 0xffffffffffffffffn;
const RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const ROUND_CONSTANTS = [
	0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
	0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
	0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
	0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
	0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
	0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

function rotateLeft(value: bigint, shift: number): bigint {
	if (shift === 0) return value;
	const n = BigInt(shift);
	return ((value << n) | (value >> (64n - n))) & MASK64;
}

function permute(state: bigint[]): void {
	for (const roundConstant of ROUND_CONSTANTS) {
		const column = new Array<bigint>(5);
		for (let x = 0; x < 5; x++) column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
		for (let x = 0; x < 5; x++) {
			const delta = column[(x + 4) % 5] ^ rotateLeft(column[(x + 1) % 5], 1);
			for (let y = 0; y < 5; y++) state[x + 5 * y] = (state[x + 5 * y] ^ delta) & MASK64;
		}
		const moved = new Array<bigint>(25).fill(0n);
		for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
			moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotateLeft(state[x + 5 * y], RHO[x + 5 * y]);
		}
		for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
			state[x + 5 * y] = (moved[x + 5 * y] ^ ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y])) & MASK64;
		}
		state[0] ^= roundConstant;
	}
}

/** Keccak sponge for SHAKE256 and cSHAKE256, using the FIPS 202/SP 800-185 rate and delimiters. */
export function keccakSponge256(input: Uint8Array, outputBytes: number, suffix: 0x1f | 0x04 = 0x1f): Uint8Array {
	return new Keccak256Sponge().update(input).digest(outputBytes, suffix);
}

function absorb(state: bigint[], block: Uint8Array): void {
	for (let i = 0; i < block.length; i++) state[i >> 3] ^= BigInt(block[i]) << BigInt((i & 7) * 8);
}

export class Keccak256Sponge {
	private readonly state = new Array<bigint>(25).fill(0n);
	private readonly buffer = new Uint8Array(136);
	private buffered = 0;
	private finalized = false;

	update(input: Uint8Array): this {
		if (this.finalized) throw new Error('Cannot update a finalized sponge');
		let offset = 0;
		if (this.buffered > 0) {
			const take = Math.min(136 - this.buffered, input.byteLength);
			this.buffer.set(input.subarray(0, take), this.buffered);
			this.buffered += take;
			offset = take;
			if (this.buffered === 136) { absorb(this.state, this.buffer); permute(this.state); this.buffer.fill(0); this.buffered = 0; }
		}
		while (input.byteLength - offset >= 136) {
			absorb(this.state, input.subarray(offset, offset + 136));
			permute(this.state);
			offset += 136;
		}
		if (offset < input.byteLength) {
			this.buffer.set(input.subarray(offset), 0);
			this.buffered = input.byteLength - offset;
		}
		return this;
	}

	digest(outputBytes: number, suffix: 0x1f | 0x04 = 0x1f): Uint8Array {
		if (this.finalized) throw new Error('Sponge has already been finalized');
		if (!Number.isSafeInteger(outputBytes) || outputBytes < 1) throw new RangeError('Output size must be a positive safe integer');
		this.buffer[this.buffered] ^= suffix;
		this.buffer[135] ^= 0x80;
		absorb(this.state, this.buffer);
		permute(this.state);
		this.finalized = true;
		const result = new Uint8Array(outputBytes);
		let written = 0;
		while (written < outputBytes) {
			const take = Math.min(136, outputBytes - written);
			for (let i = 0; i < take; i++) result[written + i] = Number((this.state[i >> 3] >> BigInt((i & 7) * 8)) & 0xffn);
			written += take;
			if (written < outputBytes) permute(this.state);
		}
		return result;
	}

	save(): Uint8Array {
		if (this.finalized) throw new Error('Cannot save a finalized sponge');
		const result = new Uint8Array(204 + 136);
		const view = new DataView(result.buffer);
		for (let i = 0; i < 25; i++) view.setBigUint64(i * 8, this.state[i], true);
		view.setUint32(200, this.buffered, true);
		result.set(this.buffer, 204);
		return result;
	}

	load(saved: Uint8Array): this {
		if (!(saved instanceof Uint8Array) || saved.byteLength !== 340) throw new Error('Invalid SHAKE256 state length');
		const view = new DataView(saved.buffer, saved.byteOffset, saved.byteLength);
		const buffered = view.getUint32(200, true);
		if (buffered >= 136 || saved.subarray(204 + buffered).some((byte) => byte !== 0)) throw new Error('Invalid SHAKE256 state contents');
		for (let i = 0; i < 25; i++) this.state[i] = view.getBigUint64(i * 8, true);
		this.buffer.set(saved.subarray(204));
		this.buffered = buffered;
		this.finalized = false;
		return this;
	}
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
	const size = parts.reduce((sum, part) => sum + part.byteLength, 0);
	if (!Number.isSafeInteger(size)) throw new RangeError('Input is too large');
	const output = new Uint8Array(size);
	let offset = 0;
	for (const part of parts) { output.set(part, offset); offset += part.byteLength; }
	return output;
}

export function encodeString(value: Uint8Array): Uint8Array {
	return concatBytes(leftEncode(BigInt(value.byteLength) * 8n), value);
}

export function leftEncode(value: bigint): Uint8Array {
	if (value < 0n) throw new RangeError('Encoded value must be non-negative');
	let bytes = 1;
	while (value >= (1n << BigInt(bytes * 8))) bytes++;
	const result = new Uint8Array(bytes + 1);
	result[0] = bytes;
	for (let i = 0; i < bytes; i++) result[bytes - i] = Number((value >> BigInt(i * 8)) & 0xffn);
	return result;
}

export function rightEncode(value: bigint): Uint8Array {
	if (value < 0n) throw new RangeError('Encoded value must be non-negative');
	let bytes = 1;
	while (value >= (1n << BigInt(bytes * 8))) bytes++;
	const result = new Uint8Array(bytes + 1);
	for (let i = 0; i < bytes; i++) result[bytes - 1 - i] = Number((value >> BigInt(i * 8)) & 0xffn);
	result[bytes] = bytes;
	return result;
}

export function bytepad(value: Uint8Array, width: number): Uint8Array {
	const prefix = leftEncode(BigInt(width));
	const remainder = (prefix.byteLength + value.byteLength) % width;
	return concatBytes(prefix, value, new Uint8Array((width - remainder) % width));
}
