import { Keccak256Sponge } from './keccakSponge';
import { getUInt8Buffer } from './util';
import type { IHasher } from './WASMInterface';

const MAX_OUTPUT_BYTES = 1_048_576;
const STATE_MAGIC = new TextEncoder().encode('SHAKE256-v2');

function validateOutputBits(outputBits: number): number {
	if (!Number.isSafeInteger(outputBits) || outputBits < 8 || outputBits % 8 !== 0 || outputBits / 8 > MAX_OUTPUT_BYTES) {
		throw new RangeError(`SHAKE256 output must be a byte-aligned length from 8 to ${MAX_OUTPUT_BYTES * 8} bits`);
	}
	return outputBits / 8;
}

function toHex(data: Uint8Array): string {
	return Array.from(data, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Calculates SHAKE256 (FIPS 202) with a true extendable-output implementation. */
export async function shake256(data: Parameters<typeof getUInt8Buffer>[0], outputBits = 256): Promise<string> {
	const size = validateOutputBits(outputBits);
	return toHex(new Keccak256Sponge().update(getUInt8Buffer(data)).digest(size));
}

/** Creates an incremental SHAKE256 hasher. Saved state is sensitive and must be protected like the input. */
export async function createSHAKE256(outputBits = 256): Promise<IHasher> {
	const outputSize = validateOutputBits(outputBits);
	let sponge = new Keccak256Sponge();
	let finalized = false;
	const obj: IHasher = {
		init: () => { sponge = new Keccak256Sponge(); finalized = false; return obj; },
		update: (data) => {
			if (finalized) throw new Error('SHAKE256 hasher has been finalized; call init() before updating');
			sponge.update(getUInt8Buffer(data));
			return obj;
		},
		digest: ((outputType: 'hex' | 'binary' = 'hex') => {
			if (finalized) throw new Error('SHAKE256 hasher has already been finalized');
			finalized = true;
			const digest = sponge.digest(outputSize);
			return outputType === 'binary' ? digest : toHex(digest);
		}) as IHasher['digest'],
		save: () => {
			if (finalized) throw new Error('Cannot save a finalized SHAKE256 hasher');
			const inner = sponge.save();
			const state = new Uint8Array(STATE_MAGIC.length + 4 + inner.length);
			state.set(STATE_MAGIC);
			new DataView(state.buffer).setUint32(STATE_MAGIC.length, outputBits, true);
			state.set(inner, STATE_MAGIC.length + 4);
			return state;
		},
		load: (state) => {
			if (!(state instanceof Uint8Array) || state.length !== STATE_MAGIC.length + 4 + 340 ||
				!STATE_MAGIC.every((byte, index) => state[index] === byte) ||
				new DataView(state.buffer, state.byteOffset, state.byteLength).getUint32(STATE_MAGIC.length, true) !== outputBits) {
				throw new Error('Incompatible or malformed SHAKE256 state');
			}
			sponge = new Keccak256Sponge().load(state.subarray(STATE_MAGIC.length + 4));
			finalized = false;
			return obj;
		},
		blockSize: 136,
		digestSize: outputSize,
		algorithm: 'SHAKE256-v2',
	};
	return obj;
}
