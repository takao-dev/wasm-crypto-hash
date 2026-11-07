import { sha256 } from "./sha256";
import { type IDataType, getUInt8Buffer } from "./util";

function hexToBytes(hex: string): Uint8Array {
	const len = hex.length >> 1;
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	}
	return out;
}

export interface BalloonOptions {
	/** Space cost: size of buffer in blocks (defaults to 128) */
	spaceCost?: number;
	/** Time cost: number of rounds over buffer (defaults to 3) */
	timeCost?: number;
	/** Delta: number of random dependencies per step (defaults to 3) */
	delta?: number;
}

/**
 * Balloon Hashing: memory-hard password-hashing function designed by Stanford University (Boneh et al.)
 * Resists GPU/ASIC brute-force attacks via space-cost and time-cost parameters.
 * @param password Secret password string or byte array
 * @param salt Cryptographic salt string or byte array
 * @param options Balloon configuration (spaceCost, timeCost, delta)
 * @returns 64-character hex-encoded SHA-256 derived key
 */
export async function balloonHash(
	password: IDataType,
	salt: IDataType,
	options: BalloonOptions = {},
): Promise<string> {
	const sCost = options.spaceCost ?? 128;
	const tCost = options.timeCost ?? 3;
	const delta = options.delta ?? 3;

	const pw = getUInt8Buffer(password);
	const slt = getUInt8Buffer(salt);

	let cnt = 0;
	const buffer: string[] = new Array(sCost);

	// Step 1: Expand initial buffer
	const initHex = await sha256(new Uint8Array([...pw, ...slt, cnt++]));
	buffer[0] = initHex;

	for (let m = 1; m < sCost; m++) {
		const prev = hexToBytes(buffer[m - 1]);
		buffer[m] = await sha256(new Uint8Array([...prev, cnt++]));
	}

	// Step 2: Mix buffer across time rounds
	for (let t = 0; t < tCost; t++) {
		for (let m = 0; m < sCost; m++) {
			const prevIdx = (m - 1 + sCost) % sCost;
			const block = new Uint8Array([...hexToBytes(buffer[prevIdx]), ...hexToBytes(buffer[m])]);
			buffer[m] = await sha256(new Uint8Array([...block, cnt++]));

			for (let d = 0; d < delta; d++) {
				const idxBlock = hexToBytes(buffer[m]);
				const idxHash = await sha256(new Uint8Array([...idxBlock, t, m, d]));
				const other = parseInt(idxHash.slice(0, 8), 16) % sCost;
				const mix = new Uint8Array([...hexToBytes(buffer[m]), ...hexToBytes(buffer[other])]);
				buffer[m] = await sha256(new Uint8Array([...mix, cnt++]));
			}
		}
	}

	return buffer[sCost - 1];
}
