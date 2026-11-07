import wasmJson from "../wasm/sha3.wasm.json";
import {
	type IHasher,
	type IWASMInterface,
	WASMInterface,
} from "./WASMInterface";
import lockedCreate from "./lockedCreate";
import Mutex from "./mutex";
import type { IDataType } from "./util";

const mutex = new Mutex();
let wasmCache: IWASMInterface = null;

/**
 * Calculates SHAKE256 extendable-output function (XOF / FIPS 202)
 * @param data Input data (string, Buffer or TypedArray)
 * @param outputBits Number of output bits (defaults to 256 bits = 32 bytes)
 * @returns Computed hash as a hexadecimal string
 */
export function shake256(data: IDataType, outputBits: number = 256): Promise<string> {
	const hashLength = outputBits / 8;

	if (wasmCache === null || wasmCache.hashLength !== hashLength) {
		return lockedCreate(mutex, wasmJson, hashLength).then((wasm) => {
			wasmCache = wasm;
			return wasmCache.calculate(data, 256, 0x1f);
		});
	}

	try {
		const hash = wasmCache.calculate(data, 256, 0x1f);
		return Promise.resolve(hash);
	} catch (err) {
		return Promise.reject(err);
	}
}

/**
 * Creates a new SHAKE256 instance (FIPS 202)
 * @param outputBits Output bits (defaults to 256 bits)
 */
export function createSHAKE256(outputBits: number = 256): Promise<IHasher> {
	const outputSize = outputBits / 8;

	return WASMInterface(wasmJson, outputSize).then((wasm) => {
		wasm.init(256);
		const obj: IHasher = {
			init: () => {
				wasm.init(256);
				return obj;
			},
			update: (data) => {
				wasm.update(data);
				return obj;
			},
			// biome-ignore lint/suspicious/noExplicitAny: Conflict with IHasher type
			digest: (outputType) => wasm.digest(outputType, 0x1f) as any,
			save: () => wasm.save(),
			load: (data) => {
				wasm.load(data);
				return obj;
			},
			blockSize: 136,
			digestSize: outputSize,
		};
		return obj;
	});
}
