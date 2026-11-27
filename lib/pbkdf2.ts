import type { IHasher } from "./WASMInterface";
import { createHMAC } from "./hmac";
import { type IDataType, getDigestHex, getUInt8Buffer } from "./util";

export interface IPBKDF2Options {
	/**
	 * Password (or message) to be hashed
	 */
	password: IDataType;
	/**
	 * Salt (usually containing random bytes)
	 */
	salt: IDataType;
	/**
	 * Number of iterations to perform
	 */
	iterations: number;
	/**
	 * Output size in bytes
	 */
	hashLength: number;
	/**
	 * Hash algorithm to use. It has to be the return value of a function like createSHA1()
	 */
	hashFunction: Promise<IHasher>;
	/**
	 * Desired output type. Defaults to 'hex'
	 */
	outputType?: "hex" | "binary";
}

async function calculatePBKDF2(
	digest: IHasher,
	salt: IDataType,
	iterations: number,
	hashLength: number,
	outputType?: "hex" | "binary",
): Promise<Uint8Array | string> {
	const DK = new Uint8Array(hashLength);
	const saltBuffer = getUInt8Buffer(salt);
	const saltUIntBuffer = new Uint8Array(
		saltBuffer.buffer,
		saltBuffer.byteOffset,
		saltBuffer.length,
	);
	const block1 = new Uint8Array(saltUIntBuffer.byteLength + 4);
	const block1View = new DataView(block1.buffer);
	block1.set(saltUIntBuffer);

	let destPos = 0;
	const hLen = digest.digestSize;
	const l = Math.ceil(hashLength / hLen);

	let T: Uint8Array = null;
	let U: Uint8Array = null;

	for (let i = 1; i <= l; i++) {
		block1View.setUint32(saltUIntBuffer.byteLength, i);

		digest.init();
		digest.update(block1);
		T = digest.digest("binary");
		U = T.slice();

		for (let j = 1; j < iterations; j++) {
			digest.init();
			digest.update(U);
			U = digest.digest("binary");
			for (let k = 0; k < hLen; k++) {
				T[k] ^= U[k];
			}
		}

		DK.set(T.subarray(0, hashLength - destPos), destPos);
		destPos += hLen;
	}

	if (outputType === "binary") {
		return DK;
	}

	const digestChars = new Uint8Array(hashLength * 2);
	return getDigestHex(digestChars, DK, hashLength);
}

const validateOptions = (options: IPBKDF2Options) => {
	if (!options || typeof options !== "object") {
		throw new Error("Invalid options parameter. It requires an object.");
	}

	if (!options.hashFunction || !options.hashFunction.then) {
		throw new Error(
			'Invalid hash function is provided! Usage: pbkdf2("password", "salt", 1000, 32, createSHA1()).',
		);
	}

	if (!Number.isSafeInteger(options.iterations) || options.iterations < 1 || options.iterations > 10_000_000) {
		throw new Error("Iterations should be an integer from 1 to 10000000");
	}

	if (!Number.isSafeInteger(options.hashLength) || options.hashLength < 1 || options.hashLength > 1_048_576) {
		throw new Error("Hash length should be an integer from 1 to 1048576 bytes");
	}

	if (options.outputType === undefined) {
		options.outputType = "hex";
	}

	if (!["hex", "binary"].includes(options.outputType)) {
		throw new Error(
			`Insupported output type ${options.outputType}. Valid values: ['hex', 'binary']`,
		);
	}
};

const MAX_PBKDF2_PRF_ITERATIONS = 2_000_000;

interface IPBKDF2OptionsBinary {
	outputType: "binary";
}

type PBKDF2ReturnType<T> = T extends IPBKDF2OptionsBinary ? Uint8Array : string;

/**
 * Generates a new PBKDF2 hash for the supplied password
 */
export async function pbkdf2<T extends IPBKDF2Options>(
	options: T,
): Promise<PBKDF2ReturnType<T>> {
	validateOptions(options);

	const hmac = await createHMAC(options.hashFunction, options.password);
	const workFactor = options.iterations * Math.ceil(options.hashLength / hmac.digestSize);
	if (!Number.isSafeInteger(workFactor) || workFactor > MAX_PBKDF2_PRF_ITERATIONS) {
		throw new RangeError(`PBKDF2 work factor exceeds the ${MAX_PBKDF2_PRF_ITERATIONS} safety limit`);
	}
	return calculatePBKDF2(
		hmac,
		options.salt,
		options.iterations,
		options.hashLength,
		options.outputType,
	) as Promise<PBKDF2ReturnType<T>>;
}
