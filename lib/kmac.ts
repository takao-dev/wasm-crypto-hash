import { createSHAKE256 } from "./shake";
import { type IDataType, getUInt8Buffer } from "./util";

function rightEncode(val: number): Uint8Array {
	let n = 1;
	let v = val;
	while ((v >>= 8) > 0) n++;
	const res = new Uint8Array(n + 1);
	for (let i = 1; i <= n; i++) {
		res[n - i] = (val >> (8 * (i - 1))) & 0xff;
	}
	res[n] = n;
	return res;
}

function leftEncode(val: number): Uint8Array {
	let n = 1;
	let v = val;
	while ((v >>= 8) > 0) n++;
	const res = new Uint8Array(n + 1);
	res[0] = n;
	for (let i = 1; i <= n; i++) {
		res[i] = (val >> (8 * (n - i))) & 0xff;
	}
	return res;
}

function encodeString(strOrBytes: Uint8Array): Uint8Array {
	const bitLen = strOrBytes.length * 8;
	const lenPrefix = leftEncode(bitLen);
	const res = new Uint8Array(lenPrefix.length + strOrBytes.length);
	res.set(lenPrefix);
	res.set(strOrBytes, lenPrefix.length);
	return res;
}

function bytepad(input: Uint8Array, w: number): Uint8Array {
	const z = leftEncode(w);
	const total = z.length + input.length;
	const padLen = (w - (total % w)) % w;
	const res = new Uint8Array(total + padLen);
	res.set(z);
	res.set(input, z.length);
	return res;
}

/**
 * Calculates KMAC256 (Keccak Message Authentication Code / NIST SP 800-185)
 * @param key Cryptographic authentication key
 * @param data Input message data
 * @param outputBits Output digest size in bits (defaults to 256 bits = 32 bytes)
 * @param customization Optional domain separation customization string
 * @returns Hex-encoded MAC string
 */
export async function kmac256(
	key: IDataType,
	data: IDataType,
	outputBits: number = 256,
	customization: string = "",
): Promise<string> {
	const keyBuf = getUInt8Buffer(key);
	const dataBuf = getUInt8Buffer(data);
	const customBuf = new TextEncoder().encode(customization);

	const encodedKey = bytepad(encodeString(keyBuf), 136);
	const lenSuffix = rightEncode(outputBits);

	const hasher = await createSHAKE256(outputBits);
	hasher.update(encodedKey);
	if (customBuf.length > 0) {
		hasher.update(encodeString(customBuf));
	}
	hasher.update(dataBuf);
	hasher.update(lenSuffix);

	return hasher.digest("hex");
}
