import { bytepad, concatBytes, encodeString, keccakSponge256, rightEncode } from './keccakSponge';
import { getUInt8Buffer } from './util';

const RATE_BYTES = 136;
const MAX_OUTPUT_BYTES = 1_048_576;
const encoder = new TextEncoder();

/** Calculates KMAC256 as specified in NIST SP 800-185. */
export async function kmac256(
	key: Parameters<typeof getUInt8Buffer>[0],
	data: Parameters<typeof getUInt8Buffer>[0],
	outputBits = 256,
	customization = '',
): Promise<string> {
	if (!Number.isSafeInteger(outputBits) || outputBits < 8 || outputBits % 8 !== 0 || outputBits / 8 > MAX_OUTPUT_BYTES) {
		throw new RangeError(`KMAC256 output must be byte-aligned from 8 to ${MAX_OUTPUT_BYTES * 8} bits`);
	}
	if (typeof customization !== 'string') throw new TypeError('KMAC256 customization must be a string');
	const keyBytes = getUInt8Buffer(key);
	const dataBytes = getUInt8Buffer(data);
	const functionName = encoder.encode('KMAC');
	const customizationBytes = encoder.encode(customization);
	const domain = bytepad(concatBytes(encodeString(functionName), encodeString(customizationBytes)), RATE_BYTES);
	const paddedKey = bytepad(encodeString(keyBytes), RATE_BYTES);
	const input = concatBytes(domain, paddedKey, dataBytes, rightEncode(BigInt(outputBits)));
	const digest = keccakSponge256(input, outputBits / 8, 0x04);
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
