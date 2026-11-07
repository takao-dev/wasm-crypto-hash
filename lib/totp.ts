import { createHMAC } from "./hmac";
import { createSHA1 } from "./sha1";
import { createSHA256 } from "./sha256";
import { timingSafeEqualString } from "./util";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function isBase32Pattern(key: string): boolean {
	if (key.length === 0 || key.length % 8 !== 0) return false;
	for (let i = 0; i < key.length; i++) {
		const code = key.charCodeAt(i);
		const isAlpha = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
		const isNum = code >= 50 && code <= 55;
		const isPad = code === 61;
		if (!isAlpha && !isNum && !isPad) return false;
	}
	return true;
}

export function decodeBase32(str: string): Uint8Array {
	let bits = 0;
	let value = 0;
	const out: number[] = [];

	for (let i = 0; i < str.length; i++) {
		const code = str.charCodeAt(i);
		if (code === 32 || code === 9 || code === 10 || code === 13) {
			continue;
		}
		if (code === 61) {
			break;
		}
		const ch = str[i].toUpperCase();
		const idx = BASE32_ALPHABET.indexOf(ch);
		if (idx === -1) throw new Error(`Invalid Base32 character: ${str[i]}`);
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return new Uint8Array(out);
}

export interface TotpOptions {
	/** Time step in seconds (defaults to 30) */
	step?: number;
	/** Number of digits (defaults to 6) */
	digits?: number;
	/** Timestamp in milliseconds (defaults to Date.now()) */
	timestamp?: number;
	/** Hash algorithm: 'sha1' (RFC standard default) or 'sha256' */
	algorithm?: "sha1" | "sha256";
}

/**
 * Calculates HMAC-based One-Time Password (HOTP / RFC 4226)
 */
export async function hotp(
	key: Uint8Array | string,
	counter: number,
	digits: number = 6,
	algorithm: "sha1" | "sha256" = "sha1",
): Promise<string> {
	const keyBytes = typeof key === "string"
		? (isBase32Pattern(key) ? decodeBase32(key) : new TextEncoder().encode(key))
		: key;

	const hasherPromise = algorithm === "sha256" ? createSHA256() : createSHA1();
	const hmac = await createHMAC(hasherPromise, keyBytes);

	// Counter formatted as 8-byte big-endian
	const counterBytes = new Uint8Array(8);
	const view = new DataView(counterBytes.buffer);
	view.setBigUint64(0, BigInt(counter), false);

	hmac.update(counterBytes);
	const hmacResult = hmac.digest("binary");

	// RFC 4226 Dynamic Truncation
	const offset = hmacResult[hmacResult.length - 1] & 0x0f;
	const binaryCode =
		((hmacResult[offset] & 0x7f) << 24) |
		((hmacResult[offset + 1] & 0xff) << 16) |
		((hmacResult[offset + 2] & 0xff) << 8) |
		(hmacResult[offset + 3] & 0xff);

	const otp = binaryCode % 10 ** digits;
	return otp.toString().padStart(digits, "0");
}

/**
 * Calculates Time-based One-Time Password (TOTP / RFC 6238 / Google Authenticator)
 */
export async function totp(key: Uint8Array | string, options: TotpOptions = {}): Promise<string> {
	const step = options.step ?? 30;
	const digits = options.digits ?? 6;
	const time = options.timestamp ?? Date.now();
	const counter = Math.floor(time / 1000 / step);

	return hotp(key, counter, digits, options.algorithm ?? "sha1");
}

/**
 * Verifies a TOTP token against a secret key with time drift window.
 */
export async function verifyTotp(
	token: string,
	key: Uint8Array | string,
	options: TotpOptions & { window?: number } = {},
): Promise<boolean> {
	const step = options.step ?? 30;
	const digits = options.digits ?? 6;
	const window = options.window ?? 1; // default check +/- 1 step (30s)
	const time = options.timestamp ?? Date.now();
	const currentCounter = Math.floor(time / 1000 / step);

	for (let offset = -window; offset <= window; offset++) {
		const candidate = await hotp(key, currentCounter + offset, digits, options.algorithm ?? "sha1");
		if (candidate.length === token.length && timingSafeEqualString(candidate, token)) {
			return true;
		}
	}
	return false;
}
