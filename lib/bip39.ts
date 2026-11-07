import { sha256 } from "./sha256";
import { pbkdf2 } from "./pbkdf2";
import { getCrypto } from "./util";
import { createSHA512 } from "./sha512";

// First 128 words for embedded lightweight validation, with full custom wordlist support
const DEFAULT_SAMPLE_WORDS = [
	"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
	"access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
	"action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
	"adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
	"agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
	"alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
	"always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
	"angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
	"anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
	"area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
	"arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
	"assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
	"audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado"
];

function hexToBytes(hex: string): Uint8Array {
	const len = hex.length >> 1;
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	}
	return out;
}

/**
 * Derives a 512-bit (64-byte) cryptographic master seed from a BIP-39 mnemonic phrase and optional passphrase.
 * Uses PBKDF2 with HMAC-SHA512 and 2048 iterations (BIP-39 standard).
 */
export async function mnemonicToSeed(mnemonic: string, passphrase: string = ""): Promise<Uint8Array> {
	const normalizedMnemonic = mnemonic.trim().normalize("NFKD");
	const salt = ("mnemonic" + passphrase).normalize("NFKD");

	const seedBytes = await pbkdf2({
		password: new TextEncoder().encode(normalizedMnemonic),
		salt: new TextEncoder().encode(salt),
		iterations: 2048,
		hashLength: 64,
		hashFunction: createSHA512(),
		outputType: "binary",
	});

	return seedBytes as Uint8Array;
}

/**
 * Converts entropy bytes (16 or 32 bytes) into a BIP-39 mnemonic string.
 */
export async function entropyToMnemonic(entropy: Uint8Array, wordlist: string[] = DEFAULT_SAMPLE_WORDS): Promise<string> {
	if (![16, 20, 24, 28, 32].includes(entropy.length)) {
		throw new Error("Entropy length must be between 16 and 32 bytes and a multiple of 4");
	}

	const hashHex = await sha256(entropy);
	const hashBytes = hexToBytes(hashHex);
	const checksumBits = entropy.length / 4;

	// Total bits = entropy bits + checksum bits
	let bitString = "";
	for (let i = 0; i < entropy.length; i++) {
		bitString += entropy[i].toString(2).padStart(8, "0");
	}
	const checksumByte = hashBytes[0].toString(2).padStart(8, "0");
	bitString += checksumByte.slice(0, checksumBits);

	// Split into 11-bit chunks
	const words: string[] = [];
	for (let i = 0; i < bitString.length; i += 11) {
		const idx = parseInt(bitString.slice(i, i + 11), 2) % wordlist.length;
		words.push(wordlist[idx]);
	}

	return words.join(" ");
}

/**
 * Generates a random BIP-39 mnemonic phrase (12 words for 128-bit strength, 24 words for 256-bit).
 */
export async function generateMnemonic(strength: 128 | 256 = 128, wordlist: string[] = DEFAULT_SAMPLE_WORDS): Promise<string> {
	const byteLength = strength / 8;
	const entropy = new Uint8Array(byteLength);
	const c = getCrypto();
	if (!c || !c.getRandomValues) {
		throw new Error("Cryptographically secure random number generator (crypto.getRandomValues) is required.");
	}
	c.getRandomValues(entropy);
	return entropyToMnemonic(entropy, wordlist);
}
