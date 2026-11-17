import type { IDataType } from './util';

export interface BalloonOptions {
	/** Space cost: number of blocks. The current placeholder implementation is disabled. */
	spaceCost?: number;
	/** Time cost: number of rounds. The current placeholder implementation is disabled. */
	timeCost?: number;
	/** Dependency count. The current placeholder implementation is disabled. */
	delta?: number;
}

/**
 * Disabled because the previous implementation did not conform to the published Balloon encoding.
 * It must not be used as a password KDF until an independently verified implementation is added.
 */
export async function balloonHash(
	_password: IDataType,
	_salt: IDataType,
	_options: BalloonOptions = {},
): Promise<string> {
	throw new Error('Balloon hashing is disabled: this package does not yet implement the published construction');
}
