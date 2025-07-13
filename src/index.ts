/**
 * Open Double Ratchet Algorithm
 * 
 * Copyright (C) 2025  Christian Braghette
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import crypto from "@freesignal/crypto";
import { decodeUTF8, encodeUTF8, verifyUint8Array } from "@freesignal/utils";

type BoxKeyPair = crypto.KeyPair;
type SignKeyPair = crypto.KeyPair;

type BundleStoreInstance = {
    SPK: Map<string, BoxKeyPair>,
    OPK: Map<string, BoxKeyPair>
}

type ExportedBundleStore = [
    SignKeyPair,
    [
        Array<[string, BoxKeyPair]>,
        Array<[string, BoxKeyPair]>
    ]
];

export class BundleStore {
    private static readonly maxOPK = 10;

    private signKeyPair: SignKeyPair;
    private IK: BoxKeyPair;
    private bundleStore: BundleStoreInstance;

    public constructor(signKeyPair: SignKeyPair, instance?: [Iterable<[string, BoxKeyPair]>, Iterable<[string, BoxKeyPair]>]) {
        this.signKeyPair = signKeyPair;
        this.IK = crypto.ECDH.keyPair(crypto.hash(signKeyPair.secretKey));
        this.bundleStore = {
            SPK: new Map(instance ? instance[0] : []),
            OPK: new Map(instance ? instance[1] : [])
        };
    }

    public digest(message: Message): Uint8Array {
        if (Message.getType(message) !== MessageType.USER) throw new Error();
        const data = X3DH.getUnsigned(message);
        let offset = data.length - X3DH.publicKeyLength * 2;
        const SPK = this.bundleStore.SPK.get(encodeUTF8(new Uint8Array(data.buffer, offset, X3DH.publicKeyLength)));
        if (!SPK) throw new Error();
        let OPK: BoxKeyPair | undefined;
        if (offset + X3DH.publicKeyLength < data.length) {
            OPK = this.bundleStore.OPK.get(encodeUTF8(new Uint8Array(data.buffer, offset, X3DH.publicKeyLength * 2)));
            if (!OPK) throw new Error();
        }
        offset = 0;
        const publicKey = data.subarray(offset, offset += X3DH.publicIdentityKeyLength);
        if (!Message.verify(message, publicKey)) throw new Error();
        const IK = data.subarray(offset, offset += X3DH.publicKeyLength);
        const EK = data.subarray(offset, offset += X3DH.publicKeyLength);
        return crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(SPK.secretKey, IK),
            ...crypto.scalarMult(this.IK.secretKey, EK),
            ...crypto.scalarMult(SPK.secretKey, EK)
        ]), OPK ? crypto.scalarMult(OPK.secretKey, EK) : new Uint8Array(), X3DH.hkdfInfo, X3DH.keyLength);
    }

    public generate(): Message {
        const SPK = crypto.ECDH.keyPair();
        const spkHash = crypto.hash(SPK.publicKey);
        this.bundleStore.SPK.set(encodeUTF8(spkHash), SPK);
        const OPK = crypto.ECDH.keyPair();
        this.bundleStore.OPK.set(encodeUTF8(new Uint8Array([...spkHash, ...crypto.hash(OPK.publicKey)])), OPK);
        return Message.create(this.signKeyPair.secretKey, 'HOST',
            [
                ...crypto.hash(this.signKeyPair.publicKey),
                ...this.IK.publicKey,
                ...SPK.publicKey,
                ...OPK.publicKey,
                ...crypto.EdDSA.sign(new Uint8Array([...this.IK.publicKey, ...SPK.publicKey, ...OPK.publicKey]), this.signKeyPair.secretKey)
            ]
        );
    }

    public generateBundle(length?: number): Bundle {
        const SPK = crypto.ECDH.keyPair();
        const OPK = new Array(length ?? BundleStore.maxOPK).fill(0).map(() => crypto.ECDH.keyPair());
        const spkHash = crypto.hash(SPK.publicKey);
        this.bundleStore.SPK.set(encodeUTF8(spkHash), SPK);
        OPK.forEach(value => {
            this.bundleStore.OPK.set(encodeUTF8(new Uint8Array([...spkHash, ...crypto.hash(value.publicKey)])), value)
        });
        return Bundle.create(this.signKeyPair.secretKey,
            [
                ...crypto.hash(this.signKeyPair.publicKey),
                ...this.IK.publicKey,
                ...SPK.publicKey,
                ...OPK.flatMap(value => [
                    ...value.publicKey,
                    ...crypto.EdDSA.sign(new Uint8Array([...this.IK.publicKey, ...SPK.publicKey, ...value.publicKey]), this.signKeyPair.secretKey)
                ])
            ]
        );
    }

    public export(): ExportedBundleStore {
        return [
            this.IK,
            [
                Array.from(this.bundleStore.SPK.entries()),
                Array.from(this.bundleStore.OPK.entries())
            ]
        ]
    }

    public static import(input: ExportedBundleStore): BundleStore {
        return new BundleStore(...input);
    }
}

enum X3DHType {
    BUNDLE,
    MESSAGE
}

namespace X3DH {
    export const secretIdentityKeyLength = crypto.EdDSA.secretKeyLength;
    export const publicIdentityKeyLength = crypto.EdDSA.publicKeyLength;
    export const secretKeyLength = crypto.ECDH.secretKeyLength;
    export const publicKeyLength = crypto.ECDH.publicKeyLength;
    export const signatureLength = crypto.EdDSA.signatureLength;
    export const keyLength = crypto.box.keyLength;
    export const version = 1;
    export const hkdfInfo = decodeUTF8("X3DH" + X3DH.version);

    export function create(secretKey: Uint8Array, type: 'BUNDLE' | 'MESSAGE', array: Iterable<number>): Message {
        const unsigned = X3DH.createUnsigned(type, array);
        return new Uint8Array([...unsigned, ...crypto.EdDSA.sign(unsigned, secretKey)]);
    }

    export function createUnsigned(type: 'BUNDLE' | 'MESSAGE', array: Iterable<number>): Message {
        return new Uint8Array([...X3DH.hkdfInfo.subarray(0, -1), (X3DH.version & 127) | (Number(X3DHType[type]) << 7), ...array]);
    }

    export function getUnsigned(array: Uint8Array): Uint8Array {
        return array.subarray(X3DH.hkdfInfo.length, array.length - X3DH.signatureLength);
    }

    export function isX3DH(array: Uint8Array): boolean {
        return verifyUint8Array(X3DH.hkdfInfo.subarray(0, -1), array.subarray(0, X3DH.hkdfInfo.length - 1));
    }

    export function getVersion(array: Uint8Array): number | undefined {
        if (!X3DH.isX3DH(array)) return undefined;
        return array[X3DH.hkdfInfo.length - 1] & 63;
    }

    export function getType(array: Uint8Array): X3DHType | undefined {
        if (!X3DH.isX3DH(array)) return undefined;
        return (array[X3DH.hkdfInfo.length - 1] & 128) >>> 7;
    }
}

export interface Bundle extends Uint8Array { }
export namespace Bundle {
    export function create(secretKey: Uint8Array, array: Iterable<number>): Bundle {
        const unsigned = X3DH.createUnsigned('BUNDLE', array);
        return new Uint8Array([...unsigned, ...crypto.EdDSA.sign(unsigned, secretKey)]);
    }

    export function isBundle(bundle: Uint8Array): boolean {
        if (!X3DH.isX3DH(bundle)) return false;
        return X3DH.getType(bundle) === X3DHType.BUNDLE;
    }
}

enum MessageType {
    HOST,
    USER
}

export interface Message extends Uint8Array { }
export namespace Message {

    export function create(secretKey: Uint8Array, type: 'HOST' | 'USER', array: Iterable<number>): Message {
        const unsigned = X3DH.createUnsigned('MESSAGE', array);
        unsigned[X3DH.hkdfInfo.length - 1] = (unsigned[X3DH.hkdfInfo.length - 1] & 191) | (MessageType[type] << 6);
        return new Uint8Array([...unsigned, ...crypto.EdDSA.sign(unsigned.subarray(X3DH.hkdfInfo.length), secretKey)]);
    }

    export function isMessage(bundle: Uint8Array): boolean {
        if (!X3DH.isX3DH(bundle)) return false;
        return X3DH.getType(bundle) === X3DHType.MESSAGE;
    }

    export function getType(array: Uint8Array): MessageType | undefined {
        if (!Message.isMessage(array)) return undefined;
        return (array[X3DH.hkdfInfo.length - 1] & 64) >>> 6;
    }

    export function verify(array: Uint8Array, publicKey: Uint8Array): boolean {
        if (!Message.isMessage(array)) return false;
        return crypto.EdDSA.verify(
            X3DH.getUnsigned(array),
            array.subarray(array.length - X3DH.signatureLength),
            publicKey
        );
    }
}

export function initBundleStore(secretKey: Uint8Array): BundleStore | undefined {
    try {
        return new BundleStore(crypto.EdDSA.keyPair(secretKey));
    } catch (error) {
        return undefined;
    }
}

export function digestMessage(identityKey: Uint8Array, remotePublicKey: Uint8Array, message: Message): [Uint8Array | undefined, Message | undefined] {
    //try {
    if (Message.getType(message) !== MessageType.HOST) throw new Error();
    const signKeyPair = crypto.EdDSA.keyPair(identityKey);
    const IK = crypto.ECDH.keyPair(crypto.hash(signKeyPair.secretKey));
    if (!Message.verify(message, remotePublicKey)) throw new Error();
    message = X3DH.getUnsigned(message);
    let offset = 0;
    const publicKey = message.subarray(offset, offset += X3DH.publicIdentityKeyLength);
    if (!verifyUint8Array(crypto.hash(remotePublicKey), publicKey)) throw new Error();
    const remoteIK = message.subarray(offset, offset += X3DH.publicKeyLength);
    const EK = crypto.ECDH.keyPair();
    const SPK = message.subarray(offset, offset += X3DH.publicKeyLength);
    let OPK: Uint8Array | undefined;
    if (offset < message.length)
        OPK = message.subarray(offset, offset += X3DH.publicKeyLength);
    const sharedKey = crypto.hkdf(new Uint8Array([
        ...crypto.scalarMult(IK.secretKey, SPK),
        ...crypto.scalarMult(EK.secretKey, remoteIK),
        ...crypto.scalarMult(EK.secretKey, SPK)
    ]), OPK ? crypto.scalarMult(EK.secretKey, OPK) : new Uint8Array(), X3DH.hkdfInfo, X3DH.keyLength);
    return [
        sharedKey,
        Message.create(signKeyPair.secretKey, 'USER',
            [
                ...signKeyPair.publicKey,
                ...IK.publicKey,
                ...EK.publicKey,
                ...crypto.hash(SPK),
                ...(OPK ? crypto.hash(OPK) : [])
            ]
        )
    ];
    /*} catch (error) {
        return [undefined, undefined];
    }*/

}

/*public static unpack(bundle: Bundle, index?: number): Message | undefined {
        const message = X3DH.getUnsigned(bundle);
        let offset = 0;
        const IK = message.subarray(offset, offset += X3DH.publicKeyLength);
        const SPK = message.subarray(offset, offset += X3DH.publicKeyLength);
        const length = X3DH.publicKeyLength + X3DH.signatureLength;
        offset += (index ?? Math.floor(Math.random() * ((bundle.length - offset) / length))) * length;
        const OPK = message.subarray(offset, offset += X3DH.keyLength);
        const signature = message.subarray(offset, offset += X3DH.signatureLength);
        return X3DH.createUnsigned('MESSAGE', new Uint8Array([...IK, ...SPK, ...OPK, ...signature]));
    }*/