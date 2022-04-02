/* sha3 - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
 */
import { print, Utils } from "as-chain"
import * as env from "./env"

const sha3_max_permutation_size: u8 = 25
const sha3_max_rate_in_qwords: u8 = 24

export class SHA3_CTX {
    hash: Array<u64> = new Array<u64>(sha3_max_permutation_size)
    message: Array<u64> = new Array<u64>(sha3_max_rate_in_qwords)
    rest: u16 = 0
}

function IS_ALIGNED_64(p: u8): boolean { return (0 == (7 & (p - 0))) }
// #define me64_to_le_str(to, from, length) memcpy((to), (from), (length))

const BLOCK_SIZE: u16 = ((1600 - 256 * 2) / 8)
function ROTL64(qword: u64, n: u64): u64 {
    return ((qword) << (n) ^ ((qword) >> (64 - (n))))
}

const constants: u8[] = [
    1, 26, 94, 112, 31, 33, 121, 85, 14, 12, 53, 38, 63, 79, 93, 83, 82, 72, 22, 102, 121, 88, 33, 116,
    1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18, 17, 11, 7, 10,
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const TYPE_ROUND_INFO: u8 = 0
const TYPE_PI_TRANSFORM: u8 = 24
const TYPE_RHO_TRANSFORM: u8 = 48

function getConstant(type: u8, index: u8): u8 {
    return constants[type + index];
}

function get_round_constant(round: u8): u64 {
    let result: u64 = 0;

    const roundInfo: u8 = getConstant(TYPE_ROUND_INFO, round);
    if (roundInfo & (1 << 6)) { result |= (<u64>(1) << 63); }
    if (roundInfo & (1 << 5)) { result |= (<u64>(1) << 31); }
    if (roundInfo & (1 << 4)) { result |= (<u64>(1) << 15); }
    if (roundInfo & (1 << 3)) { result |= (<u64>(1) << 7); }
    if (roundInfo & (1 << 2)) { result |= (<u64>(1) << 3); }
    if (roundInfo & (1 << 1)) { result |= (<u64>(1) << 1); }
    if (roundInfo & (1 << 0)) { result |= (<u64>(1) << 0); }

    return result;
}

/* Keccak theta() transformation */
function keccak_theta(A: u64[]): void {
    const C: u64[] = [0, 0, 0, 0, 0]
    const D: u64[] = [0, 0, 0, 0, 0]

    for (let i: u8 = 0; i < 5; i++) {
        C[i] = A[i];
        for (let j: u8 = 5; j < 25; j += 5) { C[i] ^= A[i + j]; }
    }

    for (let i: u8 = 0; i < 5; i++) {
        D[i] = ROTL64(C[(i + 1) % 5], 1) ^ C[(i + 4) % 5];
    }

    for (let i: u8 = 0; i < 5; i++) {
        for (let j: u8 = 0; j < 25; j += 5) { A[i + j] ^= D[i]; }
    }
}


/* Keccak pi() transformation */
function keccak_pi(A: u64[]): void {
    const A1 = A[1];

    for (let i: u8 = 1; i < 24; i++) {
        A[getConstant(TYPE_PI_TRANSFORM, i - 1)] = A[getConstant(TYPE_PI_TRANSFORM, i)];
    }
    
    A[10] = A1;
}

/*
ketch uses 30084 bytes (93%) of program storage space. Maximum is 32256 bytes.
Global variables use 743 bytes (36%) of dynamic memory, leaving 1305 bytes for local variables. Maximum is 2048 bytes.
*/
/* Keccak chi() transformation */
function keccak_chi(A: u64[]): void {
    for (let i: u8 = 0; i < 25; i += 5) {
        const A0 = A[0 + i], A1 = A[1 + i];
        A[0 + i] ^= ~A1 & A[2 + i];
        A[1 + i] ^= ~A[2 + i] & A[3 + i];
        A[2 + i] ^= ~A[3 + i] & A[4 + i];
        A[3 + i] ^= ~A[4 + i] & A0;
        A[4 + i] ^= ~A0 & A1;
    }
}

function sha3_permutation(state: u64[]): void {
    for (let round: u8 = 0; round < 24; round++) {
        keccak_theta(state);

        /* apply Keccak rho() transformation */
        for (let i: u8 = 1; i < 25; i++) {
            //state[i] = ROTL64(state[i], pgm_read_byte(&rhoTransforms[i - 1]));
            state[i] = ROTL64(state[i], getConstant(TYPE_RHO_TRANSFORM, i - 1));
        }

        keccak_pi(state);
        keccak_chi(state);

        /* apply iota(state, round) */
        state[0] ^= get_round_constant(round);
    }
}

/**
 * The core transformation. Process the specified block of data.
 *
 * @param hash the algorithm state
 * @param block the message block to process
 * @param block_size the size of the processed block in bytes
 */
function sha3_process_block(hash: u64[], block: u64[]): void {
    for (let i: u8 = 0; i < 17; i++) {
        hash[i] ^= block[i];
    }

    /* make a permutation of the hash */
    sha3_permutation(hash);
}

//#define SHA3_FINALIZED 0x80000000
//#define SHA3_FINALIZED 0x8000

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param size length of the message chunk
 */
export function keccak_update(ctx: SHA3_CTX, msg: u8[], size: u32): void
{
    const idx: u16 = ctx.rest;

    //if (ctx->rest & SHA3_FINALIZED) return; /* too late for additional input */
    ctx.rest = <u16>((ctx.rest + size) % BLOCK_SIZE)

    print(`ctx.rest ${ctx.rest}`)
    print(`idx ${idx}`)

    /* fill partial block */
    if (idx) {
        const left: u32 = BLOCK_SIZE - idx;
        print(`size ${size}`)
        print(`left ${left}`)

        for (let i: u32 = 0; i < (size < left ? size : left); i++) {
            ctx.message[idx + i] = msg[i]
        }
        if (size < left) return;

        /* process partial block */
        sha3_process_block(ctx.hash, ctx.message);
        msg.splice(0, left)
        size -= left;
    }

    print(`size ${size}`)
    print(`BLOCK_SIZE ${BLOCK_SIZE}`)
    print(`msg ${msg}`)

    while (size >= BLOCK_SIZE) {
        let aligned_message_block: u64[]
        if (IS_ALIGNED_64(msg[0])) {
            aligned_message_block = new Array<u64>(msg.length);
            // the most common case is processing of an already aligned message without copying it
            for (let i = 0; i < msg.length; i++) {
                aligned_message_block[i] = msg[i];
            }
        } else {
            aligned_message_block = new Array<u64>(ctx.message.length);

            env.memcpy(ctx.message.dataStart, msg.dataStart, BLOCK_SIZE);
            aligned_message_block = ctx.message;
        }

        sha3_process_block(ctx.hash, aligned_message_block);
        msg.splice(0, BLOCK_SIZE)
        size -= BLOCK_SIZE;
    }

    // for (let i = 0; i < ctx.message.length; i++) {
    //     print(`ctx.message[${i}] ${ctx.message[i]}`)
    // }

    print(`BIG SIZE ${size}`)

    if (size) {
        env.memcpy(ctx.message.dataStart, msg.dataStart, size); /* save leftovers */
    }
}

/**
* Store calculated hash into the given array.
*
* @param ctx the algorithm context containing current hashing state
* @param result calculated hash in binary form
*/
export function keccak_final(ctx: SHA3_CTX): u8[]
{
    const empty: u8[] = new Array<u8>(BLOCK_SIZE - ctx.rest).fill(0, 0, BLOCK_SIZE - ctx.rest)
    env.memcpy(ctx.message.dataStart + ctx.rest, empty.dataStart, BLOCK_SIZE - ctx.rest)

    print(`ctx.message ${ctx.message.length} ${ctx.rest} ${BLOCK_SIZE -1}`)

    print(`ctx.rest ${ctx.message[ctx.rest]}`)
    ctx.message[ctx.rest] |= 0x01;
    print(`ctx.rest ${ctx.message[ctx.rest]}`)

    print(`ctx.rest ${ctx.message[BLOCK_SIZE - 1]}`)
    ctx.message[BLOCK_SIZE - 1] |= 0x80;
    print(`ctx.rest ${ctx.message[BLOCK_SIZE - 1]}`)

    print(`ctx.memset  ${BLOCK_SIZE} ${BLOCK_SIZE - ctx.rest}`)

    for (let i = 0; i < ctx.message.length; i++) {
        print(`ctx.message[${i}] ${ctx.message[i]}`)
    }

    sha3_process_block(ctx.hash, ctx.message);

    const digest_length: u16 = 100 - BLOCK_SIZE / 2;

    const result = new Array<u8>(digest_length)
    env.memcpy(result.dataStart, ctx.hash.dataStart, digest_length)
    print(`${Utils.bytesToHex(result)}`)

    return result
}