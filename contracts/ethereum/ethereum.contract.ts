import { Name, requireAuth, Contract, print, Utils } from 'as-chain'
import { keccak_final, keccak_update, SHA3_CTX } from './utils'

@contract("ethereum")
export class EthereumContract extends Contract {
    @action("test")
    updatevalues(
        actor: Name
    ): void {
        // Authorization
        requireAuth(actor)

        const msg: u8[] = Utils.hexToBytes("0")

        const ctx = new SHA3_CTX()

        keccak_update(ctx, msg, msg.length)
        const res = keccak_final(ctx)

        print(`${res}, ${res.length}`)
        print(`${Utils.bytesToHex(res)}, ${res.length}`)
    }
}