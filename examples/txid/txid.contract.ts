import { Name, getTransactionId, requireAuth, Contract, transactionSize, print, getAction, Table, TableStore } from 'proton-tsc'
import { AccountKV, KV } from '../kv';

@packer
class GetSizeAndId extends Table {
    constructor (
        public actor: Name = new Name(),
    ) {
        super()
    }
}

@contract
export class TxIdContract extends Contract {
    kvsTable: TableStore<AccountKV> = AccountKV.getTable(this.receiver)

    @action("getsizeandid")
    getsizeandid(
        actor: Name
    ): void {
        requireAuth(actor)

        const accountKv = new AccountKV(actor, [
            new KV("tx_size", `${transactionSize()}`),
            new KV("tx_id", `${getTransactionId()}`)
        ])
        print(`${accountKv.values[0].value} | `)
        print(`${accountKv.values[1].value} | `)
        this.kvsTable.store(accountKv, actor)
    }

    @action("readaction")
    readaction(): void {
        const action = getAction(1, 0)

        const getSizeAndId = new GetSizeAndId()
        getSizeAndId.unpack(action.data)

        const accountKv = this.kvsTable.requireGet(getSizeAndId.actor.N, "could not find KV")
        accountKv.values.push(new KV("action_size", `${action.getSize()}`))

        this.kvsTable.update(accountKv, getSizeAndId.actor)
    }
}