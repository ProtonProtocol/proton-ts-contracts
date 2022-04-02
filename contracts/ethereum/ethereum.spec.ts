import { expect } from "chai";
import { Blockchain, expectToThrow } from "@jafri/vert"

/* Create Blockchain */
const blockchain = new Blockchain()

/* Create Contracts and accounts */
const ethereumContract = blockchain.createContract('ethereum', 'contracts/ethereum/target/ethereum.contract', true)
blockchain.createAccounts('account1', 'account2', 'account3')

/* Runs before each test */
beforeEach(async () => {
  blockchain.resetTables()
})
/* Tests */
describe('Ethereum', () => {
  describe('Check Authorizations', () => {
    it('ok: Only actor can call', async () => { 
      await ethereumContract.actions.test(['account1']).send('account1@active')
    });
  })
});