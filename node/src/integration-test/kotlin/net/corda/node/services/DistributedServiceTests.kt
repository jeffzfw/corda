package net.corda.node.services

import net.corda.core.bufferUntilSubscribed
import net.corda.core.contracts.Amount
import net.corda.core.contracts.POUNDS
import net.corda.core.crypto.Party
import net.corda.core.getOrThrow
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.StateMachineUpdate
import net.corda.core.messaging.startFlow
import net.corda.core.node.NodeInfo
import net.corda.core.serialization.OpaqueBytes
import net.corda.core.utilities.DUMMY_BANK_A
import net.corda.core.utilities.DUMMY_NOTARY
import net.corda.flows.CashIssueFlow
import net.corda.flows.CashPaymentFlow
import net.corda.node.driver.NodeHandle
import net.corda.node.driver.driver
import net.corda.node.services.transactions.RaftValidatingNotaryService
import net.corda.nodeapi.User
import net.corda.testing.expect
import net.corda.testing.expectEvents
import net.corda.testing.node.DriverBasedTest
import net.corda.testing.replicate
import org.junit.Test
import rx.Observable
import java.util.*
import kotlin.test.assertEquals

class DistributedServiceTests : DriverBasedTest() {
    lateinit var bankA: NodeHandle
    lateinit var notaries: List<NodeHandle>
    lateinit var bankAProxy: CordaRPCOps
    lateinit var raftNotaryIdentity: Party
    lateinit var notaryStateMachines: Observable<Pair<NodeInfo, StateMachineUpdate>>

    override fun setup() = driver {
        // Start Alice and 3 notaries in a RAFT cluster
        val clusterSize = 3
        val testUser = User("test", "test", permissions = setOf(
                startFlowPermission<CashIssueFlow>(),
                startFlowPermission<CashPaymentFlow>())
        )
        val bankAFuture = startNode(DUMMY_BANK_A.name, rpcUsers = listOf(testUser))
        val notariesFuture = startNotaryCluster(
                DUMMY_NOTARY.name,
                rpcUsers = listOf(testUser),
                clusterSize = clusterSize,
                type = RaftValidatingNotaryService.type
        )

        bankA = bankAFuture.get()
        val (notaryIdentity, notaryNodes) = notariesFuture.get()
        raftNotaryIdentity = notaryIdentity
        notaries = notaryNodes

        assertEquals(notaries.size, clusterSize)
        assertEquals(notaries.size, notaries.map { it.nodeInfo.legalIdentity }.toSet().size)

        // Connect to Bank A and the notaries
        fun connectRpc(node: NodeHandle): CordaRPCOps {
            val client = node.rpcClientToNode()
            client.start("test", "test")
            return client.proxy()
        }
        bankAProxy = connectRpc(bankA)
        val rpcClientsToNotaries = notaries.map(::connectRpc)
        notaryStateMachines = Observable.from(rpcClientsToNotaries.map { proxy ->
            proxy.stateMachinesAndUpdates().second.map { Pair(proxy.nodeIdentity(), it) }
        }).flatMap { it.onErrorResumeNext(Observable.empty()) }.bufferUntilSubscribed()

        runTest()
    }

    // TODO Use a dummy distributed service rather than a Raft Notary Service as this test is only about Artemis' ability
    // to handle distributed services
    @Test
    fun `requests are distributed evenly amongst the nodes`() {
        // Issue 100 pounds, then pay ourselves 50x2 pounds
        issueCash(100.POUNDS)

        for (i in 1..50) {
            paySelf(2.POUNDS)
        }

        // The state machines added in the notaries should map one-to-one to notarisation requests
        val notarisationsPerNotary = HashMap<Party, Int>()
        notaryStateMachines.expectEvents(isStrict = false) {
            replicate<Pair<NodeInfo, StateMachineUpdate>>(50) {
                expect(match = { it.second is StateMachineUpdate.Added }) {
                    val (notary, update) = it
                    update as StateMachineUpdate.Added
                    notarisationsPerNotary.compute(notary.legalIdentity) { _, number -> number?.plus(1) ?: 1 }
                }
            }
        }

        // The distribution of requests should be very close to sg like 16/17/17 as by default artemis does round robin
        println("Notarisation distribution: $notarisationsPerNotary")
        require(notarisationsPerNotary.size == 3)
        // We allow some leeway for artemis as it doesn't always produce perfect distribution
        require(notarisationsPerNotary.values.all { it > 10 })
    }

    // TODO This should be in RaftNotaryServiceTests
    @Test
    fun `cluster survives if a notary is killed`() {
        // Issue 100 pounds, then pay ourselves 10x5 pounds
        issueCash(100.POUNDS)

        for (i in 1..10) {
            paySelf(5.POUNDS)
        }

        // Now kill a notary
        with(notaries[0].process) {
            destroy()
            waitFor()
        }

        // Pay ourselves another 20x5 pounds
        for (i in 1..20) {
            paySelf(5.POUNDS)
        }

        val notarisationsPerNotary = HashMap<Party, Int>()
        notaryStateMachines.expectEvents(isStrict = false) {
            replicate<Pair<NodeInfo, StateMachineUpdate>>(30) {
                expect(match = { it.second is StateMachineUpdate.Added }) {
                    val (notary, update) = it
                    update as StateMachineUpdate.Added
                    notarisationsPerNotary.compute(notary.legalIdentity) { _, number -> number?.plus(1) ?: 1 }
                }
            }
        }

        println("Notarisation distribution: $notarisationsPerNotary")
        require(notarisationsPerNotary.size == 3)
    }

    private fun issueCash(amount: Amount<Currency>) {
        val issueHandle = bankAProxy.startFlow(
                ::CashIssueFlow,
                amount, OpaqueBytes.of(0), bankA.nodeInfo.legalIdentity, raftNotaryIdentity)
        issueHandle.returnValue.getOrThrow()
    }

    private fun paySelf(amount: Amount<Currency>) {
        val payHandle = bankAProxy.startFlow(::CashPaymentFlow, amount, bankA.nodeInfo.legalIdentity)
        payHandle.returnValue.getOrThrow()
    }
}
