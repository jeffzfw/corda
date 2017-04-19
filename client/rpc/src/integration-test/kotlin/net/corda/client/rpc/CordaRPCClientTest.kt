package net.corda.client.rpc

import net.corda.core.contracts.DOLLARS
import net.corda.core.flows.CommunicationInitiator
import net.corda.core.flows.FlowException
import net.corda.core.getOrThrow
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.StateMachineUpdate
import net.corda.core.messaging.startFlow
import net.corda.core.node.services.ServiceInfo
import net.corda.core.random63BitValue
import net.corda.core.serialization.OpaqueBytes
import net.corda.core.utilities.ALICE
import net.corda.flows.CashIssueFlow
import net.corda.flows.CashPaymentFlow
import net.corda.node.internal.Node
import net.corda.node.services.startFlowPermission
import net.corda.node.services.transactions.ValidatingNotaryService
import net.corda.nodeapi.User
import net.corda.testing.node.NodeBasedTest
import org.apache.activemq.artemis.api.core.ActiveMQSecurityException
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CordaRPCClientTest : NodeBasedTest() {
    private val rpcUser = User("user1", "test", permissions = setOf(
            startFlowPermission<CashIssueFlow>(),
            startFlowPermission<CashPaymentFlow>()
    ))
    private lateinit var node: Node
    private lateinit var client: CordaRPCClient

    @Before
    fun setUp() {
        node = startNode(ALICE.name, rpcUsers = listOf(rpcUser), advertisedServices = setOf(ServiceInfo(ValidatingNotaryService.type))).getOrThrow()
        client = CordaRPCClient(node.configuration.rpcAddress!!)
    }

    @After
    fun done() {
        client.close()
    }

    @Test
    fun `log in with valid username and password`() {
        client.start(rpcUser.username, rpcUser.password)
    }

    @Test
    fun `log in with unknown user`() {
        assertThatExceptionOfType(ActiveMQSecurityException::class.java).isThrownBy {
            client.start(random63BitValue().toString(), rpcUser.password)
        }
    }

    @Test
    fun `log in with incorrect password`() {
        assertThatExceptionOfType(ActiveMQSecurityException::class.java).isThrownBy {
            client.start(rpcUser.username, random63BitValue().toString())
        }
    }

    @Test
    fun `close-send deadlock and premature shutdown on empty observable`() {
        val proxy = createRpcProxy(rpcUser.username, rpcUser.password)
        println("Starting flow")
        val flowHandle = proxy.startFlow(
                ::CashIssueFlow,
                20.DOLLARS, OpaqueBytes.of(0), node.info.legalIdentity, node.info.legalIdentity)
        println("Started flow, waiting on result")
        flowHandle.progress.subscribe {
            println("PROGRESS $it")
        }
        println("Result: ${flowHandle.returnValue.getOrThrow()}")
    }

    @Test
    fun `FlowException thrown by flow`() {
        client.start(rpcUser.username, rpcUser.password)
        val proxy = client.proxy()
        val handle = proxy.startFlow(::CashPaymentFlow, 100.DOLLARS, node.info.legalIdentity)
        // TODO Restrict this to CashException once RPC serialisation has been fixed
        assertThatExceptionOfType(FlowException::class.java).isThrownBy {
            handle.returnValue.getOrThrow()
        }
    }

    @Test
    fun `get cash balances`() {
        val proxy = createRpcProxy(rpcUser.username, rpcUser.password)
        val startCash = proxy.getCashBalances()
        assertTrue(startCash.isEmpty(), "Should not start with any cash")

        val flowHandle = proxy.startFlow(::CashIssueFlow,
                123.DOLLARS, OpaqueBytes.of(0),
                node.info.legalIdentity, node.info.legalIdentity
        )
        println("Started issuing cash, waiting on result")
        flowHandle.progress.subscribe {
            println("CashIssue PROGRESS $it")
        }

        val finishCash = proxy.getCashBalances()
        println("Cash Balances: $finishCash")
        assertEquals(1, finishCash.size)
        assertEquals(123.DOLLARS, finishCash.get(Currency.getInstance("USD")))
    }

    @Test
    fun `flow initiator via RPC`() {
        val proxy = createRpcProxy(rpcUser.username, rpcUser.password)
        val smUpdates = proxy.stateMachinesAndUpdates()
        var countRpcFlows = 0
        var countManualFlows = 0
        smUpdates.second.subscribe {
            if (it is StateMachineUpdate.Added) {
                val initiator = it.stateMachineInfo.initiator
                if (initiator is CommunicationInitiator.Rpc)
                    countRpcFlows += 1
                if (initiator is CommunicationInitiator.Manual)
                    countManualFlows += 1
            }
        }
        val nodeIdentity = node.info.legalIdentity
        node.services.startFlow(CashIssueFlow(2000.DOLLARS, OpaqueBytes.of(0), nodeIdentity, nodeIdentity)).resultFuture.getOrThrow()
        proxy.startFlow(::CashIssueFlow,
                123.DOLLARS, OpaqueBytes.of(0),
                nodeIdentity, nodeIdentity
        ).returnValue.getOrThrow()
        proxy.startFlowDynamic(CashIssueFlow::class.java,
                1000.DOLLARS, OpaqueBytes.of(0),
                nodeIdentity, nodeIdentity).returnValue.getOrThrow()
        assertEquals(2, countRpcFlows)
        assertEquals(1, countManualFlows)
    }

    private fun createRpcProxy(username: String, password: String): CordaRPCOps {
        println("Starting client")
        client.start(username, password)
        println("Creating proxy")
        return client.proxy()
    }
}
