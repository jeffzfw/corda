package net.corda.attachmentdemo

import net.corda.core.div
import net.corda.core.node.services.ServiceInfo
import net.corda.core.utilities.DUMMY_BANK_A
import net.corda.core.utilities.DUMMY_BANK_B
import net.corda.core.utilities.DUMMY_NOTARY
import net.corda.node.driver.driver
import net.corda.node.services.transactions.SimpleNotaryService
import net.corda.nodeapi.User
import java.nio.file.Paths

/**
 * This file is exclusively for being able to run your nodes through an IDE (as opposed to running deployNodes)
 * Do not use in a production environment.
 */
fun main(args: Array<String>) {
    val demoUser = listOf(User("demo", "demo", setOf("StartFlow.net.corda.flows.FinalityFlow")))
    driver(isDebug = true, driverDirectory = Paths.get("build") / "attachment-demo-nodes") {
        startNode(DUMMY_NOTARY.name, setOf(ServiceInfo(SimpleNotaryService.Companion.type)))
        startNode(DUMMY_BANK_A.name, rpcUsers = demoUser)
        startNode(DUMMY_BANK_B.name, rpcUsers = demoUser)
        waitForAllNodesToFinish()
    }
}
