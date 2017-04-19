package net.corda.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.ContractState
import net.corda.core.contracts.DealState
import net.corda.core.contracts.StateRef
import net.corda.core.crypto.*
import net.corda.core.flows.FlowLogic
import net.corda.core.node.NodeInfo
import net.corda.core.node.services.ServiceType
import net.corda.core.seconds
import net.corda.core.serialization.CordaSerializable
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.ProgressTracker
import net.corda.core.utilities.UntrustworthyData
import net.corda.core.utilities.trace
import net.corda.core.utilities.unwrap
import java.security.KeyPair
import java.security.PublicKey

/**
 * Classes for manipulating a two party deal or agreement.
 *
 * TODO: The subclasses should probably be broken out into individual flows rather than making this an ever expanding collection of subclasses.
 *
 * TODO: Also, the term Deal is used here where we might prefer Agreement.
 *
 * TODO: Consider whether we can merge this with [TwoPartyTradeFlow]
 *
 */
object TwoPartyDealFlow {
    // This object is serialised to the network and is the first flow message the seller sends to the buyer.
    @CordaSerializable
    data class Handshake<out T>(val payload: T, val publicKey: PublicKey)

    /**
     * [Primary] at the end sends the signed tx to all the regulator parties. This a seperate workflow which needs a
     * sepearate session with the regulator. This interface is used to do that in [Primary.getCounterpartyMarker].
     */
    interface MarkerForBogusRegulatorFlow

    /**
     * Abstracted bilateral deal flow participant that initiates communication/handshake.
     */
    abstract class Primary(override val progressTracker: ProgressTracker = Primary.tracker()) : FlowLogic<SignedTransaction>() {

        companion object {
            object AWAITING_PROPOSAL : ProgressTracker.Step("Handshaking and awaiting transaction proposal")
            object VERIFYING : ProgressTracker.Step("Verifying proposed transaction")
            object SIGNING : ProgressTracker.Step("Signing transaction")
            object NOTARY : ProgressTracker.Step("Getting notary signature")
            object SENDING_SIGS : ProgressTracker.Step("Sending transaction signatures to other party")
            object RECORDING : ProgressTracker.Step("Recording completed transaction")
            object COPYING_TO_REGULATOR : ProgressTracker.Step("Copying regulator")

            fun tracker() = ProgressTracker(AWAITING_PROPOSAL, VERIFYING, SIGNING, NOTARY, SENDING_SIGS, RECORDING, COPYING_TO_REGULATOR)
        }

        abstract val payload: Any
        abstract val notaryNode: NodeInfo
        abstract val otherParty: Party
        abstract val myKeyPair: KeyPair

        override fun getCounterpartyMarker(party: Party): Class<*> {
            return if (serviceHub.networkMapCache.regulatorNodes.any { it.legalIdentity == party }) {
                MarkerForBogusRegulatorFlow::class.java
            } else {
                super.getCounterpartyMarker(party)
            }
        }

        @Suspendable
        override fun call(): SignedTransaction {
            progressTracker.currentStep = AWAITING_PROPOSAL
            // Make the first message we'll send to kick off the flow.
            val hello = Handshake(payload, serviceHub.myInfo.legalIdentity.owningKey)
            // Wait for the FinalityFlow to finish on the other side and return the tx when it's available.
            return sendAndReceive<SecureHash>(otherParty, hello).unwrap { waitForLedgerCommit(it) }
        }
    }

    /**
     * Abstracted bilateral deal flow participant that is recipient of initial communication.
     */
    abstract class Secondary<U>(override val progressTracker: ProgressTracker = Secondary.tracker()) : FlowLogic<SignedTransaction>() {

        companion object {
            object RECEIVING : ProgressTracker.Step("Waiting for deal info")
            object VERIFYING : ProgressTracker.Step("Verifying deal info")
            object SIGNING : ProgressTracker.Step("Generating and signing transaction proposal")
            object COLLECTING_SIGNATURES : ProgressTracker.Step("Collecting signatures from other parties.")
            object RECORDING : ProgressTracker.Step("Recording completed transaction")
            object COPYING_TO_REGULATOR : ProgressTracker.Step("Copying regulator")

            fun tracker() = ProgressTracker(RECEIVING, VERIFYING, SIGNING, COLLECTING_SIGNATURES, RECORDING, COPYING_TO_REGULATOR)
        }

        abstract val otherParty: Party

        @Suspendable
        override fun call(): SignedTransaction {
            val handshake = receiveAndValidateHandshake()

            progressTracker.currentStep = SIGNING
            val (utx, additionalSigningPubKeys) = assembleSharedTX(handshake)
            val ptx = signWithOurKeys(additionalSigningPubKeys, utx)

            logger.trace { "Signed proposed transaction." }

            progressTracker.currentStep = COLLECTING_SIGNATURES
            val stx = subFlow(CollectSignaturesFlow(ptx))

            logger.trace { "Got signatures from other party, verifying ... " }

            progressTracker.currentStep = RECORDING
            val ftx = subFlow(FinalityFlow(stx, setOf(otherParty, serviceHub.myInfo.legalIdentity))).single()

            logger.trace { "Recorded transaction." }

            progressTracker.currentStep = COPYING_TO_REGULATOR
            val regulators = serviceHub.networkMapCache.regulatorNodes
            if (regulators.isNotEmpty()) {
                // Copy the transaction to every regulator in the network. This is obviously completely bogus, it's
                // just for demo purposes.
                regulators.forEach { send(it.serviceIdentities(ServiceType.regulator).first(), ftx) }
            }

            // Send the final transaction hash back to the other party.
            // We need this so we don't break the IRS demo and the SIMM Demo.
            send(otherParty, ftx.id)

            return ftx
        }

        @Suspendable
        private fun receiveAndValidateHandshake(): Handshake<U> {
            progressTracker.currentStep = RECEIVING
            // Wait for a trade request to come in on our pre-provided session ID.
            val handshake = receive<Handshake<U>>(otherParty)

            progressTracker.currentStep = VERIFYING
            return handshake.unwrap { validateHandshake(it) }
        }

        private fun signWithOurKeys(signingPubKeys: List<PublicKey>, ptx: TransactionBuilder): SignedTransaction {
            // Now sign the transaction with whatever keys we need to move the cash.
            for (publicKey in signingPubKeys.expandedCompositeKeys) {
                val privateKey = serviceHub.keyManagementService.toPrivate(publicKey)
                ptx.signWith(KeyPair(publicKey, privateKey))
            }

            return ptx.toSignedTransaction(checkSufficientSignatures = false)
        }

        @Suspendable protected abstract fun validateHandshake(handshake: Handshake<U>): Handshake<U>
        @Suspendable protected abstract fun assembleSharedTX(handshake: Handshake<U>): Pair<TransactionBuilder, List<PublicKey>>
    }

    @CordaSerializable
    data class AutoOffer(val notary: Party, val dealBeingOffered: DealState)

    /**
     * One side of the flow for inserting a pre-agreed deal.
     */
    open class Instigator(override val otherParty: Party,
                          override val payload: AutoOffer,
                          override val myKeyPair: KeyPair,
                          override val progressTracker: ProgressTracker = Primary.tracker()) : Primary() {

        override val notaryNode: NodeInfo get() =
        serviceHub.networkMapCache.notaryNodes.filter { it.notaryIdentity == payload.notary }.single()
    }

    /**
     * One side of the flow for inserting a pre-agreed deal.
     */
    open class Acceptor(override val otherParty: Party,
                        override val progressTracker: ProgressTracker = Secondary.tracker()) : Secondary<AutoOffer>() {

        override fun validateHandshake(handshake: Handshake<AutoOffer>): Handshake<AutoOffer> {
            // What is the seller trying to sell us?
            val autoOffer = handshake.payload
            val deal = autoOffer.dealBeingOffered
            logger.trace { "Got deal request for: ${deal.ref}" }
            return handshake.copy(payload = autoOffer.copy(dealBeingOffered = deal))
        }

        override fun assembleSharedTX(handshake: Handshake<AutoOffer>): Pair<TransactionBuilder, List<PublicKey>> {
            val deal = handshake.payload.dealBeingOffered
            val ptx = deal.generateAgreement(handshake.payload.notary)

            // And add a request for timestamping: it may be that none of the contracts need this! But it can't hurt
            // to have one.
            ptx.setTime(serviceHub.clock.instant(), 30.seconds)
            return Pair(ptx, arrayListOf(deal.parties.single { it == serviceHub.myInfo.legalIdentity as AbstractParty }.owningKey))
        }
    }
}
