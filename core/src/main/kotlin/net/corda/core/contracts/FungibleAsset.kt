package net.corda.core.contracts

import net.corda.core.flows.FlowException
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import java.security.PublicKey
import java.util.*

class InsufficientBalanceException(val amountMissing: Amount<*>) : FlowException("Insufficient balance, missing $amountMissing")

/**
 * Interface for contract states representing assets which are fungible, countable and issued by a
 * specific party. States contain assets which are equivalent (such as cash of the same currency),
 * so records of their existence can be merged or split as needed where the issuer is the same. For
 * instance, dollars issued by the Fed are fungible and countable (in cents), barrels of West Texas
 * crude are fungible and countable (oil from two small containers can be poured into one large
 * container), shares of the same class in a specific company are fungible and countable, and so on.
 *
 * See [Cash] for an example contract that implements currency using state objects that implement
 * this interface.
 *
 * @param T a type that represents the asset in question. This should describe the basic type of the asset
 * (GBP, USD, oil, shares in company <X>, etc.) and any additional metadata (issuer, grade, class, etc.).
 */
interface FungibleAsset<T : Any> : OwnableState {
    companion object {
        val log = loggerFor<FungibleAsset<*>>()


        /**
         * Generate a transaction that moves an amount of currency to the given pubkey.
         *
         * Note: an [Amount] of [Currency] is only fungible for a given Issuer Party within a [FungibleAsset]
         *
         * @param tx A builder, which may contain inputs, outputs and commands already. The relevant components needed
         *           to move the cash will be added on top.
         * @param amount How much currency to send.
         * @param to a key of the recipient.
         * @param acceptableStates a list of acceptable input states to use.
         * @param deriveState a function to derive an output state based on an input state, amount for the output
         * and public key to pay to.
         * @return A [Pair] of the same transaction builder passed in as [tx], and the list of keys that need to sign
         *         the resulting transaction for it to be valid.
         * @throws InsufficientBalanceException when a cash spending transaction fails because
         *         there is insufficient quantity for a given currency (and optionally set of Issuer Parties).
         */
        @Throws(InsufficientBalanceException::class)
        fun <S : FungibleAsset<T>, T: Any> generateSpend(tx: TransactionBuilder,
                                                         amount: Amount<T>,
                                                         to: PublicKey,
                                                         acceptableStates: List<StateAndRef<S>>,
                                                         deriveState: (TransactionState<S>, Amount<Issued<T>>, PublicKey) -> TransactionState<S>,
                                                         generateMoveCommand: () -> CommandData): Pair<TransactionBuilder, List<PublicKey>> {
            // Discussion
            //
            // This code is analogous to the Wallet.send() set of methods in bitcoinj, and has the same general outline.
            //
            // First we must select a set of asset states (which for convenience we will call 'coins' here, as in bitcoinj).
            // The input states can be considered our "vault", and may consist of different products, and with different
            // issuers and deposits.
            //
            // Coin selection is a complex problem all by itself and many different approaches can be used. It is easily
            // possible for different actors to use different algorithms and approaches that, for example, compete on
            // privacy vs efficiency (number of states created). Some spends may be artificial just for the purposes of
            // obfuscation and so on.
            //
            // Having selected input states of the correct asset, we must craft output states for the amount we're sending and
            // the "change", which goes back to us. The change is required to make the amounts balance. We may need more
            // than one change output in order to avoid merging assets from different deposits. The point of this design
            // is to ensure that ledger entries are immutable and globally identifiable.
            //
            // Finally, we add the states to the provided partial transaction.

            // TODO: We should be prepared to produce multiple transactions spending inputs from
            // different notaries, or at least group states by notary and take the set with the
            // highest total value.

            // notary may be associated with locked state only
            tx.notary = acceptableStates.firstOrNull()?.state?.notary

            val (gathered, gatheredAmount) = gatherCoins(acceptableStates, amount)

            val takeChangeFrom = gathered.firstOrNull()
            val change = if (takeChangeFrom != null && gatheredAmount > amount) {
                Amount(gatheredAmount.quantity - amount.quantity, takeChangeFrom.state.data.amount.token)
            } else {
                null
            }
            val keysUsed = gathered.map { it.state.data.owner }

            val states = gathered.groupBy { it.state.data.amount.token.issuer }.map {
                val coins = it.value
                val totalAmount = coins.map { it.state.data.amount }.sumOrThrow()
                deriveState(coins.first().state, totalAmount, to)
            }.sortedBy { it.data.amount.quantity }

            val outputs = if (change != null) {
                // Just copy a key across as the change key. In real life of course, this works but leaks private data.
                // In bitcoinj we derive a fresh key here and then shuffle the outputs to ensure it's hard to follow
                // value flows through the transaction graph.
                val existingOwner = gathered.first().state.data.owner
                // Add a change output and adjust the last output downwards.
                states.subList(0, states.lastIndex) +
                        states.last().let {
                            val spent = it.data.amount.withoutIssuer() - change.withoutIssuer()
                            deriveState(it, Amount(spent.quantity, it.data.amount.token), it.data.owner)
                        } +
                        states.last().let {
                            deriveState(it, Amount(change.quantity, it.data.amount.token), existingOwner)
                        }
            } else states

            for (state in gathered) tx.addInputState(state)
            for (state in outputs) tx.addOutputState(state)

            // What if we already have a move command with the right keys? Filter it out here or in platform code?
            tx.addCommand(generateMoveCommand(), keysUsed)

            return Pair(tx, keysUsed)
        }

        /**
         * Gather assets from the given list of states, sufficient to match or exceed the given amount.
         *
         * @param acceptableCoins list of states to use as inputs.
         * @param amount the amount to gather states up to.
         * @throws InsufficientBalanceException if there isn't enough value in the states to cover the requested amount.
         */
        @Throws(InsufficientBalanceException::class)
        private fun <S : FungibleAsset<T>, T : Any> gatherCoins(acceptableCoins: Collection<StateAndRef<S>>,
                                                                amount: Amount<T>): Pair<ArrayList<StateAndRef<S>>, Amount<T>> {
            require(amount.quantity > 0) { "Cannot gather zero coins" }
            val gathered = arrayListOf<StateAndRef<S>>()
            var gatheredAmount = Amount(0, amount.token)
            for (c in acceptableCoins) {
                if (gatheredAmount >= amount) break
                gathered.add(c)
                gatheredAmount += Amount(c.state.data.amount.quantity, amount.token)
            }

            if (gatheredAmount < amount) {
                log.trace { "Insufficient balance: requested $amount, available $gatheredAmount" }
                throw InsufficientBalanceException(amount - gatheredAmount)
            }

            log.trace("Gathered coins: requested $amount, available $gatheredAmount, change: ${gatheredAmount - amount}")

            return Pair(gathered, gatheredAmount)
        }

        /**
         * Generate an transaction exiting fungible assets from the ledger.
         *
         * @param tx transaction builder to add states and commands to.
         * @param amountIssued the amount to be exited, represented as a quantity of issued currency.
         * @param assetStates the asset states to take funds from. No checks are done about ownership of these states, it is
         * the responsibility of the caller to check that they do not attempt to exit funds held by others.
         * @return the public key of the assets issuer, who must sign the transaction for it to be valid.
         */
        @Throws(InsufficientBalanceException::class)
        fun <S : FungibleAsset<T>, T: Any> generateExit(tx: TransactionBuilder, amountIssued: Amount<Issued<T>>,
                         assetStates: List<StateAndRef<S>>,
                         deriveState: (TransactionState<S>, Amount<Issued<T>>, PublicKey) -> TransactionState<S>,
                         generateMoveCommand: () -> CommandData,
                         generateExitCommand: (Amount<Issued<T>>) -> CommandData): PublicKey {
            val owner = assetStates.map { it.state.data.owner }.toSet().singleOrNull() ?: throw InsufficientBalanceException(amountIssued)
            val currency = amountIssued.token.product
            val amount = Amount(amountIssued.quantity, currency)
            var acceptableCoins = assetStates.filter { ref -> ref.state.data.amount.token == amountIssued.token }
            tx.notary = acceptableCoins.firstOrNull()?.state?.notary
            // TODO: We should be prepared to produce multiple transactions exiting inputs from
            // different notaries, or at least group states by notary and take the set with the
            // highest total value
            acceptableCoins = acceptableCoins.filter { it.state.notary == tx.notary }

            val (gathered, gatheredAmount) = gatherCoins(acceptableCoins, amount)
            val takeChangeFrom = gathered.lastOrNull()
            val change = if (takeChangeFrom != null && gatheredAmount > amount) {
                Amount(gatheredAmount.quantity - amount.quantity, takeChangeFrom.state.data.amount.token)
            } else {
                null
            }

            val outputs = if (change != null) {
                // Add a change output and adjust the last output downwards.
                listOf(deriveState(gathered.last().state, change, owner))
            } else emptyList()

            for (state in gathered) tx.addInputState(state)
            for (state in outputs) tx.addOutputState(state)
            tx.addCommand(generateMoveCommand(), gathered.map { it.state.data.owner })
            tx.addCommand(generateExitCommand(amountIssued), gathered.flatMap { it.state.data.exitKeys })
            return amountIssued.token.issuer.party.owningKey
        }
    }

    val amount: Amount<Issued<T>>
    /**
     * There must be an ExitCommand signed by these keys to destroy the amount. While all states require their
     * owner to sign, some (i.e. cash) also require the issuer.
     */
    val exitKeys: Collection<PublicKey>
    /** There must be a MoveCommand signed by this key to claim the amount */
    override val owner: PublicKey

    fun move(newAmount: Amount<Issued<T>>, newOwner: PublicKey): FungibleAsset<T>

    // Just for grouping
    interface Commands : CommandData {
        interface Move : MoveCommand, Commands

        /**
         * Allows new asset states to be issued into existence: the nonce ("number used once") ensures the transaction
         * has a unique ID even when there are no inputs.
         */
        interface Issue : IssueCommand, Commands

        /**
         * A command stating that money has been withdrawn from the shared ledger and is now accounted for
         * in some other way.
         */
        interface Exit<T : Any> : Commands {
            val amount: Amount<Issued<T>>
        }
    }
}

// Small DSL extensions.

/** Sums the asset states in the list, returning null if there are none. */
fun <T : Any> Iterable<ContractState>.sumFungibleOrNull() = filterIsInstance<FungibleAsset<T>>().map { it.amount }.sumOrNull()

/** Sums the asset states in the list, returning zero of the given token if there are none. */
fun <T : Any> Iterable<ContractState>.sumFungibleOrZero(token: Issued<T>) = filterIsInstance<FungibleAsset<T>>().map { it.amount }.sumOrZero(token)

