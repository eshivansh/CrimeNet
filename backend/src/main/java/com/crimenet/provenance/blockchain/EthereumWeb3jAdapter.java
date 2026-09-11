package com.crimenet.provenance.blockchain;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Web3j adapter for EVM chains, calling the DocumentProvenanceAnchor contract.
 *
 * <p>Three things changed here, all of them load-bearing for the tamper-evidence claim:
 *
 * <p><b>No fallback.</b> Every exception used to be caught and delegated to an in-memory
 * {@code ConcurrentHashMap}, while {@code getAdapterType()} still reported
 * {@code ETHEREUM_WEB3J}. With the RPC unreachable, the "external, independently
 * controlled" anchor was a map in the same process, written and read by the code it was
 * supposed to check — and after a restart every such batch reported a mismatch,
 * indistinguishable from real tampering. A failure is now reported as a failure.
 *
 * <p><b>Receipts are awaited.</b> {@code sendTransaction} returns a hash for a transaction
 * that may revert, run out of gas, or be dropped. Because {@code anchorRoot} is
 * {@code onlyOwner} and requires an empty slot, a front-run on the batch number made
 * CrimeNet's transaction revert while the batch was still recorded as anchored — and the
 * slot was then permanently occupied, so the correct root could never be anchored.
 *
 * <p><b>One client, one chain ID.</b> A {@code Web3j} instance was built per call and never
 * shut down, leaking a dispatcher thread pool and connection pool each time; and the
 * two-argument {@code RawTransactionManager} defaults to {@code ChainId.NONE}, producing
 * pre-EIP-155 transactions with no replay protection.
 */
@Slf4j
@Component("ethereumWeb3jAdapter")
public class EthereumWeb3jAdapter implements BlockchainAdapter {

    public static final String ADAPTER_TYPE = "ETHEREUM_WEB3J";

    private final boolean enabled;
    private final String rpcUrl;
    private final String contractAddress;
    private final long chainId;
    private final int confirmationBlocks;
    private final int confirmationTimeoutSeconds;

    private final Web3j web3j;
    private final Credentials credentials;

    public EthereumWeb3jAdapter(
            @Value("${blockchain.enabled:true}") boolean enabled,
            @Value("${blockchain.rpc-url:http://localhost:8545}") String rpcUrl,
            // No default. An anchoring key is a signing credential; the previous default
            // was the publicly documented Hardhat account #0, so the adapter would happily
            // start with a key every attacker already has.
            @Value("${blockchain.private-key}") String privateKey,
            @Value("${blockchain.contract-address}") String contractAddress,
            @Value("${blockchain.chain-id:80002}") long chainId,
            @Value("${crimenet.provenance.confirmation-blocks:64}") int confirmationBlocks,
            @Value("${crimenet.provenance.confirmation-timeout-seconds:180}") int confirmationTimeoutSeconds
    ) {
        this.enabled = enabled;
        this.rpcUrl = rpcUrl;
        this.contractAddress = contractAddress;
        this.chainId = chainId;
        this.confirmationBlocks = confirmationBlocks;
        this.confirmationTimeoutSeconds = confirmationTimeoutSeconds;

        if (enabled) {
            if (privateKey == null || privateKey.isBlank()) {
                throw new IllegalStateException(
                        "blockchain.private-key is required when blockchain.enabled=true. "
                                + "Set BLOCKCHAIN_PRIVATE_KEY, or disable anchoring.");
            }
            this.web3j = Web3j.build(new HttpService(rpcUrl));
            this.credentials = Credentials.create(privateKey);
            log.info("Blockchain anchoring enabled: chainId={}, contract={}, anchoring address={}",
                    chainId, contractAddress, credentials.getAddress());
        } else {
            this.web3j = null;
            this.credentials = null;
            log.warn("Blockchain anchoring is DISABLED. Merkle batches will not be externally anchored.");
        }
    }

    @PreDestroy
    void shutdown() {
        if (web3j != null) {
            web3j.shutdown();
        }
    }

    @Override
    public synchronized AnchorOutcome anchorMerkleRoot(long batchNumber, String merkleRoot, int eventCount) {
        if (!enabled) {
            return AnchorOutcome.failed(ADAPTER_TYPE, null, "Blockchain anchoring is disabled");
        }

        String txHash = null;
        try {
            // RawTransactionManager fetches a pending nonce per send, so concurrent
            // anchors collide and one transaction is silently dropped. This method is
            // synchronized and the scheduled job is single-threaded, so sends serialise.
            RawTransactionManager txManager = new RawTransactionManager(
                    web3j, credentials, chainId,
                    new PollingTransactionReceiptProcessor(
                            web3j, 3000L, confirmationTimeoutSeconds * 1000 / 3000));

            Function function = new Function(
                    "anchorRoot",
                    Arrays.asList(
                            new Uint256(BigInteger.valueOf(batchNumber)),
                            new Bytes32(Numeric.hexStringToByteArray(toBytes32(merkleRoot))),
                            new Uint256(BigInteger.valueOf(eventCount))
                    ),
                    Collections.emptyList()
            );

            EthSendTransaction response = txManager.sendTransaction(
                    DefaultGasProvider.GAS_PRICE,
                    DefaultGasProvider.GAS_LIMIT,
                    contractAddress,
                    FunctionEncoder.encode(function),
                    BigInteger.ZERO
            );

            if (response.hasError()) {
                String reason = response.getError().getMessage();
                log.error("ANCHOR_FAILED batch {}: node rejected the transaction: {}", batchNumber, reason);
                return AnchorOutcome.failed(ADAPTER_TYPE, null, "Node rejected the transaction: " + reason);
            }

            txHash = response.getTransactionHash();

            TransactionReceipt receipt = awaitReceipt(txHash);
            if (receipt == null) {
                return AnchorOutcome.failed(ADAPTER_TYPE, txHash,
                        "No receipt within " + confirmationTimeoutSeconds + "s; the transaction may still be pending");
            }
            if (!receipt.isStatusOK()) {
                // A revert here usually means the batch slot is already occupied, which is
                // what a front-run on the batch number looks like.
                log.error("ANCHOR_REVERTED batch {}: tx {} mined in block {} with status {}",
                        batchNumber, txHash, receipt.getBlockNumber(), receipt.getStatus());
                return AnchorOutcome.failed(ADAPTER_TYPE, txHash,
                        "Transaction reverted (status " + receipt.getStatus() + "). The batch slot may already be anchored.");
            }

            if (!awaitConfirmations(receipt.getBlockNumber())) {
                return AnchorOutcome.failed(ADAPTER_TYPE, txHash,
                        "Mined in block " + receipt.getBlockNumber() + " but did not reach "
                                + confirmationBlocks + " confirmations within the timeout");
            }

            // Read the anchor back before claiming it. The write is only real if the chain agrees.
            VerificationOutcome readBack = verifyAnchor(batchNumber, merkleRoot);
            if (!readBack.valid()) {
                log.error("ANCHOR_READBACK_FAILED batch {}: tx {} confirmed but verifyRoot says {}",
                        batchNumber, txHash, readBack.status());
                return AnchorOutcome.failed(ADAPTER_TYPE, txHash,
                        "Confirmed on chain but read-back returned " + readBack.status() + ": " + readBack.detail());
            }

            log.info("ANCHORED batch {} in block {} — tx {}", batchNumber, receipt.getBlockNumber(), txHash);
            return AnchorOutcome.confirmed(ADAPTER_TYPE, txHash, receipt.getBlockNumber().longValue());

        } catch (Exception e) {
            log.error("ANCHOR_FAILED batch {} against {}: {}", batchNumber, rpcUrl, e.getMessage());
            return AnchorOutcome.failed(ADAPTER_TYPE, txHash, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    @Override
    public VerificationOutcome verifyAnchor(long batchNumber, String merkleRoot) {
        if (!enabled) {
            return VerificationOutcome.unavailable(ADAPTER_TYPE, "Blockchain anchoring is disabled");
        }

        try {
            Function function = new Function(
                    "verifyRoot",
                    Arrays.asList(
                            new Uint256(BigInteger.valueOf(batchNumber)),
                            new Bytes32(Numeric.hexStringToByteArray(toBytes32(merkleRoot)))
                    ),
                    Arrays.asList(
                            new TypeReference<Bool>() {},
                            new TypeReference<Uint256>() {},
                            new TypeReference<Address>() {}
                    )
            );

            EthCall ethCall = web3j.ethCall(
                    Transaction.createEthCallTransaction(
                            credentials.getAddress(), contractAddress, FunctionEncoder.encode(function)),
                    DefaultBlockParameterName.LATEST
            ).send();

            if (ethCall.hasError()) {
                return VerificationOutcome.unavailable(ADAPTER_TYPE,
                        "Node returned an error: " + ethCall.getError().getMessage());
            }
            if (ethCall.getValue() == null || "0x".equals(ethCall.getValue())) {
                return VerificationOutcome.unavailable(ADAPTER_TYPE,
                        "Empty response from the contract call; the node may be out of sync");
            }

            List<Type> values = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
            if (values.size() < 3) {
                return VerificationOutcome.unavailable(ADAPTER_TYPE, "Malformed response from verifyRoot");
            }

            boolean matches = values.get(0) instanceof Bool b && b.getValue();
            // timestamp and anchoredBy used to be decoded and thrown away, so an anchor
            // written by a stolen owner key still verified as valid.
            BigInteger timestamp = values.get(1) instanceof Uint256 t ? t.getValue() : BigInteger.ZERO;
            String anchoredBy = values.get(2) instanceof Address a ? a.getValue() : null;

            if (timestamp.signum() == 0) {
                return new VerificationOutcome(VerificationOutcome.Status.NOT_ANCHORED, ADAPTER_TYPE,
                        null, null, "No anchor exists on chain for batch " + batchNumber);
            }

            Instant anchoredAt = Instant.ofEpochSecond(timestamp.longValue());

            if (!matches) {
                return new VerificationOutcome(VerificationOutcome.Status.MISMATCH, ADAPTER_TYPE,
                        anchoredBy, anchoredAt,
                        "An anchor exists for batch " + batchNumber + " but the root does not match");
            }

            String expectedAnchor = credentials.getAddress();
            if (anchoredBy != null && !anchoredBy.equalsIgnoreCase(expectedAnchor)) {
                log.warn("ANCHOR_FOREIGN_WRITER batch {}: anchored by {} rather than {}",
                        batchNumber, anchoredBy, expectedAnchor);
                return new VerificationOutcome(VerificationOutcome.Status.MISMATCH, ADAPTER_TYPE,
                        anchoredBy, anchoredAt,
                        "The root matches, but it was anchored by " + anchoredBy
                                + " rather than the configured anchoring address " + expectedAnchor);
            }

            return new VerificationOutcome(VerificationOutcome.Status.VERIFIED, ADAPTER_TYPE,
                    anchoredBy, anchoredAt, "On-chain root matches");

        } catch (Exception e) {
            // Unreachable is not the same as invalid, and must never be reported as tampering.
            return VerificationOutcome.unavailable(ADAPTER_TYPE,
                    "Could not reach " + rpcUrl + ": " + e.getMessage());
        }
    }

    @Override
    public String getAdapterType() {
        return ADAPTER_TYPE;
    }

    private TransactionReceipt awaitReceipt(String txHash) throws Exception {
        long deadline = System.currentTimeMillis() + confirmationTimeoutSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            Optional<TransactionReceipt> receipt =
                    web3j.ethGetTransactionReceipt(txHash).send().getTransactionReceipt();
            if (receipt.isPresent()) {
                return receipt.get();
            }
            Thread.sleep(3000L);
        }
        return null;
    }

    private boolean awaitConfirmations(BigInteger minedBlock) throws Exception {
        if (confirmationBlocks <= 0) {
            return true;
        }
        BigInteger target = minedBlock.add(BigInteger.valueOf(confirmationBlocks));
        long deadline = System.currentTimeMillis() + confirmationTimeoutSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            BigInteger head = web3j.ethBlockNumber().send().getBlockNumber();
            if (head.compareTo(target) >= 0) {
                return true;
            }
            Thread.sleep(3000L);
        }
        return false;
    }

    /**
     * Right-padding silently zero-extended a short root and truncated a long one, anchoring
     * a value that was not the computed root. A root is 32 bytes or it is an error.
     */
    private String toBytes32(String hex) {
        String clean = hex == null ? "" : hex.startsWith("0x") ? hex.substring(2) : hex;
        if (clean.length() != 64 || !clean.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalArgumentException(
                    "Merkle root must be exactly 64 hex characters (32 bytes); got " + clean.length());
        }
        return "0x" + clean;
    }
}
