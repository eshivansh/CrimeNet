package com.crimenet.provenance.blockchain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Selects the anchoring adapter once, at startup, rather than per call.
 *
 * <p>The selection used to happen inside {@link EthereumWeb3jAdapter}'s catch blocks, which
 * meant a transient RPC failure silently downgraded the tamper-evidence guarantee while
 * still reporting the real adapter's name. Which ledger is in use is a deployment decision
 * and is logged as one.
 */
@Slf4j
@Configuration
public class BlockchainConfig {

    @Bean
    @Primary
    public BlockchainAdapter blockchainAdapter(
            EthereumWeb3jAdapter ethereumWeb3jAdapter,
            ObjectProvider<MockBlockchainAdapter> mockAdapterProvider,
            @Value("${blockchain.enabled:true}") boolean enabled) {

        if (enabled) {
            return ethereumWeb3jAdapter;
        }

        MockBlockchainAdapter mock = mockAdapterProvider.getIfAvailable();
        if (mock == null) {
            // The mock is @Profile("!prod"), so this is the prod path with anchoring off.
            throw new IllegalStateException(
                    "blockchain.enabled=false is not permitted in the prod profile: there would be "
                            + "no external anchor, and the audit chain would attest only to itself.");
        }
        log.warn("Blockchain anchoring is disabled. Using the in-memory stand-in — batches will "
                + "carry anchorType={} and provide NO external tamper evidence.",
                MockBlockchainAdapter.ADAPTER_TYPE);
        return mock;
    }
}
