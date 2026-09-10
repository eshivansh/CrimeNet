package com.crimenet.provenance.blockchain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class BlockchainConfig {

    @Bean
    @Primary
    public BlockchainAdapter blockchainAdapter(EthereumWeb3jAdapter ethereumWeb3jAdapter) {
        return ethereumWeb3jAdapter;
    }
}
