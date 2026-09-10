package com.crimenet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.util.TimeZone;

@SpringBootApplication
@EnableScheduling
// Transaction advice normally sits INNERMOST (Ordered.LOWEST_PRECEDENCE), which would put
// RlsAspect (@Order(100)) outside it: the aspect would run before the transaction began,
// find no active transaction, and skip binding app.current_user_id on exactly the
// outermost @Transactional method where it matters. Row-level security then evaluated
// with no bound user on every top-level call.
//
// Pinning transaction advice to order 0 makes it the outer advice, so RlsAspect runs
// inside an already-started transaction and its transaction-scoped set_config() applies to
// the queries that follow.
@EnableTransactionManagement(order = 0)
public class CrimeNetApplication {

    static {
        // The PostgreSQL JDBC driver sends the JVM's default zone in its startup packet,
        // before any SQL can run. On Indian Windows hosts that zone is the legacy alias
        // "Asia/Calcutta", which PostgreSQL 16 rejects outright:
        //   FATAL: invalid value for parameter "TimeZone": "Asia/Calcutta"
        // Pinning the JVM to UTC avoids that and matches hibernate.jdbc.time_zone=UTC,
        // so every timestamp is stored and compared in UTC. This runs in a static
        // initialiser so it applies however the app is launched.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    }

    public static void main(String[] args) {
        SpringApplication.run(CrimeNetApplication.class, args);
    }
}
