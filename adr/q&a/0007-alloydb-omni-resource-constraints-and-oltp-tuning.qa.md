# ADR 0007: AlloyDB Omni Resource Constraints & OLTP Tuning — Staff Interview Q&A

This document contains 25 in-depth architectural interview questions and their corresponding meta-questions based on [ADR 0007: AlloyDB Omni Resource Constraints, Memory Optimization & OLTP Tuning](../0007-alloydb-omni-resource-constraints-and-oltp-tuning.md).

---

### Question 1
**The Question:**  
During high-load testing and database migration execution on Google AlloyDB Omni, database connections were abruptly terminated with the warning: `[g_term_it.cc:163] Memory critically low. Attempting termination of high memory footprint backend (pid=245 RSS=14MB) to avoid OOM`. What is the internal architecture of AlloyDB Omni's proactive termination watchdog (`g_term_it.cc`), why does it kill backends with tiny RSS footprints like 14MB, and how does this differ from the Linux kernel's standard OOM killer?

**The Meta-Question:**  
The interviewer is probing your systems-level knowledge of database internals, container resource constraints, and specialized cloud database forks. They want to see if you understand that standard PostgreSQL relies on the Linux kernel OOM killer, which crashes the entire postmaster process and forces a painful WAL recovery. AlloyDB Omni includes an aggressive in-process watchdog (`g_term_it.cc`) that monitors host memory pressure and swap thrashing, proactively killing individual client query backends to save the main database server from crashing, even if the backend itself only holds a few megabytes of memory.

---

### Question 2
**The Question:**  
AlloyDB Omni includes Google's analytical Columnar Engine by default. In an authentication microservice whose workload consists purely of OLTP queries (indexed single-row user lookups, token inserts, and audit log writes), why was disabling the Columnar Engine (`google_columnar_engine.enabled=off`) an essential architectural decision, and what memory buffers are eliminated by turning it off?

**The Meta-Question:**  
The interviewer is evaluating your workload classification instincts: distinguishing between Online Analytical Processing (OLAP) and Online Transaction Processing (OLTP). The Columnar Engine allocates massive in-memory columnar projection buffers, vectorized execution memory, and AI/ML vector caches (often claiming 30% to 80% of host RAM). Because authentication never executes large analytical aggregations across millions of rows, reserving gigabytes for columnar buffers wastes memory and starves the OLTP buffer pool, triggering premature OOM terminations.

---

### Question 3
**The Question:**  
In our tuned configuration, we explicitly right-sized PostgreSQL's `shared_buffers` to 256MB–512MB instead of allowing AlloyDB to dynamically reserve default memory allocations. In a 4GB RAM container hosting an authentication database, what are the principles for sizing `shared_buffers` relative to the host operating system's page cache and per-connection `work_mem`?

**The Meta-Question:**  
The interviewer is checking your relational database memory sizing expertise. In PostgreSQL architecture, `shared_buffers` is typically sized between 25% and 40% of available RAM. Sizing `shared_buffers` too high (e.g., 80%) starves the OS page cache (which PostgreSQL relies on for double-buffering) and leaves insufficient memory for per-query `work_mem`, maintenance operations, and socket buffers, causing the OS to enter swap thrashing under high concurrency.

---

### Question 4
**The Question:**  
Why did we explicitly configure Docker's POSIX shared memory size (`shm_size: '1gb'`) in `docker-compose.yml`, and what failure modes occur in PostgreSQL parallel query execution and vacuum operations if Docker runs with its default `shm_size` of 64MB?

**The Meta-Question:**  
The interviewer is testing your deep container virtualization and IPC shared memory knowledge. Docker containers default to a tiny 64MB `/dev/shm` partition. Modern PostgreSQL relies heavily on POSIX shared memory for parallel workers (`max_parallel_workers_per_gather`), shared hash joins, and parallel index builds. If `/dev/shm` is capped at 64MB, complex queries or parallel migrations instantly fail with `could not resize shared memory segment: No space left on device`.

---

### Question 5
**The Question:**  
We capped `max_connections` at 100 in the PostgreSQL configuration while setting the application connection pool limit to 20. Why is setting `max_connections` to excessively high numbers (such as 1,000 or 5,000) a severe anti-pattern in PostgreSQL, and how does connection count directly inflate memory consumption?

**The Meta-Question:**  
The interviewer is testing your understanding of PostgreSQL's process-based connection architecture versus thread-per-connection models. Each PostgreSQL connection spawns an independent operating system process that consumes 5MB to 10MB of base RAM, plus per-connection `work_mem`, `temp_buffers`, and lock table memory. One thousand idle connections can consume 10GB of RAM doing zero work! Restricting `max_connections` and pairing it with connection pooling (e.g., PgBouncer or an application pool of 20) keeps CPU context switching minimal and prevents memory exhaustion.

---

### Question 6
**The Question:**  
In addition to disabling the columnar engine, we disabled `google_ml_integration`, `google_db_advisor`, and `google_storage.replay_prefetcher`. What background worker threads do these proprietary extensions spawn, and how do background workers complicate memory management in multi-container developer laptops or constrained CI runners?

**The Meta-Question:**  
The interviewer is assessing your experience with cloud-native database extensions and background daemon overhead. These extensions spawn background analyzer threads that continually scan query history, pre-calculate index recommendations, and pre-load storage blocks. In constrained environments running sibling containers (Kafka, Redis, Tempo, Auth app), these unthrottled background threads consume CPU cycles and cause memory spikes that trigger `g_term_it` watchdog backend terminations during automated migrations.

---

### Question 7
**The Question:**  
During automated migrations, our database migration script was interrupted with `[db-migrate] connection terminated unexpectedly`. How did our migration runner implement automated retry logic and exponential backoff to recover from transient backend terminations without corrupting migration state?

**The Meta-Question:**  
The interviewer is testing your resilient migration runner design. They want to hear that migrations must be strictly transactional (wrapped in `BEGIN ... COMMIT` where supported in PostgreSQL DDL) so that a severed connection automatically rolls back uncommitted changes. A robust runner must catch connection drops, re-establish the connection pool with exponential backoff (e.g., 3 retries), and query a `schema_migrations` lock table to safely resume without applying partial schema mutations.

---

### Question 8
**The Question:**  
How does PostgreSQL's `work_mem` setting interact with complex analytical queries versus simple OLTP queries, and what formula would you use to calculate safe `work_mem` values in our 4GB container with `max_connections = 100`?

**The Meta-Question:**  
The interviewer is evaluating your database configuration math. They want to verify that you know `work_mem` is allocated *per sort or hash operation*, meaning a single complex query with multiple joins and sorts can allocate multiple `work_mem` blocks! The rule of thumb for safe `work_mem` is:
$$\text{workMem} \approx \frac{\text{Total Available RAM} - \text{sharedBuffers} - \text{OS overhead}}{\text{maxConnections} \times \text{averageSortsPerQuery}}$$
In a 4GB container with `shared_buffers = 512MB` and 100 connections, setting `work_mem = 16MB` to `32MB` ensures fast in-memory sorts while preventing concurrent queries from driving the host into out-of-memory collapse.

---

### Question 9
**The Question:**  
In our Docker Compose environment, multiple sibling services run simultaneously: the auth database, another 2GB AlloyDB instance (`llmobs-alloydb-db`), Kafka, Redis, and Tempo. How do Linux cgroups memory limits (`deploy.resources.limits.memory`) prevent one runaway database container from triggering the host kernel OOM killer and killing adjacent infrastructure?

**The Meta-Question:**  
The interviewer is probing your knowledge of Linux control groups (cgroups v2) and container isolation. Without cgroups limits, a memory leak or buffer spike in one container consumes all host RAM and swap space, forcing the Linux kernel to invoke `oom-killer`, which often kills critical sibling processes like Kafka or Docker daemon. Explicit cgroup limits enforce a hard ceiling: if a container breaches its quota, the kernel throttles or terminates processes *only within that container's cgroup*, leaving sibling containers completely unharmed.

---

### Question 10
**The Question:**  
What is the difference between PostgreSQL `VACUUM`, `autovacuum`, and `VACUUM FULL`, and how does high-frequency token insertion and revocation in `auth_api_keys` cause dead tuple bloat if autovacuum is misconfigured?

**The Meta-Question:**  
The interviewer is testing your understanding of Multi-Version Concurrency Control (MVCC) and table bloat in PostgreSQL. Every `UPDATE` or `DELETE` creates a dead tuple that is not immediately removed. If an authentication system updates `last_used_at_ms` or marks revoked tokens thousands of times a day, dead tuples accumulate rapidly. Autovacuum must be tuned (`autovacuum_vacuum_scale_factor = 0.05`) to clean dead tuples continuously in the background, avoiding index bloat and table degradation without requiring table-locking `VACUUM FULL` operations.

---

### Question 11
**The Question:**  
Why did we choose Google AlloyDB Omni for our service rather than vanilla open-source PostgreSQL 16? What enterprise storage engine benefits does AlloyDB Omni retain even with the Columnar Engine disabled?

**The Meta-Question:**  
The interviewer is evaluating your awareness of modern cloud database architectures. Even with columnar buffers disabled, AlloyDB Omni features Google's optimized database engine: a faster write-ahead log (WAL) engine, compute-storage separation readiness, enhanced parallel query execution, and high-performance columnar offloading that can be selectively enabled for heavy reporting read-replicas while keeping the primary transactional engine pure OLTP.

---

### Question 12
**The Question:**  
If an OLTP query on `auth_users` takes longer than expected due to an unindexed column, how do we configure PostgreSQL statement timeouts (`statement_timeout`) to ensure that runaway queries do not hold locks and exhaust database connections?

**The Meta-Question:**  
The interviewer is assessing your database resilience and circuit-breaker patterns. Unbounded query execution can lead to connection pool starvation. Setting a global or per-user `statement_timeout` (e.g., `SET statement_timeout = '3000ms'`) ensures that any query taking longer than 3 seconds is automatically aborted by the database engine, returning an error to the application and freeing the connection back to the pool.

---

### Question 13
**The Question:**  
How does the Node.js application connection pool size (set to 20 connections) interact with container CPU limits? Why is setting the application pool size to match the number of available CPU cores (multiplied by a small factor) better than creating hundreds of connections?

**The Meta-Question:**  
The interviewer is testing your understanding of queueing theory and Little's Law in database connection pooling. PostgreSQL cannot execute more concurrent queries than the host machine has physical CPU cores and I/O channels. Setting a pool size of 20 connections on an 8-core host ensures high concurrency without CPU context-switching thrashing, keeping query queues in memory and delivering higher overall transaction throughput than a pool of 200 contending connections.

---

### Question 14
**The Question:**  
When our database restarts, the `shared_buffers` cache is initially empty (a cold cache), causing early queries to hit disk and execute slowly. What extension or mechanism in PostgreSQL pre-warms `shared_buffers` after a restart to restore peak read performance immediately?

**The Meta-Question:**  
The interviewer is checking your high-availability database operational techniques. They want to hear about `pg_prewarm` and `pg_buffercache`. `pg_prewarm` can automatically dump the state of `shared_buffers` prior to shutdown and reload high-frequency index and table blocks into RAM upon startup, eliminating cold-cache latency spikes during rolling deployments.

---

### Question 15
**The Question:**  
How does PostgreSQL handle Write-Ahead Logging (WAL) flushes on transactional commits (`synchronous_commit`), and what are the durability and latency trade-offs of setting `synchronous_commit = off` for non-critical audit log writes?

**The Meta-Question:**  
The interviewer is probing your ACID tuning and durability trade-offs. By default, `synchronous_commit = on` blocks until WAL records are physically flushed to disk (fsync), guaranteeing zero data loss on crashes at the cost of disk write latency. For high-volume, non-critical audit logs or usage telemetry, setting `synchronous_commit = off` (asynchronous commit) acknowledges commits immediately, flushing WAL in batches every `wal_writer_delay` (200ms), delivering up to 3x higher write throughput while accepting a bounded 200ms data-loss window on sudden power failure.

---

### Question 16
**The Question:**  
In our multi-tenant schema, we created partial indexes such as `CREATE INDEX idx_auth_users_active ON auth_users(email) WHERE deleted_at IS NULL`. How do partial indexes optimize memory consumption in `shared_buffers` compared to standard full-table B-tree indexes?

**The Meta-Question:**  
The interviewer is testing your index memory optimization skills. A standard B-tree index indexes every single row in the table, including soft-deleted users and deactivated accounts, consuming significant RAM in `shared_buffers`. A partial index indexing only active rows (`WHERE deleted_at IS NULL`) drastically reduces index file size on disk and in memory, ensuring that only active, frequently searched records occupy the database buffer cache.

---

### Question 17
**The Question:**  
Suppose our database logs indicate high lock contention on `auth_users` during simultaneous user updates. What tools and system views inside PostgreSQL would you query to identify the blocking transaction, the lock type, and the exact query being executed?

**The Meta-Question:**  
The interviewer is evaluating your hands-on database troubleshooting and lock diagnosis capabilities. They want to hear you mention querying `pg_stat_activity` and `pg_locks` (or running `SELECT pg_blocking_pids(pid)`). You should explain joining `pg_locks` on transaction IDs or relation OIDs to see which backend holds the `RowExclusiveLock` or `AccessExclusiveLock` and inspecting `query` in `pg_stat_activity` to isolate the offending query.

---

### Question 18
**The Question:**  
What is the purpose of PostgreSQL's `checkpoint_completion_target` setting, and why should it be tuned to a high value (like 0.9) in production OLTP environments?

**The Meta-Question:**  
The interviewer is checking your understanding of PostgreSQL checkpointing and I/O smoothing. Checkpoints flush dirty shared buffers to disk. If `checkpoint_completion_target` is left at default (0.5), PostgreSQL attempts to complete all disk writes in the first 50% of the checkpoint window, creating massive I/O spikes that stall concurrent read/write queries. Setting it to 0.9 spreads disk writes smoothly across 90% of the interval, eliminating I/O latency spikes.

---

### Question 19
**The Question:**  
In our Docker configuration, we set `deploy.resources.limits.memory: 4G`. How should PostgreSQL's `effective_cache_size` be configured relative to this container limit, and what role does it play in the cost-based query planner?

**The Meta-Question:**  
The interviewer is testing your query planner optimization knowledge. `effective_cache_size` does not allocate memory; it provides an estimate to PostgreSQL's cost-based query planner of how much memory is available for caching data (including `shared_buffers` and the OS page cache). In a 4GB container with 512MB `shared_buffers`, setting `effective_cache_size = 3GB` encourages the planner to favor index scans over sequential scans because it expects indexes to remain cached in memory.

---

### Question 20
**The Question:**  
How does PostgreSQL's `pg_stat_statements` extension assist in identifying slow queries, high buffer churn, and missing indexes in our authentication service?

**The Meta-Question:**  
The interviewer is checking your continuous database performance monitoring practices. `pg_stat_statements` records execution count, total time, min/max/mean latency, and buffer hits/misses for all parameterized SQL statements. Querying it allows engineers to detect queries with high execution counts and low cache hit ratios, identifying which endpoints are causing high disk I/O and need new composite indexes.

---

### Question 21
**The Question:**  
If a database migration script hangs because an active transaction in another connection is holding a lock on `auth_users`, how does setting `lock_timeout` prevent database migrations from causing cascading connection pool exhaustion?

**The Meta-Question:**  
The interviewer is testing your zero-downtime deployment safety rules. When DDL statements (like `ALTER TABLE`) execute, they require an `AccessExclusiveLock`. If a long-running read query is active, the DDL waits behind it, and all subsequent read queries wait behind the DDL, queueing hundreds of requests and taking down the application! Setting `SET LOCAL lock_timeout = '2000ms'` ensures that if the migration cannot acquire the lock within 2 seconds, it aborts cleanly without blocking the connection pool.

---

### Question 22
**The Question:**  
Why did our database configuration disable `google_db_advisor` in the development and CI environments, and what are the trade-offs of enabling it in production?

**The Meta-Question:**  
The interviewer is testing your operational judgment regarding automated database advisors. While Google DB Advisor is valuable in production for analyzing live workload patterns and suggesting missing indexes, in development and ephemeral CI test runs it consumes memory, runs background sampling workers, and triggers `g_term_it` watchdog backend termination without providing any actionable value for short-lived test databases.

---

### Question 23
**The Question:**  
When configuring disk storage for an OLTP database in production cloud environments, what are the differences between Provisioned IOPS (like AWS EBS io2 or Google Hyperdisk Balanced) and standard burstable SSDs (gp3), and how does write latency directly impact sign-in response times?

**The Meta-Question:**  
The interviewer is assessing your storage infrastructure and cloud architecture depth. In an OLTP database, every transaction commit requires a synchronous WAL flush to disk. Burstable storage (gp2/gp3 with exhausted burst credits) experiences erratic write latency spikes (from 1ms to 50ms+), which directly degrades sign-in latency. Provisioned IOPS with guaranteed sub-millisecond write latency guarantees consistent, deterministic authentication response times under sustained load.

---

### Question 24
**The Question:**  
How do you monitor database connection pool health in our Node.js auth service, and what metrics indicate that the pool is saturated and requests are queueing for connections?

**The Meta-Question:**  
The interviewer is evaluating your application-to-database telemetry metrics. The critical metrics to expose via OpenTelemetry are:
1. `db.pool.total_connections`: Current allocated sockets.
2. `db.pool.idle_connections`: Available sockets.
3. `db.pool.waiting_requests`: Number of application requests waiting to acquire a connection.
4. `db.pool.acquire_time_ms`: Time spent waiting in the connection pool queue. A spike in waiting requests or acquire time indicates pool starvation requiring higher capacity or faster query optimization.

---

### Question 25
**The Question:**  
Looking critically at ADR 0007, what is the ultimate operational lesson learned from resolving the `g_term_it.cc` backend terminations, and what principle should guide future infrastructure container provisioning?

**The Meta-Question:**  
The interviewer is looking for engineering maturity, root-cause depth, and architectural synthesis. The core lesson is: **Never run enterprise multi-model databases with default out-of-the-box configurations in constrained multi-container environments.** An architect must explicitly profile the application's true workload (pure OLTP vs. analytical OLAP), disable unneeded analytical and AI subsystems, right-size buffer pools, and establish strict container cgroup resource limits to ensure deterministic stability and prevent proactive watchdog terminations.
