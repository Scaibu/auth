# ADR 0010: Redis JTI Session Denylist & Adaptive Rate Limiting — Staff Interview Q&A

This document contains 25 in-depth architectural interview questions and their corresponding meta-questions based on [ADR 0010: Redis JTI-Based Session Denylist and Adaptive Login Rate Limiting Architecture](../0010-redis-jti-session-denylist-and-adaptive-login-rate-limiting.md).

---

### Question 1
**The Question:**  
In our authentication defense architecture, we implement a dual-track rate limiting system on `POST /api/v1/auth/sign-in`: one track keyed on the client IP address and the other keyed on the target email address. Why is hard-locking a user account based solely on failed attempts against their email address an architectural vulnerability, and how does the dual-track system prevent self-inflicted Denial of Service (DoS) attacks?

**The Meta-Question:**  
The interviewer is evaluating your threat modeling depth and understanding of account lockout abuse. A naive security policy that locks an account after 5 failed logins creates an immediate Denial-of-Service vector: an attacker can script 5 failed logins against `ceo@company.com` or every employee in a directory, locking out the entire executive team indefinitely! The dual-track model solves this: failed attempts against an email trigger progressive delays and CAPTCHA/Turnstile challenges without hard lockouts, while high-velocity IP subnets face hard HTTP 429 rate limit blocks.

---

### Question 2
**The Question:**  
When implementing sliding-window rate limiting in Redis, naive implementations execute multiple sequential Redis commands (`ZREMRANGEBYSCORE`, `ZADD`, `ZCARD`, `EXPIRE`), introducing race conditions and multiple network round-trips. How does our architecture ensure that sliding-window rate limit checks execute atomically in $O(1)$ network round-trips using Redis Lua scripts?

**The Meta-Question:**  
The interviewer is probing your Redis concurrency and atomicity mastery. Multiple independent commands allow concurrent requests from the same IP to interleave, causing inaccurate counter values. Executing a Lua script via `EVAL` or `EVALSHA` guarantees that the removal of expired timestamps, insertion of the current request timestamp, cardinality check, and TTL update execute as a single atomic unit on the single-threaded Redis engine, eliminating race conditions in a single network round-trip.

---

### Question 3
**The Question:**  
In our IP rate-limiting pipeline, how do we accurately extract the client's true IP address when the auth microservice sits behind layers of reverse proxies, load balancers, and Cloudflare? What security hazards arise from naively trusting the first IP in the `X-Forwarded-For` header?

**The Meta-Question:**  
The interviewer is testing your perimeter network security and header spoofing awareness. Any client can send an arbitrary `X-Forwarded-For: 1.1.1.1` header! If an application naively reads the first IP in `X-Forwarded-For`, an attacker can bypass IP rate limits entirely or spoof legitimate user IPs to trigger false-positive rate limit lockouts. The server must only trust `X-Forwarded-For` if it was appended by a verified, trusted proxy CIDR range (e.g., Traefik or Cloudflare ingress IPs), reading from the right-most trusted proxy boundary.

---

### Question 4
**The Question:**  
When tracking failed login attempts per IP address, why is rate-limiting based on individual `/32` IPv4 addresses or `/128` IPv6 addresses ineffective against distributed credential stuffing attacks, and why is aggregating counters by `/24` IPv4 subnets and `/64` IPv6 prefixes necessary?

**The Meta-Question:**  
The interviewer is assessing your experience with distributed botnets and mobile network IP topology. Attackers rotate IPs across residential proxy networks or borrow contiguous blocks of cloud IPs. Furthermore, IPv6 provides quintillions of addresses per residential customer; an attacker can change their IPv6 address on every single request! Aggregating failed attempt counters across `/24` subnets (IPv4) or `/64` routing prefixes (IPv6) aggregates botnet bursts into a shared bucket, effectively throttling the attacker regardless of per-host IP hopping.

---

### Question 5
**The Question:**  
In our sequence diagram, the rate-limiting check (`checkLoginAllowed`) executes *before* the database lookup for the user and *before* Argon2id password verification. Why is placing the rate-limiter as the outermost guard clause essential for protecting system resources during a massive brute-force attack?

**The Meta-Question:**  
The interviewer is evaluating your understanding of resource hierarchy and compute defense. Argon2id password verification consumes significant CPU time (~100ms per verification). If a botnet bombards the sign-in endpoint with 1,000 requests per second, executing Argon2id on every attempt immediately drives CPU utilization to 100%, causing cascading request drops. Placing the in-memory Redis rate-limiter at the entry gate drops malicious traffic in under 1 millisecond before any CPU-intensive hashing or database connections are allocated.

---

### Question 6
**The Question:**  
How does our rate-limiting service handle false positives for mobile carrier networks that employ Carrier-Grade NAT (CGNAT)? If hundreds of legitimate mobile users share the exact same external public IP address, how do we prevent one bad actor from locking out all mobile users on that carrier?

**The Meta-Question:**  
The interviewer is probing your awareness of real-world mobile telecommunications networking. In CGNAT environments (such as mobile cellular towers), thousands of distinct phones share a small pool of public IP addresses. Hard-blocking a CGNAT IP locks out innocent mobile users. An adaptive rate limiter must detect high-density IP ranges and transition from hard IP blocks to soft step-up challenges: prompting Cloudflare Turnstile, sending email verification codes, or requiring TOTP instead of rejecting requests with HTTP 429.

---

### Question 7
**The Question:**  
When an authenticated user signs out via `POST /api/v1/auth/sign-out`, we record the token's `jti` in the Redis denylist. What happens if an attacker attempts to flood the sign-out endpoint with random strings or already-expired tokens? How does the service prevent Redis memory bloat from unauthenticated sign-out flooding?

**The Meta-Question:**  
The interviewer is checking your defensive design against denial-of-wallet and cache pollution attacks. The sign-out endpoint must be protected by bearer token authentication middleware. The server validates the cryptographic signature of the JWT *before* interacting with Redis. If an incoming token has an invalid signature, an expired timestamp, or a malformed format, it is rejected immediately, ensuring that only legitimately issued, active tokens can write entries into the Redis denylist.

---

### Question 8
**The Question:**  
If a user successfully authenticates after several failed attempts, how does `recordLoginSuccess` reset the failure counters in Redis, and why is deleting the failure keys upon successful login an essential user experience guarantee?

**The Meta-Question:**  
The interviewer is testing your failure recovery mechanics. If a user mistypes their password four times and then correctly enters it on the fifth try, failing to clear the failure counter means that a single accidental typo later in the day would immediately trigger an account lockout! `recordLoginSuccess` must atomically delete or decrement the user's failed attempt counter in Redis upon successful credential verification, restoring the account to a clean state.

---

### Question 9
**The Question:**  
What is the difference between a Fixed Window, a Sliding Log, and a Sliding Window Counter algorithm for rate limiting, and why is the Sliding Window Counter algorithm the industry standard for high-throughput authentication services?

**The Meta-Question:**  
The interviewer is testing your algorithmic depth in rate-limiting data structures.
- **Fixed Window**: Suffers from the boundary bursting problem: a user can send their full quota at the end of window 1 and another full quota at the start of window 2, doubling the allowed rate across the boundary.
- **Sliding Log**: Stores every request timestamp in a sorted set; perfectly accurate, but memory consumption scales linearly with request volume.
- **Sliding Window Counter**: Combines weighted counts from the current and previous fixed windows ($Count = Count_{\text{current}} + Count_{\text{previous}} \times (1 - \text{elapsedFraction})$). It prevents boundary bursting, requires only two integer keys per user, and executes in $O(1)$ memory.

---

### Question 10
**The Question:**  
In our sequence diagram, when `checkLoginAllowed` determines an account is locked, it returns `retryAfterMs`, and the router responds with `HTTP 423 Locked` and a `Retry-After` header. How should frontend clients consume the `Retry-After` header, and how does this improve mobile battery life and network efficiency during lockouts?

**The Meta-Question:**  
The interviewer is evaluating your client-server coordination and mobile network optimization. When a client receives a `Retry-After: 900` header, the frontend should disable the login submit button, display a live countdown timer to the user, and prevent background polling. On mobile devices, this prevents client apps from spinning CPU cycles and keeping cellular radios awake in useless retry loops.

---

### Question 11
**The Question:**  
How does the OpenTelemetry tracer integrate with `LoginRateLimiterService`? What specific span attributes and events should be attached to `withSpan("LoginRateLimiterService.checkLoginAllowed")` to enable security teams to visualize brute-force attacks in Grafana Tempo?

**The Meta-Question:**  
The interviewer is checking your security observability instrumentation. Key span attributes include:
1. `rate_limit.ip`: The client subnet.
2. `rate_limit.current_count`: Number of attempts recorded in the active window.
3. `rate_limit.allowed`: Boolean flag.
4. `rate_limit.action`: Categorized as `ALLOW`, `CHALLENGE_CAPTCHA`, or `BLOCK_429`.
If blocked, the span records a Span Event (`rate_limit_exceeded`) with the lockout duration, allowing security analysts to write TraceQL queries to identify distributed attack sources.

---

### Question 12
**The Question:**  
When an attacker performs a "password spraying" attack, they try a single common password (like `Winter2026!`) across thousands of different user accounts from multiple rotating IP addresses. Why does standard per-user and per-IP rate limiting fail to detect password spraying, and what global rate-limiting heuristics must be implemented?

**The Meta-Question:**  
The interviewer is probing your advanced threat detection beyond localized rate limits. In password spraying, each IP makes only 1 request, and each user experiences only 1 failure—completely slipping under standard thresholds! Mitigating password spraying requires **Global Velocity Metrics**: tracking the overall failure rate across the entire service. If the global login failure rate surges from a normal 3% baseline to 40% within 5 minutes, an adaptive defense engine automatically increases global security postures (e.g., requiring CAPTCHA for all unauthenticated logins).

---

### Question 13
**The Question:**  
In our Redis denylist implementation, what data structure is used to store `denylist:<jti>`? Is a simple string key with `SET ... EX` superior to using a Redis Hash or Sorted Set, and why?

**The Meta-Question:**  
The interviewer is testing your Redis data modeling efficiency. A top-level string key (`SET denylist:<jti> "1" EX <ttl>`) is optimal because:
1. It supports per-key native expiration handled directly by Redis's active/passive expiration algorithms.
2. Checking membership (`EXISTS denylist:<jti>`) executes in $O(1)$ constant time with minimal CPU overhead.
3. Redis Hashes and Sets do not support individual per-field TTLs in standard Redis, which would require custom cleanup workers.

---

### Question 14
**The Question:**  
What happens if an attacker attempts an HTTP Slowloris attack or connection exhaustion attack against the Node.js authentication server by initiating thousands of TLS handshakes without sending full request bodies?

**The Meta-Question:**  
The interviewer is testing your perimeter infrastructure and reverse proxy architecture. Node.js should never be exposed directly to the public internet without an intermediate reverse proxy (like Traefik, NGINX, or Cloudflare). The ingress proxy handles TLS termination, enforces `client_body_timeout` (e.g., dropping connections that do not send headers within 10 seconds), and buffers complete HTTP requests before forwarding them to the internal Node.js auth service, completely absorbing Slowloris attacks.

---

### Question 15
**The Question:**  
In our implementation, what happens to Redis rate-limiting keys when an IP or user stops making requests? How do we ensure that stale sliding-window counters are automatically garbage-collected by Redis without manual cron jobs?

**The Meta-Question:**  
The interviewer is checking your knowledge of Redis key lifecycle management. Every time a rate-limiting key is updated or created (e.g., via the atomic Lua script), the script sets an explicit TTL on the key equal to the rate-limiting window (e.g., `EXPIRE key 900` for a 15-minute window). If the client ceases activity, Redis automatically purges the key after 15 minutes of inactivity, guaranteeing zero lingering memory leaks.

---

### Question 16
**The Question:**  
How does our authentication architecture protect against credential stuffing attacks utilizing leaked breach databases from sites like HaveIBeenPwned?

**The Meta-Question:**  
The interviewer is assessing your credential hygiene and breached password screening capabilities. Modern authentication systems integrate with HaveIBeenPwned's API using **k-Anonymity**:
1. When a user submits a password during sign-up or login, the service computes its SHA-1 hash.
2. It sends only the first 5 characters of the hash to the Pwned Passwords API.
3. The API returns a list of matching hash suffixes and breach counts.
4. The service checks the remainder locally. Zero password material leaves the auth server, and compromised passwords can be rejected immediately.

---

### Question 17
**The Question:**  
If a user is operating behind a corporate VPN or proxy server where multiple employees legitimately share the same public IP address, how does our rate limiter avoid locking out the entire office when one employee forgets their password?

**The Meta-Question:**  
The interviewer is evaluating your enterprise networking nuance. In corporate VPNs, hundreds of employees share a corporate egress IP. The rate limiter must never rely solely on an aggressive IP block. If IP failure thresholds are approached, the system transitions to email-specific challenges or Cloudflare Turnstile CAPTCHA. Only an extreme volume of failures across multiple distinct accounts should trigger a temporary IP-level block.

---

### Question 18
**The Question:**  
How do you write automated integration tests to assert that an IP sliding-window rate limiter accurately blocks traffic on the 11th request, and how do you mock time in tests to verify that the block expires after exactly 15 minutes?

**The Meta-Question:**  
The interviewer is testing your automated testing discipline for time-dependent algorithms. Tests should use Vitest/Jest virtual timers or a mocked Redis time function in the Lua script. The test script fires 10 rapid requests asserting HTTP 200/401, verifies the 11th request returns `HTTP 429 Too Many Requests` with a `Retry-After` header, advances virtual time by 15 minutes and 1 second, and asserts that the 12th request is permitted through.

---

### Question 19
**The Question:**  
What is the difference between client-side CAPTCHA verification (like Cloudflare Turnstile or Google reCAPTCHA v3) and backend rate limiting, and how do they work in synergy to defeat distributed botnets?

**The Meta-Question:**  
The interviewer is assessing your multi-layered bot defense architecture. Backend rate limiting operates on traffic volume (requests per second), but distributed botnets rotate millions of residential IPs, keeping per-IP volume low. Client-side Turnstile evaluates browser fingerprinting, browser environment legitimacy, and cryptographic proof-of-work challenges. Requiring a valid Turnstile token after 3 consecutive failures forces the botnet to solve expensive cryptographic challenges or solve CAPTCHAs, breaking automated stuffing scripts.

---

### Question 20
**The Question:**  
In our sequence diagram, what happens if the Redis connection times out while `checkLoginAllowed` is running? Does the service throw an uncaught error, or does it log a warning and allow the request to proceed to the database?

**The Meta-Question:**  
The interviewer is probing your fault-tolerant degradation strategy. If Redis is down, should legitimate users be blocked from logging in? An enterprise auth service should implement a **graceful fallback**: catch the Redis timeout, record a metric and log an emergency alert, and allow the request to proceed to database verification. It is generally better to accept temporary vulnerability to brute force during a Redis outage than to cause a 100% platform-wide authentication blackout.

---

### Question 21
**The Question:**  
How does our rate-limiting service track failed attempts across distributed instances of our auth service running in Kubernetes? Why is in-memory rate limiting within a single Node.js process insufficient?

**The Meta-Question:**  
The interviewer is testing your distributed systems state management knowledge. In a Kubernetes deployment with 10 auth pods, an in-memory rate limiter inside each pod only tracks one-tenth of incoming requests. A botnet can distribute 100 failed attempts evenly across the 10 pods, and no single pod will ever see more than 10 attempts! Centralizing rate-limiting state in a shared Redis cluster ensures that request counts are aggregated globally across all pods.

---

### Question 22
**The Question:**  
What are the performance implications of using Redis Cluster with hash tags (e.g., `{ip:1.2.3.4}`) when running multi-key Lua scripts for rate limiting, and why are hash tags mandatory in clustered Redis?

**The Meta-Question:**  
The interviewer is testing your advanced Redis Cluster partitioning mechanics. In a sharded Redis Cluster, multi-key commands or Lua scripts that touch multiple keys fail with a `CROSSSLOT Keys in request don't hash to the same slot` error if the keys reside on different cluster nodes. Wrapping the primary key in curly braces (`{login:ip:1.2.3.4}:window`, `{login:ip:1.2.3.4}:count`) forces Redis to compute the CRC16 hash slot based solely on the text inside the braces, guaranteeing that all related keys reside on the exact same cluster shard.

---

### Question 23
**The Question:**  
When an administrative account is locked due to security policy or excessive failed attempts, how should security notifications be dispatched to the account owner, and why must security notification dispatch be decoupled from the HTTP response?

**The Meta-Question:**  
The interviewer is assessing security notification delivery and asynchronous decoupling. When an account lockout triggers, an alert email must be dispatched immediately ("Security Alert: Your account has been temporarily locked due to failed login attempts"). This notification must be dispatched asynchronously via a message queue or background worker, ensuring that any downstream email provider delay or outage does not increase HTTP response latency.

---

### Question 24
**The Question:**  
How can an API gateway like Traefik or Envoy offload login rate limiting and JWT revocation checks using ForwardAuth or external authorization filters before requests ever reach the Node.js auth service?

**The Meta-Question:**  
The interviewer is checking your perimeter offloading and zero-trust gateway architecture. With Traefik ForwardAuth or Envoy `ext_authz`, every inbound request is pre-checked by a lightweight edge filter that queries Redis directly. If the token is revoked or the IP is rate-limited, the gateway terminates the connection at the edge with 401 or 429, preventing unauthenticated or malicious traffic from ever consuming backend application container memory or CPU.

---

### Question 25
**The Question:**  
Looking at ADR 0010 as an architectural whole, how does the combination of stateless JWTs, Redis JTI denylists, and adaptive rate limiting achieve the optimal balance between high-throughput performance, low latency, and enterprise-grade security?

**The Meta-Question:**  
The interviewer is evaluating your ability to synthesize the entire authentication architecture into a cohesive executive summary. The staff-level answer articulates that:
1. Under normal operation, requests execute with zero database overhead: stateless JWT verification in microseconds.
2. In the rare event of sign-out or compromise, sub-millisecond edge Redis checks provide immediate revocation.
3. Brute-force and credential stuffing threats are neutralized at the outer perimeter by dual-track rate limiters, shielding CPU-expensive password hashing and relational databases from exhaustion.
