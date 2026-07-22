# Profile: troubleshooting-v1

## When to use this profile
Use this profile for any concept document that helps resolve a recurring error, failure, or unexpected behavior — the "why is X broken and how do I fix it" class of query. This is the single most common query type AI agents fetch documentation for, and the one where unstructured prose most often causes an agent to give a partial or wrong fix.

## Required frontmatter fields
```yaml
type: Troubleshooting Guide
```
No additional fields beyond OKF's base set (title, description, resource, tags, timestamp) are required. Keep `tags` specific enough to disambiguate near-identical problems.

## Required body sections
1. **Symptom** — the exact observable behavior or error text, verbatim where possible, so an agent can pattern-match the query to this doc with confidence.
2. **Likely causes** — a short ordered list, most common cause first.
3. **Fix** — numbered, imperative steps. One action per step.
4. **Limitations** — cases where this fix does NOT apply, or environments where it behaves differently. This is the section unstructured troubleshooting docs skip most often.
5. **Links** — related pages an agent should check if this fix doesn't resolve the symptom.

## Why this structure
Unstructured troubleshooting prose typically front-loads context and buries the actual fix, forcing an agent to read the whole document to extract three usable steps. The **Limitations** section is not optional: without it, agents applying a fix outside its valid context is the most common failure mode observed in loosely structured docs.

## Worked example
```markdown
---
type: Troubleshooting Guide
title: Connection pool exhausted under burst traffic
description: Fix for "FATAL too many connections" errors during traffic spikes.
tags: [connection-timeout, database, pooling]
profile: troubleshooting-v1
timestamp: 2026-07-21T00:00:00Z
---

# Symptom
Application logs show `FATAL: too many connections` or requests hang for 30+ seconds during traffic spikes, but not under steady load.

# Likely causes
1. Connection pool max size is set below actual concurrent demand at peak.
2. Connections aren't being released after short-lived queries (leak).
3. A downstream service is holding connections open longer than expected.

# Fix
1. Check current pool config: confirm max_connections and application-level pool size.
2. Increase application-level pool size to match expected peak concurrency, not average.
3. Add a connection timeout so leaked connections are forcibly released.
4. Redeploy and monitor pool utilization during the next traffic spike.

# Limitations
This fix does not apply if the database itself is at its own connection ceiling — raise that limit first, or add a pooler in front of it.

# Links
- (link to related pages once published)
```
