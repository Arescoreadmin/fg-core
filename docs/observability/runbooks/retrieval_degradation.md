# Runbook: FrostgateRetrievalLatencyHigh / FrostgateRetrievalFailureHigh

**Alert:** `FrostgateRetrievalLatencyHigh`, `FrostgateRetrievalFailureHigh`
**Severity:** Warning / Critical
**Metric:** `frostgate_retrieval_latency_seconds`, `frostgate_retrieval_requests_total`
**Threshold:** p99 latency > 2s or failure rate > 5% over 5 minutes

## Symptoms
- Retrieval latency panel shows p99 degradation by retrieval mode
- Users report slow or failed RAG query responses

## Immediate actions
1. Identify affected mode: `histogram_quantile(0.99, sum by (mode, le) (rate(frostgate_retrieval_latency_seconds_bucket[5m])))`
2. Check embedding service health and vector store availability
3. Check database query latency: `frostgate_db_query_latency_seconds`
4. Review recent ingestion volume — high ingest under load can degrade retrieval

## Resolution
- Scale retrieval workers if CPU/memory bound
- Check vector index compaction status
- Restart embedding service if stuck
