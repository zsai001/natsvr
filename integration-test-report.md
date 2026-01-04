# NatSvr Integration Test Report

**Start Time:** 2026-01-04T13:12:09+08:00  
**End Time:** 2026-01-04T13:12:54+08:00  
**Duration:** 44.39909925s

## Summary

| Metric | Value |
|--------|-------|
| Total Modes | 4 |
| Successful | 4 |
| Failed | 0 |
| Consistency Rate | 100.00% |
| Avg Latency | 0.00 ms |
| Total Throughput | 589.97 MB/s |

## Mode Comparison

| Mode | Type | Consistency | Latency (avg) | Throughput | Stress Success |
|------|------|-------------|---------------|------------|----------------|
| Mode2-CloudSelf | cloud-self | 100.0% | 0.04 ms | 294.08 MB/s | 100.0% |
| Mode3-AgentCloud | agent-cloud | 100.0% | 0.11 ms | 112.55 MB/s | 100.0% |
| Mode4-P2P | p2p | 100.0% | 0.17 ms | 67.41 MB/s | 100.0% |
| Mode1-Remote | remote | 100.0% | 0.10 ms | 115.94 MB/s | 100.0% |

## Detailed Results

### Mode2-CloudSelf (cloud-self)

#### Consistency Test

- Total Messages: 300
- Success: 300
- Checksum Errors: 0
- Data Mismatch: 0

#### Latency Test

- Samples: 200
- Min: 26.292µs
- Max: 151.333µs
- P50: 39.833µs
- P99: 142.791µs

#### Throughput Test

- Duration: 5.000062208s
- Send Rate: 294.08 MB/s
- Recv Rate: 294.08 MB/s

#### Stress Test

- Connections: 50/50
- Messages: 314842/314842
- Throughput: 124.40 MB/s

### Mode3-AgentCloud (agent-cloud)

#### Consistency Test

- Total Messages: 300
- Success: 300
- Checksum Errors: 0
- Data Mismatch: 0

#### Latency Test

- Samples: 200
- Min: 59.625µs
- Max: 433.292µs
- P50: 102.375µs
- P99: 207.292µs

#### Throughput Test

- Duration: 5.000167208s
- Send Rate: 112.55 MB/s
- Recv Rate: 112.55 MB/s

#### Stress Test

- Connections: 50/50
- Messages: 210440/210440
- Throughput: 83.14 MB/s

### Mode4-P2P (p2p)

#### Consistency Test

- Total Messages: 300
- Success: 300
- Checksum Errors: 0
- Data Mismatch: 0

#### Latency Test

- Samples: 200
- Min: 98.708µs
- Max: 462.042µs
- P50: 168.667µs
- P99: 435.166µs

#### Throughput Test

- Duration: 5.000292333s
- Send Rate: 67.41 MB/s
- Recv Rate: 67.41 MB/s

#### Stress Test

- Connections: 50/50
- Messages: 154599/154599
- Throughput: 61.08 MB/s

### Mode1-Remote (remote)

#### Consistency Test

- Total Messages: 300
- Success: 300
- Checksum Errors: 0
- Data Mismatch: 0

#### Latency Test

- Samples: 200
- Min: 57.125µs
- Max: 547.083µs
- P50: 94.041µs
- P99: 272.959µs

#### Throughput Test

- Duration: 5.000031875s
- Send Rate: 115.94 MB/s
- Recv Rate: 115.94 MB/s

#### Stress Test

- Connections: 50/50
- Messages: 210391/210391
- Throughput: 83.12 MB/s

## Result

**ALL TESTS PASSED**
