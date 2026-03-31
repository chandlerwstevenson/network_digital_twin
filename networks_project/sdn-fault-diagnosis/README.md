# SDN Fault Diagnosis with LLM + Digital Twin

A research project evaluating LLM-driven fault diagnosis in software-defined networks using a digital twin approach.

## Overview

This system:
1. Deploys a spine-leaf network topology using Containerlab with FRRouting containers running OSPF
2. Collects real vtysh JSON telemetry from every router
3. Injects faults (link failures, stale routes, flapping links, missing routes, counter anomalies)
4. Feeds identical telemetry snapshots to TWO diagnostic systems:
   - A rule-based Python baseline (decision tree over the JSON)
   - An LLM agent (Claude API with chain-of-thought prompting)
5. Compares their diagnoses using paired statistical tests

## Network Topology

```
                    ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
                    │ spine1  │ │ spine2  │ │ spine3  │ │ spine4  │
                    │10.0.0.1 │ │10.0.0.2 │ │10.0.0.3 │ │10.0.0.4 │
                    └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
                         │          │          │          │
        ┌────────────────┼──────────┼──────────┼──────────┼────────────────┐
        │                │          │          │          │                │
   ┌────┴────┐      ┌────┴────┐ ┌───┴────┐ ┌───┴────┐ ┌───┴────┐     ┌────┴────┐
   │  leaf1  │      │  leaf2  │ │ leaf3  │ │ leaf4  │ │  ...   │     │  ...    │
   │10.0.1.1 │      │10.0.1.2 │ │10.0.1.3│ │10.0.1.4│ │        │     │         │
   └────┬────┘      └────┬────┘ └───┬────┘ └───┬────┘ └────────┘     └─────────┘
        │                │          │          │
   ┌────┴────┐      ┌────┴────┐ ┌───┴────┐ ┌───┴────┐
   │host1,2  │      │host3,4  │ │host5,6 │ │host7,8 │
   │192.168.1│      │192.168.2│ │192.168.3│ │192.168.4│
   └─────────┘      └─────────┘ └────────┘ └────────┘
```

- 4 Spine routers (spine1-spine4)
- 4 Leaf routers (leaf1-leaf4)
- 8 Host nodes (2 per leaf)
- Full mesh connectivity between spine and leaf tiers
- All routers run OSPF in Area 0

## Prerequisites

- **Python 3.10+**
- **Docker** (running)
- **Containerlab** ([installation](https://containerlab.dev/install/))
- **Anthropic API key** (for LLM agent)

```bash
# Install Containerlab
bash -c "$(curl -sL https://get.containerlab.dev)"

# Install Python dependencies
pip install -r requirements.txt

# Set API key
export ANTHROPIC_API_KEY=sk-ant-...
```

## Quick Start

```bash
# 1. Deploy the network topology
./scripts/deploy.sh

# 2. Wait for OSPF convergence (~30 seconds)
sleep 30

# 3. Verify network health
./scripts/verify_health.sh

# 4. Run a single test trial
python -m evaluation.runner --trials 1 --mock-llm

# 5. Run full experiment (100 trials)
./scripts/run_experiment.sh --trials 100

# 6. Tear down when done
./scripts/destroy.sh
```

## Project Structure

```
sdn-fault-diagnosis/
├── topology/              # Containerlab topology and FRR configs
│   ├── topology.yml       # Network topology definition
│   └── configs/           # FRR configuration per router
├── telemetry/             # Telemetry collection
│   ├── schemas.py         # Pydantic data models
│   ├── collector.py       # vtysh polling daemon
│   └── snapshot.py        # Snapshot management and diffing
├── faults/                # Fault injection
│   ├── fault_types.py     # Fault class definitions
│   ├── injector.py        # Injection harness
│   └── scenarios.py       # Pre-defined scenarios
├── diagnosis/             # Diagnostic engines
│   ├── base.py            # Abstract base class
│   ├── rule_based.py      # Decision tree engine
│   ├── llm_agent.py       # Claude API agent
│   └── prompts/           # LLM prompts and examples
├── evaluation/            # Experiment framework
│   ├── runner.py          # Experiment orchestration
│   ├── metrics.py         # Performance metrics
│   ├── stats.py           # Statistical tests
│   └── results/           # Output directory
├── scripts/               # Shell scripts
│   ├── deploy.sh          # Deploy topology
│   ├── destroy.sh         # Tear down topology
│   ├── verify_health.sh   # Health check
│   └── run_experiment.sh  # Full experiment runner
└── tests/                 # Unit tests
```

## Fault Types

| Fault Class | Description | Symptoms |
|-------------|-------------|----------|
| `link_failure` | Interface goes down | OSPF neighbor loss, LSA updates |
| `flapping_link` | Interface cycles up/down | Repeated state changes, route churn |
| `stale_route` | Incorrect static route | Routing inconsistency, traffic misdirection |
| `missing_route` | OSPF network withdrawn | Route disappears from LSDB |
| `counter_anomaly` | Packet loss/errors | High error/drop counters |

## Usage Examples

### Manual Fault Injection

```bash
# Inject a link failure
python -m faults.injector link_down --target spine1 --interface eth1

# Inject packet loss
python -m faults.injector counter_anomaly --target leaf2 --interface eth3 --loss 5

# Restore all faults
python -m faults.injector restore --all

# List active faults
python -m faults.injector list
```

### Telemetry Collection

```bash
# Single snapshot
python telemetry/collector.py --once

# Continuous polling
python telemetry/collector.py --interval 2 --output ./snapshots
```

### Running Experiments

```bash
# Quick test with mock LLM
python -m evaluation.runner --trials 10 --mock-llm

# Full experiment with real LLM
python -m evaluation.runner --trials 100 --compound-ratio 0.2

# Run specific scenario
python -m evaluation.runner --scenario spine1_leaf1_link_down
```

## Diagnostic Engines

### Rule-Based Engine

Implements systematic analysis:
1. **LSDB diff**: Compare Router-LSAs for topology changes
2. **Neighbor check**: Flag non-Full adjacencies
3. **Route audit**: Verify next-hop reachability
4. **Counter analysis**: Detect error/drop rate anomalies

### LLM Agent

Uses Claude API with:
- System prompt defining OSPF fault taxonomy
- Few-shot examples with worked diagnoses
- Chain-of-thought reasoning
- Structured JSON output

## Evaluation Metrics

- **Classification Accuracy**: Correct fault class identification
- **Localization Accuracy**: Correct affected component identification
- **Time-to-Diagnosis**: Wall-clock diagnostic latency

### Statistical Tests

- **McNemar's Test**: Paired accuracy comparison
- **Wilcoxon Signed-Rank**: Time comparison
- **Bootstrap CI**: Confidence intervals

## Results

Results are saved to `evaluation/results/`:

```
results/
├── results_YYYYMMDD_HHMMSS.json    # Summary metrics
├── trials_YYYYMMDD_HHMMSS.json     # Detailed trial data
└── snapshots/                       # Network state snapshots
```

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_rule_based.py -v
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Claude API key | Required for LLM |

### Diagnosis Configuration

```python
from diagnosis.base import DiagnosisConfig

config = DiagnosisConfig(
    error_rate_threshold=1.0,   # Flag if >1% errors
    drop_rate_threshold=1.0,    # Flag if >1% drops
    require_full_adjacency=True,
    min_confidence=0.5
)
```

## Extending the System

### Adding New Fault Types

1. Create class in `faults/fault_types.py` extending `BaseFault`
2. Implement `inject()`, `restore()`, and `verify()` methods
3. Add to `FaultClass` enum and `create_fault()` factory
4. Create scenarios in `faults/scenarios.py`

### Adding New Diagnostic Engines

1. Create class extending `BaseDiagnosticEngine` in `diagnosis/`
2. Implement `diagnose()` method
3. Add to experiment runner

## Troubleshooting

### Network not starting
```bash
# Check Docker is running
docker info

# Check Containerlab installation
containerlab version

# Force redeploy
./scripts/deploy.sh --reconfigure
```

### OSPF not converging
```bash
# Check FRR status on a router
docker exec clab-sdn-fault-diagnosis-spine1 vtysh -c "show ip ospf neighbor"

# Check interface status
docker exec clab-sdn-fault-diagnosis-spine1 vtysh -c "show interface brief"
```

### LLM agent errors
```bash
# Check API key is set
echo $ANTHROPIC_API_KEY

# Use mock LLM for testing
python -m evaluation.runner --trials 10 --mock-llm
```

## License

MIT License - See LICENSE file for details.

## References

- [Containerlab Documentation](https://containerlab.dev/)
- [FRRouting Documentation](https://docs.frrouting.org/)
- [Anthropic Claude API](https://docs.anthropic.com/)
- [OSPF RFC 2328](https://tools.ietf.org/html/rfc2328)
