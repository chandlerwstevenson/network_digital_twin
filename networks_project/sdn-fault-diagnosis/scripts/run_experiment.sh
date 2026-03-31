#!/bin/bash
# Full experiment runner: deploy -> verify -> run N trials -> collect results
# Usage: ./run_experiment.sh [--trials N] [--compound-ratio R] [--mock-llm]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default parameters
TRIALS=100
COMPOUND_RATIO=0.2
MOCK_LLM=""
SKIP_DEPLOY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --trials)
            TRIALS="$2"
            shift 2
            ;;
        --compound-ratio)
            COMPOUND_RATIO="$2"
            shift 2
            ;;
        --mock-llm)
            MOCK_LLM="--mock-llm"
            shift
            ;;
        --skip-deploy)
            SKIP_DEPLOY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--trials N] [--compound-ratio R] [--mock-llm] [--skip-deploy]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   SDN Fault Diagnosis - Full Experiment Runner     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}Configuration:${NC}"
echo "  Trials: $TRIALS"
echo "  Compound Ratio: $COMPOUND_RATIO"
echo "  Mock LLM: ${MOCK_LLM:-disabled}"
echo ""

# Step 1: Deploy (if not skipped)
if [ "$SKIP_DEPLOY" = false ]; then
    echo -e "${BLUE}Step 1/4: Deploying network topology...${NC}"
    "$SCRIPT_DIR/deploy.sh" --reconfigure 2>&1 | sed 's/^/  /'

    # Wait for FRR to initialize
    echo -e "\n${YELLOW}Waiting 30 seconds for OSPF convergence...${NC}"
    sleep 30
else
    echo -e "${BLUE}Step 1/4: Skipping deployment (--skip-deploy)${NC}"
fi

# Step 2: Verify health
echo -e "\n${BLUE}Step 2/4: Verifying network health...${NC}"
MAX_RETRIES=3
RETRY=0

while [ $RETRY -lt $MAX_RETRIES ]; do
    if "$SCRIPT_DIR/verify_health.sh" 2>&1 | sed 's/^/  /'; then
        break
    else
        RETRY=$((RETRY + 1))
        if [ $RETRY -lt $MAX_RETRIES ]; then
            echo -e "${YELLOW}  Health check failed, waiting 15s and retrying ($RETRY/$MAX_RETRIES)...${NC}"
            sleep 15
        else
            echo -e "${RED}  Network health check failed after $MAX_RETRIES attempts${NC}"
            echo -e "${RED}  Aborting experiment${NC}"
            exit 1
        fi
    fi
done

# Step 3: Run experiment
echo -e "\n${BLUE}Step 3/4: Running experiment...${NC}"
echo -e "${YELLOW}  This may take a while for $TRIALS trials...${NC}"

cd "$PROJECT_DIR"

# Check if ANTHROPIC_API_KEY is set (unless using mock)
if [ -z "$MOCK_LLM" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}  Warning: ANTHROPIC_API_KEY not set, falling back to mock LLM${NC}"
    MOCK_LLM="--mock-llm"
fi

# Run the experiment
python -m evaluation.runner \
    --trials "$TRIALS" \
    --compound-ratio "$COMPOUND_RATIO" \
    $MOCK_LLM \
    2>&1 | sed 's/^/  /'

RESULT=$?

# Step 4: Summary
echo -e "\n${BLUE}Step 4/4: Experiment complete!${NC}"

if [ $RESULT -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Experiment Successful!                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"

    # Find latest results file
    LATEST_RESULTS=$(ls -t "$PROJECT_DIR/evaluation/results"/results_*.json 2>/dev/null | head -1)

    if [ -n "$LATEST_RESULTS" ]; then
        echo -e "\n${YELLOW}Results saved to:${NC}"
        echo "  $LATEST_RESULTS"

        # Extract and display key metrics
        echo -e "\n${YELLOW}Key Metrics:${NC}"
        python3 -c "
import json
with open('$LATEST_RESULTS') as f:
    data = json.load(f)
    rb_acc = data['metrics']['rule_based']['classification']['accuracy']
    llm_acc = data['metrics']['llm_agent']['classification']['accuracy']
    print(f'  Rule-based accuracy: {rb_acc:.1%}')
    print(f'  LLM agent accuracy:  {llm_acc:.1%}')
    print(f'  Difference: {(llm_acc - rb_acc)*100:+.1f}%')
" 2>/dev/null || echo "  (Could not parse results)"
    fi
else
    echo -e "${RED}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              Experiment Failed!                    ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════╝${NC}"
    exit 1
fi

echo -e "\n${YELLOW}Next steps:${NC}"
echo "  - Review detailed results in evaluation/results/"
echo "  - Run additional trials with different parameters"
echo "  - Destroy topology when done: ./scripts/destroy.sh"
