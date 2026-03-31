#!/bin/bash
# Deploy the SDN fault diagnosis network topology using OrbStack
# Usage: ./deploy.sh [--reconfigure]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TOPOLOGY_FILE="$PROJECT_DIR/topology/topology.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}SDN Fault Diagnosis - Network Deployment${NC}"
echo -e "${GREEN}========================================${NC}"

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

if ! command -v orb &> /dev/null; then
    echo -e "${RED}Error: OrbStack is not installed${NC}"
    echo "Install with: brew install orbstack"
    exit 1
fi

# Check if sdn-lab VM exists
if ! orbctl list | grep -q "sdn-lab"; then
    echo -e "${YELLOW}Creating sdn-lab VM...${NC}"
    orbctl create ubuntu sdn-lab
    sleep 5
fi

# Check if containerlab is installed in the VM
if ! orb -m sdn-lab which containerlab &> /dev/null; then
    echo -e "${YELLOW}Installing containerlab in VM...${NC}"
    orb -m sdn-lab bash -c 'curl -sL https://get.containerlab.dev | sudo bash'
fi

# Check if Docker is available
if ! orb -m sdn-lab sudo docker info &> /dev/null; then
    echo -e "${YELLOW}Starting Docker in VM...${NC}"
    orb -m sdn-lab sudo systemctl start docker
    sleep 3
fi

echo -e "${GREEN}✓ Prerequisites satisfied${NC}"

# Check if topology file exists
if [ ! -f "$TOPOLOGY_FILE" ]; then
    echo -e "${RED}Error: Topology file not found: $TOPOLOGY_FILE${NC}"
    exit 1
fi

# Check if already deployed
if orb -m sdn-lab sudo docker ps --filter "name=clab-sdn-fault-diagnosis" -q | grep -q .; then
    echo -e "${YELLOW}Topology already deployed${NC}"

    if [ "$1" == "--reconfigure" ]; then
        echo -e "${YELLOW}Reconfigure requested - destroying existing deployment...${NC}"
        orb -m sdn-lab sudo containerlab destroy -t "$TOPOLOGY_FILE" --cleanup 2>/dev/null || true
    else
        echo "Use --reconfigure to redeploy, or run destroy.sh first"
        exit 0
    fi
fi

# Pull FRR image if needed
echo -e "\n${YELLOW}Ensuring FRR image is available...${NC}"
orb -m sdn-lab sudo docker pull frrouting/frr:latest || true

# Deploy topology
echo -e "\n${YELLOW}Deploying topology...${NC}"
cd "$PROJECT_DIR/topology"
DEPLOY_FLAGS=""
if [ "$1" == "--reconfigure" ]; then
    DEPLOY_FLAGS="--reconfigure"
fi
orb -m sdn-lab sudo containerlab deploy -t topology.yml $DEPLOY_FLAGS

# Wait for containers to initialize
echo -e "\n${YELLOW}Waiting for FRR daemons to start...${NC}"
sleep 10

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Wait ~30 seconds for OSPF to converge"
echo "2. Run: ./scripts/verify_health.sh"
echo "3. Then: python evaluation/runner.py --trials 10"
