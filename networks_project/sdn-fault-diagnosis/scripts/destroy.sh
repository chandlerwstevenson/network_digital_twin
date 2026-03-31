#!/bin/bash
# Destroy the SDN fault diagnosis network topology using OrbStack
# Usage: ./destroy.sh [--cleanup]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TOPOLOGY_FILE="$PROJECT_DIR/topology/topology.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}SDN Fault Diagnosis - Network Teardown${NC}"
echo -e "${YELLOW}========================================${NC}"

# Check if OrbStack is installed
if ! command -v orb &> /dev/null; then
    echo -e "${RED}Error: OrbStack is not installed${NC}"
    echo "Install with: brew install orbstack"
    exit 1
fi

# Check if sdn-lab VM exists
if ! orbctl list | grep -q "sdn-lab"; then
    echo -e "${YELLOW}sdn-lab VM not found - nothing to destroy${NC}"
    exit 0
fi

# Check if topology file exists
if [ ! -f "$TOPOLOGY_FILE" ]; then
    echo -e "${RED}Error: Topology file not found: $TOPOLOGY_FILE${NC}"
    exit 1
fi

# Build destroy command options
CLEANUP_OPT=""
if [ "$1" == "--cleanup" ]; then
    echo -e "${YELLOW}Cleanup mode: will remove all generated files${NC}"
    CLEANUP_OPT="--cleanup"
fi

# Destroy topology
echo -e "\n${YELLOW}Destroying topology...${NC}"
cd "$PROJECT_DIR/topology"

if orb -m sdn-lab sudo containerlab destroy -t topology.yml $CLEANUP_OPT 2>/dev/null; then
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Topology destroyed successfully${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo -e "\n${YELLOW}Topology may already be destroyed${NC}"
fi

# Optional: clean up any orphaned containers
echo -e "\n${YELLOW}Checking for orphaned containers...${NC}"
ORPHANS=$(orb -m sdn-lab sudo docker ps -a --filter "name=clab-sdn-fault-diagnosis" -q 2>/dev/null || true)

if [ -n "$ORPHANS" ]; then
    echo -e "${YELLOW}Removing orphaned containers...${NC}"
    orb -m sdn-lab sudo docker rm -f $ORPHANS 2>/dev/null || true
    echo -e "${GREEN}Orphaned containers removed${NC}"
else
    echo -e "${GREEN}No orphaned containers found${NC}"
fi

echo -e "\n${GREEN}Done!${NC}"
