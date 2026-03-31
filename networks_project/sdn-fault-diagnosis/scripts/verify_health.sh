#!/bin/bash
# Verify network health - all OSPF adjacencies Full and end-to-end connectivity
# Uses OrbStack to access containers in sdn-lab VM
# Usage: ./verify_health.sh [--verbose]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VERBOSE=false
if [ "$1" == "--verbose" ]; then
    VERBOSE=true
fi

CONTAINER_PREFIX="clab-sdn-fault-diagnosis"
ROUTERS="spine1 spine2 spine3 spine4 leaf1 leaf2 leaf3 leaf4"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}SDN Fault Diagnosis - Health Verification${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if OrbStack is available
if ! command -v orb &> /dev/null; then
    echo -e "${RED}Error: OrbStack is not installed${NC}"
    exit 1
fi

# Track overall health
HEALTHY=true
TOTAL_ADJACENCIES=0
FULL_ADJACENCIES=0

# Check each router
echo -e "\n${YELLOW}Checking OSPF adjacencies...${NC}"

for ROUTER in $ROUTERS; do
    CONTAINER="${CONTAINER_PREFIX}-${ROUTER}"

    # Check if container is running
    if ! orb -m sdn-lab sudo docker ps --filter "name=$CONTAINER" --filter "status=running" -q | grep -q .; then
        echo -e "${RED}✗ $ROUTER: Container not running${NC}"
        HEALTHY=false
        continue
    fi

    # Get OSPF neighbors
    NEIGHBOR_OUTPUT=$(orb -m sdn-lab sudo docker exec "$CONTAINER" vtysh -c "show ip ospf neighbor" 2>/dev/null || echo "ERROR")

    if [ "$NEIGHBOR_OUTPUT" == "ERROR" ]; then
        echo -e "${RED}✗ $ROUTER: Failed to get OSPF neighbors${NC}"
        HEALTHY=false
        continue
    fi

    # Count neighbors and Full states
    NEIGHBOR_COUNT=$(echo "$NEIGHBOR_OUTPUT" | grep -c "Full" 2>/dev/null || echo "0")
    NON_FULL=$(echo "$NEIGHBOR_OUTPUT" | grep -E "Init|ExStart|Exchange|Loading|2-Way|Down" 2>/dev/null || true)

    # Expected neighbors
    if [[ "$ROUTER" == spine* ]]; then
        EXPECTED=4  # Spines connect to 4 leafs
    else
        EXPECTED=4  # Leafs connect to 4 spines
    fi

    TOTAL_ADJACENCIES=$((TOTAL_ADJACENCIES + EXPECTED))
    FULL_ADJACENCIES=$((FULL_ADJACENCIES + NEIGHBOR_COUNT))

    if [ "$NEIGHBOR_COUNT" -eq "$EXPECTED" ]; then
        echo -e "${GREEN}✓ $ROUTER: $NEIGHBOR_COUNT/$EXPECTED neighbors Full${NC}"
    else
        echo -e "${RED}✗ $ROUTER: $NEIGHBOR_COUNT/$EXPECTED neighbors Full${NC}"
        HEALTHY=false

        if [ "$VERBOSE" = true ] && [ -n "$NON_FULL" ]; then
            echo -e "  ${YELLOW}Non-Full neighbors:${NC}"
            echo "$NON_FULL" | sed 's/^/    /'
        fi
    fi
done

# Summary
echo -e "\n${YELLOW}Adjacency Summary: $FULL_ADJACENCIES/$TOTAL_ADJACENCIES Full${NC}"

# Test end-to-end connectivity
echo -e "\n${YELLOW}Testing end-to-end connectivity...${NC}"

# Ping from leaf1 to all other leaf loopbacks
LEAF1_CONTAINER="${CONTAINER_PREFIX}-leaf1"
TARGETS="10.0.1.2 10.0.1.3 10.0.1.4"  # leaf2, leaf3, leaf4 loopbacks

PING_FAILED=false
for TARGET in $TARGETS; do
    if orb -m sdn-lab sudo docker exec "$LEAF1_CONTAINER" ping -c 2 -W 2 "$TARGET" &>/dev/null; then
        echo -e "${GREEN}✓ leaf1 -> $TARGET: OK${NC}"
    else
        echo -e "${RED}✗ leaf1 -> $TARGET: FAILED${NC}"
        PING_FAILED=true
        HEALTHY=false
    fi
done

# Check route counts
echo -e "\n${YELLOW}Checking routing tables...${NC}"

for ROUTER in spine1 leaf1; do
    CONTAINER="${CONTAINER_PREFIX}-${ROUTER}"
    ROUTE_COUNT=$(orb -m sdn-lab sudo docker exec "$CONTAINER" vtysh -c "show ip route" 2>/dev/null | grep -c "^O" || echo "0")
    echo -e "  $ROUTER: $ROUTE_COUNT OSPF routes"
done

# Final verdict
echo -e "\n${GREEN}========================================${NC}"
if [ "$HEALTHY" = true ]; then
    echo -e "${GREEN}Network is HEALTHY${NC}"
    echo -e "${GREEN}All OSPF adjacencies Full, connectivity verified${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
else
    echo -e "${RED}Network has ISSUES${NC}"
    echo -e "${RED}Check the errors above and wait for OSPF convergence${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
