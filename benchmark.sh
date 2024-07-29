#!/bin/bash
#
# Build with:
#
# ```bash
# $ cargo build --release -p solochain-template-node --features runtime-benchmarks
# ```

binary="./target/release/solochain-template-node"

steps=20
repeat=3

export RUST_LOG="sassafras=debug"

pallet='pallet_sassafras'

extrinsic=$1

if [[ $extrinsic == "" ]]; then
    list=$($binary benchmark pallet --list | grep $pallet | cut -d ',' -f 2)

    echo "Usage: $0 <benchmark>"
    echo ""
    echo "Available benchmarks:"
    for bench in $list; do
        echo "- $bench"
    done
    echo "- all"
    exit
fi

if [[ $extrinsic == "all" ]]; then
    extrinsic='*'
fi

RUST_LOG=sassafras=debug $binary benchmark pallet \
    --chain dev \
    --pallet $pallet \
    --extrinsic "$extrinsic" \
    --steps $steps \
    --repeat $repeat \
    --output weights.rs \
    --template substrate/.maintain/frame-weight-template.hbs
