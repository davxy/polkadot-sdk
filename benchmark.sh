#!/bin/bash

# https://github.com/paritytech/polkadot-sdk/pull/1577/commits/4fd7f7aab71bc0f8d7a24a45f47ff4a23dabdb05#diff-833a94ebc229f189e17fdb680257706f88638b55cbfd3123a75411733e3a2645

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
