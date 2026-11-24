#!/bin/sh
# Revision 10 runs (sim-model-6). Run from the repository root after
# `cargo build --release -p freenet-vault-model`. One run at a time.
set -x
B=./target/release/vault-model
R=crates/freenet-vault-model/results/rev10
COV_ALL=1 $B --seeds 2000 > $R/gate-2000.log 2>&1
COV_ALL=1 $B --seeds 100000 --shrink 1 > $R/core-100k.log 2>&1
COV_ALL=1 $B --seeds 100000 --shrink 1 --absent-parts-valid-list > $R/core-100k-absent-parts-valid-list.log 2>&1
COV_ALL=1 $B --seeds 100000 --shrink 0 --catchall-answers-nothing > $R/core-100k-catchall-answers-nothing.log 2>&1
COV_ALL=1 $B --seeds 100000 --shrink 0 --quiesce-shuffle > $R/core-100k-quiesce-shuffle.log 2>&1
COV_ALL=1 $B --seeds 100000 --shrink 1 --adversarial > $R/adversarial-100k.log 2>&1
$B --mutants --seeds 20000 --shrink 1 --not-blocking "$NOT_BLOCKING" > $R/mutants-20k.log 2>&1
