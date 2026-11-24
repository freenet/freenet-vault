#!/bin/bash
# sim-model-7, targeted re-check of revision 10.1: gate, one 100k core
# batch, and the 20k mutation check (15.5 list of 10.1 plus the G2 mutant).
cd /home/ian/code/scratch/d269b3ff-model7/vault
B=target/release/vault-model
R=crates/freenet-vault-model/results/rev10.1
t() { local name=$1; shift; local s=$(date +%s); COV_ALL=1 "$B" "$@" > $R/$name.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/$name.log; echo "$name done"; }
t gate-2000 --seeds 2000 --shrink 1
t core-100k --seeds 100000 --shrink 1
t mutants-20k --mutants --seeds 20000 --shrink 0
echo ALL DONE
