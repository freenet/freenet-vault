#!/bin/bash
# sim-model-7: final revision 10 runs, one at a time.
cd /home/ian/code/scratch/d269b3ff-model7/vault
B=target/release/vault-model
R=crates/freenet-vault-model/results/rev10-final
t() { local name=$1; shift; local s=$(date +%s); COV_ALL=1 "$B" "$@" > $R/$name.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/$name.log; echo "$name done"; }
t gate-2000 --seeds 2000 --shrink 1
t core-100k-literal --seeds 100000 --shrink 1
t core-100k-alt-readings --seeds 100000 --shrink 1 --absent-parts-valid-list --catchall-answers-nothing
t core-100k-quiesce-shuffle --seeds 100000 --shrink 0 --quiesce-shuffle
t adversarial-100k --seeds 100000 --shrink 0 --adversarial
t mutants-20k --mutants --seeds 20000 --shrink 1
echo ALL DONE
