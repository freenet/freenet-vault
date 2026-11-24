#!/bin/bash
# sim-model-7: revision 10.1 with G2b in the text (the G2 Moved rule also
# under 4.5 condition 2): gate, one 100k core batch, full 20k mutation check.
cd /home/ian/code/scratch/d269b3ff-model7/vault
B=target/release/vault-model
R=crates/freenet-vault-model/results/rev10.1-g2b
t() { local name=$1; shift; local s=$(date +%s); COV_ALL=1 "$B" "$@" > $R/$name.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/$name.log; echo "$name done"; }
t gate-2000 --seeds 2000 --shrink 1
t core-100k --seeds 100000 --shrink 1
t mutants-20k --mutants --seeds 20000 --shrink 0
echo ALL DONE
