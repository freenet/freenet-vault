#!/bin/bash
# sim-model-7: rerun of the heal 100k batches after the label fix (a heal's
# removal is now labelled by the name it removed, not by the index at the
# end of the call) and the refound staging-full coverage seed.
cd /home/ian/code/scratch/d269b3ff-model7/vault
B=target/release/vault-model
R=crates/freenet-vault-model/results/rev10.2-heal
t() { local name=$1; shift; local s=$(date +%s); COV_ALL=1 "$B" "$@" > $R/$name.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/$name.log; echo "$name done"; }
t final-core-100k-strict --seeds 100000 --shrink 1
HEAL_I6_COUNT_ONLY=1 t final-core-100k-diag --seeds 100000 --shrink 1
MUTANTS_ONLY=HealWithoutDigestCheck,HealWhileSealed HEAL_I6_COUNT_ONLY=1 t final-mutants-heal-20k-diag --mutants --seeds 20000 --shrink 1
echo ALL DONE
