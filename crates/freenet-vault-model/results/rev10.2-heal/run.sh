#!/bin/bash
# sim-model-7: revision 10.2 heal from mirror plus G2b. One 100k core batch
# as the document reads (strict I6), the same batch with the heal's removal
# of the named copy counted instead of failing (diagnostic, so the rest of
# each schedule is still checked), the heal mutants, and a coverage-seed
# search for the one counter the heal moved.
cd /home/ian/code/scratch/d269b3ff-model7/vault
B=target/release/vault-model
R=crates/freenet-vault-model/results/rev10.2-heal
t() { local name=$1; shift; local s=$(date +%s); COV_ALL=1 "$B" "$@" > $R/$name.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/$name.log; echo "$name done"; }
t core-100k-strict --seeds 100000 --shrink 1
HEAL_I6_COUNT_ONLY=1 t core-100k-diag --seeds 100000 --shrink 1
MUTANTS_ONLY=HealWithoutDigestCheck,HealWhileSealed HEAL_I6_COUNT_ONLY=1 t mutants-heal-20k-diag --mutants --seeds 20000 --shrink 1
t find-staging-full --find "7.2/outcome-staging-full" --seeds 400000 --start 0
echo ALL DONE
