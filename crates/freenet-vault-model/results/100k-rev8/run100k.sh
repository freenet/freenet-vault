#!/bin/bash
# 100k-schedule runs of the handover model against protocol revision 8:
# core (gating) and adversarial delivery, each with the default vault:parts
# ordering (vault:parts before the first index write) and with
# --parts-after-index (the reading that removes finding F8, so that the
# other invariants are measured without it masking them).
D=/home/ian/code/scratch/d269b3ff-model4/vault
B=$D/target/release/vault-model
R=$D/crates/freenet-vault-model/results/100k-rev8
P=/home/ian/code/scratch/d269b3ff/sim4-PROGRESS.md
git -C $D rev-parse HEAD > $R/run100k.sha
run() {
  name=$1; shift
  echo "$(date -u +%FT%TZ) 100k $name started" >> $P
  COV_ALL=1 $B --seeds 100000 --shrink 1 "$@" > $R/$name.log 2>&1
  echo "exit $?" >> $R/$name.log
  echo "$(date -u +%FT%TZ) 100k $name finished: $(grep -c '^violation' $R/$name.log) violation kinds" >> $P
}
run core-100k
run core-100k-parts-after-index --parts-after-index
run adversarial-100k --adversarial
run adversarial-100k-parts-after-index --adversarial --parts-after-index
echo done > $R/run100k.done
