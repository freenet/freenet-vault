#!/bin/bash
# 100k-schedule runs of the handover model against protocol revision 9:
# core delivery (gating) and adversarial delivery with the document's
# readings (vault:parts after the first index is now the only ordering),
# plus core runs under the two alternative labelled readings, and the
# 2,000-seed gate.
D=/home/ian/code/scratch/d269b3ff-model5/vault
B=$D/target/release/vault-model
R=$D/crates/freenet-vault-model/results/100k-rev9
P=/home/ian/code/scratch/d269b3ff/sim5-PROGRESS.md
git -C $D rev-parse HEAD > $R/run100k.sha
run() {
  name=$1; shift
  echo "$(date -u +%FT%TZ) $name started" >> $P
  COV_ALL=1 $B --shrink 1 "$@" > $R/$name.log 2>&1
  echo "exit $?" >> $R/$name.log
  echo "$(date -u +%FT%TZ) $name finished: $(grep -c '^violation' $R/$name.log) violation kinds" >> $P
}
run gate-2000 --seeds 2000
run core-100k --seeds 100000
run adversarial-100k --seeds 100000 --adversarial
run core-100k-no-list-none-indexes --seeds 100000 --no-list-none-indexes
run core-100k-gc-old-after-index --seeds 100000 --gc-old-after-index
echo done > $R/run100k.done
