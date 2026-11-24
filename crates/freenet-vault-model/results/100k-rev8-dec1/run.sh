#!/bin/bash
# 100k core and adversarial runs at the commit with the decision 1 counters
# (awaiting-path crash, two queriers of one predecessor, lost/duplicated 0x0B).
D=/home/ian/code/scratch/d269b3ff-model4/vault
B=$D/target/release/vault-model
R=$D/crates/freenet-vault-model/results/100k-rev8-dec1
P=/home/ian/code/scratch/d269b3ff/sim4-PROGRESS.md
git -C $D rev-parse HEAD > $R/sha
for m in core adversarial; do
  a=""; [ $m = adversarial ] && a=--adversarial
  echo "$(date -u +%FT%TZ) dec1 100k $m started" >> $P
  COV_ALL=1 $B --seeds 100000 --shrink 0 $a > $R/$m-100k.log 2>&1
  echo "exit $?" >> $R/$m-100k.log
  echo "$(date -u +%FT%TZ) dec1 100k $m finished" >> $P
done
echo done > $R/done
