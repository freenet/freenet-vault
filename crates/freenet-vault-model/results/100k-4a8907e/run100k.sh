#!/bin/bash
# 100k-schedule runs of the handover model: core (gating) and adversarial,
# each with and without the F1 fix (--accept-query-answer), since a run
# records only its first violation and F1 masks the others.
D=/home/ian/code/scratch/d269b3ff-model3/vault
B=$D/target/release/vault-model
R=$D/results
git -C $D rev-parse HEAD > $R/run100k.sha
COV_ALL=1 $B --seeds 100000 --shrink 1 > $R/core-100k.log 2>&1; echo "exit $?" >> $R/core-100k.log
COV_ALL=1 $B --seeds 100000 --shrink 1 --accept-query-answer > $R/core-100k-aqa.log 2>&1; echo "exit $?" >> $R/core-100k-aqa.log
COV_ALL=1 $B --seeds 100000 --shrink 1 --adversarial > $R/adversarial-100k.log 2>&1; echo "exit $?" >> $R/adversarial-100k.log
COV_ALL=1 $B --seeds 100000 --shrink 1 --adversarial --accept-query-answer > $R/adversarial-100k-aqa.log 2>&1; echo "exit $?" >> $R/adversarial-100k-aqa.log
echo done > $R/run100k.done
