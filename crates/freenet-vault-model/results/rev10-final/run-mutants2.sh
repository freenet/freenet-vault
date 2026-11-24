#!/bin/bash
# sim-model-7: mutation check with this run's finding labels (G1, G2) not
# blocking (rule (a)), under the literal readings and under the alternative
# readings that remove G1 and G3.
cd /home/ian/code/scratch/d269b3ff-model7/vault
B=target/release/vault-model
R=crates/freenet-vault-model/results/rev10-final
NB=I2-two-index-lost-unlisted-state-7,I7-receiver-index-lost,I3-retired-parts-malformed,I2-retired-parts-malformed,I3-retired-parts-absent,I2-retired-parts-absent,I3-damaged-partial-receiver-unlisted,I2-damaged-partial-receiver-unlisted
s=$(date +%s); "$B" --mutants --seeds 20000 --shrink 0 --not-blocking $NB > $R/mutants-20k-literal-nb.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/mutants-20k-literal-nb.log; echo literal done
s=$(date +%s); "$B" --mutants --seeds 20000 --shrink 0 --not-blocking $NB --absent-parts-valid-list --catchall-answers-nothing > $R/mutants-20k-alt-nb.log 2>&1; echo "exit $? runtime $(( $(date +%s) - s ))s" >> $R/mutants-20k-alt-nb.log; echo ALL DONE
