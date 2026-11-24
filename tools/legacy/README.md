# Archived legacy helpers

These scripts are retained for historical reference only. They are not part of
the active application workflow.

- `bulk_label.py` creates labels from prior application decisions. Those labels
  are circular and are not valid ground truth for model training or release
  evaluation. Do not run it on current data.
- `retrain_now.py` is an older snapshot classifier trainer and must not be used
  as the production packet-flow model trainer.

The maintained runtime and scheduled retraining tools live in the application
package and `tools/maintenance/` respectively.
