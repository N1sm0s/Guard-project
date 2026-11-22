# Codex guidance for IntegrityGuard

## Project context

IntegrityGuard monitors package integrity and host network telemetry. Network
telemetry currently consists of OS interface counters and socket metadata; it is
not packet-payload inspection. Keep that scope explicit in code and UI.

## Relevant Codex skills

For work on an LLM, agent, tool, or autonomous workflow, route through
`llm-agent-builder-copilot:get-started`, then use only the focused workflows that
fit the change:

- architecture and complexity: `llm-agent-builder-copilot:choose-system-complexity`,
  `llm-agent-builder-copilot:design-llm-system`,
  `llm-agent-builder-copilot:design-agent-architecture`,
  `llm-agent-builder-copilot:design-tool-contracts`,
  `llm-agent-builder-copilot:design-guardrails-and-approvals`;
- implementation and quality: `llm-agent-builder-copilot:implement-agent-workflow`,
  `llm-agent-builder-copilot:design-agent-evals`,
  `llm-agent-builder-copilot:review-agent-eval-results`,
  `llm-agent-builder-copilot:trace-and-observe`;
- security and release: `llm-agent-builder-copilot:review-agent-security`,
  `llm-agent-builder-copilot:prepare-agent-release`.

These are Codex working procedures. They are not runtime dependencies of the
IntegrityGuard application. Do not install unrelated skills or claim that a
skill is active inside the packaged executable.

## Model evidence and training

- Do not create or use synthetic network traffic or packages as evidence of model
  quality. Clearly separate deterministic code tests from model evaluation.
- Never treat a model prediction or DShield match as ground truth; never use
  synthetic traffic as evidence. Public, real capture datasets may use the
  dataset owner's published labels for research candidates when source,
  capture, label mapping, and SHA-256 are recorded. Local live telemetry must
  have independent incident evidence and complete provenance before it is used
  for target-network metrics or supervised learning; uncertain and background
  observations remain unlabeled.
- A snapshot is benign only when all observed remote endpoints are confirmed
  benign; partial and disputed labels remain excluded.
- Split evaluations by time/capture/incident with leakage controls. Keep a final
  independent test set out of training, early stopping, and threshold selection.
- Report per-class precision/recall, false-block rate, attack coverage, abstention
  rate, class counts, provenance, and limitations. Do not report a metric if the
  real sample support is insufficient.
- Keep learned network decisions advisory-only. Do not enable firewall blocking
  from an unvalidated checkpoint.

## Changes and verification

- Keep changes scoped to the requested work and preserve unrelated user changes.
- For changes to the Windows app, update the existing build output path; do not
  create additional shortcuts.
- After each successful app rebuild, restart the existing app instance so the
  user is running the updated `dist/IntegrityGuard/IntegrityGuard.exe`. Close
  the prior instance gracefully, avoid parallel instances, then verify the
  process path and visible build-specific UI before reporting success. If the
  prior process cannot be closed safely or the new build fails to open, report
  that explicitly and do not claim the update is active.
- Use real local observations for requested operational checks. Do not modify or
  relabel the user's evidence while checking the pipeline.
- Summarize what changed, what was actually verified, and what remains blocked by
  missing real evidence.
