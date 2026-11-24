# IntegrityGuard: working rules for the assistant

## Skills (always)

On every IntegrityGuard task, invoke these skills with the Skill tool at the start of the relevant step, without asking:

- superpowers:using-superpowers at the start of a conversation;
- superpowers:writing-plans before any multi-step change (shard builds, evaluations, GUI or pipeline changes);
- superpowers:subagent-driven-development and superpowers:dispatching-parallel-agents: multi-step work goes to subagents, independent tasks in parallel;
- superpowers:systematic-debugging before proposing a fix for any error;
- superpowers:test-driven-development for code changes in integrityguard/ (failing test first);
- superpowers:verification-before-completion before claiming a build, evaluation, commit, push or app restart succeeded, with the command output shown.

## Subagents (always)

Multi-step work (evaluations, shard builds, searches, document updates, commits) is started as a subagent with a written brief. The main session keeps design decisions, questions to the user and the final report.

## Pre-registration and evidence

- Write the registration (script hash, split, criteria) before running an evaluation.
- Never change criteria after a run without recording the change and the reason.
- A criterion is "passed" only when the number meets the registered threshold, including confidence bounds. Report failed criteria as failed.

## Build and app

- Do not build into dist/IntegrityGuard while the app runs; close the app gracefully first, build into a staging folder, then swap through an elevated script.
- After a successful rebuild, the app must be restarted from dist/IntegrityGuard, and the process path verified.

## Safety

- Lab traffic only inside the lab subnet 172.20.0.0/24.
- No blocking, no promotion of any model without an explicit decision from the user.
