# Tyr abstraction follow-ups

Open items where Tyr currently calls `rust/bindings/` directly because no
safe abstraction exists. Each item should become a separate patch landing
the abstraction in `rust/kernel/`, after which the corresponding direct
binding usage in Tyr should be replaced.

## Open

- `Bo::is_imported()` to encapsulate `(*bo.as_raw()).import_attach.is_null()`.
  Call sites: `drivers/gpu/drm/tyr/gem.rs::sync` (line ~371) and
  `drivers/gpu/drm/tyr/sched/queue.rs::user_stream_window_around`. Trivial
  helper; deferred to keep this patch focused on tracing.

## Resolved
