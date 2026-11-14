/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Debug tracepoints for the Rust DRM JobQueue.
 *
 * Downstream-only debug aid, not for upstream.
 *
 * Copyright (C) 2026 Google LLC.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rust_jq_debug

#if !defined(_RUST_JQ_DEBUG_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _RUST_JQ_DEBUG_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

/*
 * jq_id is the JobQueue's dma_fence context, and seqno is the seqno of the
 * job's fence. Before submit, job (the address of its JobInternal) identifies
 * the job.
 *
 * The values below match the enums in rust/kernel/drm/job_queue_trace.rs.
 */

#define RUST_JQ_DEP_ACTION				\
	{ 0, "ADDED" },					\
	{ 1, "SIGNALED" },				\
	{ 2, "OWN_DROPPED" },				\
	{ 3, "ALLOC_FAIL" },				\
	{ 4, "WITH" }

#define RUST_JQ_WORKER					\
	{ 0, "SUBMIT" },				\
	{ 1, "DROP" }

#define RUST_JQ_KICK_SOURCE				\
	{ 0, "SUBMIT" },				\
	{ 1, "DEP" },					\
	{ 2, "COMPLETION" },				\
	{ 3, "WAKE" },					\
	{ 4, "UNPARK" },				\
	{ 5, "RUN_RACE" }

#define RUST_JQ_RUN_RESULT				\
	{ 0, "RAN" },					\
	{ 1, "NO_RESOURCES" }

#define RUST_JQ_END_REASON				\
	{ 0, "EMPTY" },					\
	{ 1, "PARKED" },				\
	{ 2, "DEPS" },					\
	{ 3, "CAPACITY" },				\
	{ 4, "NO_RESOURCES" },				\
	{ 5, "REVOKED" }

#define RUST_JQ_DROP_PHASE				\
	{ 0, "BEGIN" },					\
	{ 1, "END" }

TRACE_EVENT(rust_jq_job_new,
	TP_PROTO(u64 jq_id, unsigned long job, u32 cost, u64 max_capacity),
	TP_ARGS(jq_id, job, cost, max_capacity),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(unsigned long, job)
		__field(u32, cost)
		__field(u64, max_capacity)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->job = job;
		__entry->cost = cost;
		__entry->max_capacity = max_capacity;
	),
	TP_printk("jq_id=%llu job=%p cost=%u max_capacity=%llu",
		  __entry->jq_id, (void *)__entry->job, __entry->cost,
		  __entry->max_capacity)
);

/*
 * WITH marks a fence passed to add_dependency_with(), which does not walk a
 * dma_fence_chain. The event for what happened to the fence follows it.
 */
TRACE_EVENT(rust_jq_dep,
	TP_PROTO(u64 jq_id, unsigned long job, u64 dep_ctx, u64 dep_seqno,
		 u32 action),
	TP_ARGS(jq_id, job, dep_ctx, dep_seqno, action),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(unsigned long, job)
		__field(u64, dep_ctx)
		__field(u64, dep_seqno)
		__field(u32, action)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->job = job;
		__entry->dep_ctx = dep_ctx;
		__entry->dep_seqno = dep_seqno;
		__entry->action = action;
	),
	TP_printk("jq_id=%llu job=%p dep_ctx=%llu dep_seqno=%llu action=%s",
		  __entry->jq_id, (void *)__entry->job, __entry->dep_ctx,
		  __entry->dep_seqno,
		  __print_symbolic(__entry->action, RUST_JQ_DEP_ACTION))
);

/*
 * A walk of the links of ctx/seqno under serial execution. A truncated walk
 * leaves rest_ctx/rest_seqno, which the job then waits for as one fence.
 */
TRACE_EVENT(rust_jq_dep_walk,
	TP_PROTO(u64 jq_id, unsigned long job, u64 ctx, u64 seqno,
		 bool truncated, unsigned long visited, u64 rest_ctx,
		 u64 rest_seqno, unsigned long budget_left),
	TP_ARGS(jq_id, job, ctx, seqno, truncated, visited, rest_ctx,
		rest_seqno, budget_left),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(unsigned long, job)
		__field(u64, ctx)
		__field(u64, seqno)
		__field(bool, truncated)
		__field(unsigned long, visited)
		__field(u64, rest_ctx)
		__field(u64, rest_seqno)
		__field(unsigned long, budget_left)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->job = job;
		__entry->ctx = ctx;
		__entry->seqno = seqno;
		__entry->truncated = truncated;
		__entry->visited = visited;
		__entry->rest_ctx = rest_ctx;
		__entry->rest_seqno = rest_seqno;
		__entry->budget_left = budget_left;
	),
	TP_printk("jq_id=%llu job=%p ctx=%llu seqno=%llu result=%s visited=%lu rest_ctx=%llu rest_seqno=%llu budget_left=%lu",
		  __entry->jq_id, (void *)__entry->job, __entry->ctx,
		  __entry->seqno,
		  __entry->truncated ? "TRUNCATED" : "COMPLETE",
		  __entry->visited, __entry->rest_ctx, __entry->rest_seqno,
		  __entry->budget_left)
);

TRACE_EVENT(rust_jq_submit,
	TP_PROTO(u64 jq_id, u64 seqno, unsigned long job, u32 cost,
		 u32 pending_deps, u64 capacity),
	TP_ARGS(jq_id, seqno, job, cost, pending_deps, capacity),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u64, seqno)
		__field(unsigned long, job)
		__field(u32, cost)
		__field(u32, pending_deps)
		__field(u64, capacity)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->seqno = seqno;
		__entry->job = job;
		__entry->cost = cost;
		__entry->pending_deps = pending_deps;
		__entry->capacity = capacity;
	),
	TP_printk("jq_id=%llu seqno=%llu job=%p cost=%u pending_deps=%u capacity=%llu",
		  __entry->jq_id, __entry->seqno, (void *)__entry->job,
		  __entry->cost, __entry->pending_deps, __entry->capacity)
);

TRACE_EVENT(rust_jq_dep_signal,
	TP_PROTO(u64 jq_id, unsigned long job, u64 dep_ctx, u64 dep_seqno,
		 int errno, u32 remaining),
	TP_ARGS(jq_id, job, dep_ctx, dep_seqno, errno, remaining),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(unsigned long, job)
		__field(u64, dep_ctx)
		__field(u64, dep_seqno)
		__field(int, errno)
		__field(u32, remaining)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->job = job;
		__entry->dep_ctx = dep_ctx;
		__entry->dep_seqno = dep_seqno;
		__entry->errno = errno;
		__entry->remaining = remaining;
	),
	TP_printk("jq_id=%llu job=%p dep_ctx=%llu dep_seqno=%llu errno=%d remaining=%u",
		  __entry->jq_id, (void *)__entry->job, __entry->dep_ctx,
		  __entry->dep_seqno, __entry->errno, __entry->remaining)
);

TRACE_EVENT(rust_jq_kill,
	TP_PROTO(u64 jq_id, int errno),
	TP_ARGS(jq_id, errno),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(int, errno)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->errno = errno;
	),
	TP_printk("jq_id=%llu errno=%d", __entry->jq_id, __entry->errno)
);

/* queued is false when the worker was already pending. */
TRACE_EVENT(rust_jq_kick,
	TP_PROTO(u64 jq_id, u32 worker, u32 source, bool queued),
	TP_ARGS(jq_id, worker, source, queued),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u32, worker)
		__field(u32, source)
		__field(bool, queued)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->worker = worker;
		__entry->source = source;
		__entry->queued = queued;
	),
	TP_printk("jq_id=%llu worker=%s source=%s queued=%d",
		  __entry->jq_id,
		  __print_symbolic(__entry->worker, RUST_JQ_WORKER),
		  __print_symbolic(__entry->source, RUST_JQ_KICK_SOURCE),
		  __entry->queued)
);

TRACE_EVENT(rust_jq_worker_begin,
	TP_PROTO(u64 jq_id, u64 capacity, u64 last_completed, bool parked,
		 bool waiting_empty),
	TP_ARGS(jq_id, capacity, last_completed, parked, waiting_empty),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u64, capacity)
		__field(u64, last_completed)
		__field(bool, parked)
		__field(bool, waiting_empty)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->capacity = capacity;
		__entry->last_completed = last_completed;
		__entry->parked = parked;
		__entry->waiting_empty = waiting_empty;
	),
	TP_printk("jq_id=%llu capacity=%llu last_completed=%llu parked=%d waiting_empty=%d",
		  __entry->jq_id, __entry->capacity, __entry->last_completed,
		  __entry->parked, __entry->waiting_empty)
);

/* capacity is what is left once the job's cost is taken. */
TRACE_EVENT(rust_jq_run_job,
	TP_PROTO(u64 jq_id, u64 seqno, u32 cost, u64 capacity),
	TP_ARGS(jq_id, seqno, cost, capacity),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u64, seqno)
		__field(u32, cost)
		__field(u64, capacity)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->seqno = seqno;
		__entry->cost = cost;
		__entry->capacity = capacity;
	),
	TP_printk("jq_id=%llu seqno=%llu cost=%u capacity=%llu",
		  __entry->jq_id, __entry->seqno, __entry->cost,
		  __entry->capacity)
);

/* completed_in_run is set when the job completed while run_job() ran. */
TRACE_EVENT(rust_jq_run_job_done,
	TP_PROTO(u64 jq_id, u64 seqno, u32 result, bool completed_in_run,
		 u64 capacity),
	TP_ARGS(jq_id, seqno, result, completed_in_run, capacity),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u64, seqno)
		__field(u32, result)
		__field(bool, completed_in_run)
		__field(u64, capacity)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->seqno = seqno;
		__entry->result = result;
		__entry->completed_in_run = completed_in_run;
		__entry->capacity = capacity;
	),
	TP_printk("jq_id=%llu seqno=%llu result=%s completed_in_run=%d capacity=%llu",
		  __entry->jq_id, __entry->seqno,
		  __print_symbolic(__entry->result, RUST_JQ_RUN_RESULT),
		  __entry->completed_in_run, __entry->capacity)
);

/*
 * head_* describe the job the worker stopped at, and are 0 without one.
 * REVOKED sets only jq_id.
 */
TRACE_EVENT(rust_jq_worker_end,
	TP_PROTO(u64 jq_id, u32 reason, u32 ran, u64 head_seqno,
		 u32 head_deps, u32 head_cost, u64 capacity),
	TP_ARGS(jq_id, reason, ran, head_seqno, head_deps, head_cost,
		capacity),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u32, reason)
		__field(u32, ran)
		__field(u64, head_seqno)
		__field(u32, head_deps)
		__field(u32, head_cost)
		__field(u64, capacity)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->reason = reason;
		__entry->ran = ran;
		__entry->head_seqno = head_seqno;
		__entry->head_deps = head_deps;
		__entry->head_cost = head_cost;
		__entry->capacity = capacity;
	),
	TP_printk("jq_id=%llu reason=%s ran=%u head_seqno=%llu head_deps=%u head_cost=%u capacity=%llu",
		  __entry->jq_id,
		  __print_symbolic(__entry->reason, RUST_JQ_END_REASON),
		  __entry->ran, __entry->head_seqno, __entry->head_deps,
		  __entry->head_cost, __entry->capacity)
);

/*
 * stale is set for a seqno already completed, which kicks nothing. Otherwise
 * the SubmitWorker is kicked when waiting is set.
 */
TRACE_EVENT(rust_jq_complete,
	TP_PROTO(u64 jq_id, u64 seqno, u32 count, int errno, u64 capacity,
		 bool waiting, bool stale),
	TP_ARGS(jq_id, seqno, count, errno, capacity, waiting, stale),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u64, seqno)
		__field(u32, count)
		__field(int, errno)
		__field(u64, capacity)
		__field(bool, waiting)
		__field(bool, stale)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->seqno = seqno;
		__entry->count = count;
		__entry->errno = errno;
		__entry->capacity = capacity;
		__entry->waiting = waiting;
		__entry->stale = stale;
	),
	TP_printk("jq_id=%llu seqno=%llu count=%u errno=%d capacity=%llu waiting=%d stale=%d",
		  __entry->jq_id, __entry->seqno, __entry->count,
		  __entry->errno, __entry->capacity, __entry->waiting,
		  __entry->stale)
);

/* count is the number of jobs dropped, and 0 at BEGIN. */
TRACE_EVENT(rust_jq_drop_batch,
	TP_PROTO(u64 jq_id, u32 count, u32 phase),
	TP_ARGS(jq_id, count, phase),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u32, count)
		__field(u32, phase)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->count = count;
		__entry->phase = phase;
	),
	TP_printk("jq_id=%llu count=%u phase=%s",
		  __entry->jq_id, __entry->count,
		  __print_symbolic(__entry->phase, RUST_JQ_DROP_PHASE))
);

TRACE_EVENT(rust_jq_park,
	TP_PROTO(u64 jq_id, bool parked),
	TP_ARGS(jq_id, parked),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(bool, parked)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->parked = parked;
	),
	TP_printk("jq_id=%llu parked=%d", __entry->jq_id, __entry->parked)
);

/* errno is the error the running jobs are signaled with. */
TRACE_EVENT(rust_jq_teardown,
	TP_PROTO(u64 jq_id, u32 running, u32 waiting, int errno),
	TP_ARGS(jq_id, running, waiting, errno),
	TP_STRUCT__entry(
		__field(u64, jq_id)
		__field(u32, running)
		__field(u32, waiting)
		__field(int, errno)
	),
	TP_fast_assign(
		__entry->jq_id = jq_id;
		__entry->running = running;
		__entry->waiting = waiting;
		__entry->errno = errno;
	),
	TP_printk("jq_id=%llu running=%u waiting=%u errno=%d",
		  __entry->jq_id, __entry->running, __entry->waiting,
		  __entry->errno)
);

#endif /* _RUST_JQ_DEBUG_TRACE_H */

/* This part must be outside protection. */
#include <trace/define_trace.h>
