#include <linux/module.h>
#include <linux/types.h>
#include <linux/export.h>
#include "panthor_trace.h"

#define CREATE_TRACE_POINTS
#include <trace/events/panthor.h>

MODULE_LICENSE("GPL and additional rights");
MODULE_DESCRIPTION("Panthor Tracepoints");
