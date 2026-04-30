# SPDX-License-Identifier: GPL-2.0 or MIT

panthor-y := \
	panthor_devfreq.o \
	panthor_device.o \
	panthor_drv.o \
	panthor_fw.o \
	panthor_gem.o \
	panthor_gpu.o \
	panthor_heap.o \
	panthor_hw.o \
	panthor_mmu.o \
	panthor_pwr.o \
	panthor_sched.o

obj-$(CONFIG_DRM_PANTHOR_TRACE) += panthor_trace_points.o

CFLAGS_panthor_trace_points.o := -I$(src)

obj-$(CONFIG_DRM_PANTHOR) += panthor.o

CFLAGS_panthor_gpu.o := -I$(src)
