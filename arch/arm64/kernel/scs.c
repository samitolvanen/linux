// SPDX-License-Identifier: GPL-2.0
/*
 * Shadow Call Stack support.
 *
 * Copyright (C) 2019 Google LLC
 */

#include <linux/percpu.h>
#include <asm/scs.h>

DEFINE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);

DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);

#ifdef CONFIG_ARM_SDE_INTERFACE
DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
#endif

void scs_init_irq(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu(irq_shadow_call_stack_ptr, cpu) =
			scs_alloc(cpu_to_node(cpu));
}


void scs_free_sdei(void)
{
	int cpu;
	void *s;

	if (!IS_ENABLED(CONFIG_ARM_SDE_INTERFACE))
		return;

	for_each_possible_cpu(cpu) {
		s = per_cpu(sdei_shadow_call_stack_normal_ptr, cpu);
		if (s)
			scs_free(s);

		s = per_cpu(sdei_shadow_call_stack_critical_ptr, cpu);
		if (s)
			scs_free(s);
	}
}

int scs_init_sdei(void)
{
	int cpu;
	void *s;

	if (!IS_ENABLED(CONFIG_ARM_SDE_INTERFACE))
		return 0;

	for_each_possible_cpu(cpu) {
		s = scs_alloc(cpu_to_node(cpu));
		if (!s)
			goto err;
		per_cpu(sdei_shadow_call_stack_normal_ptr, cpu) = s;

		s = scs_alloc(cpu_to_node(cpu));
		if (!s)
			goto err;
		per_cpu(sdei_shadow_call_stack_critical_ptr, cpu) = s;
	}

	return 0;

err:
	scs_free_sdei();
	return -ENOMEM;
}
