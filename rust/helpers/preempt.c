// SPDX-License-Identifier: GPL-2.0

#include <linux/preempt.h>
#include <linux/irqflags.h>

__rust_helper void rust_helper_preempt_disable(void)
{
	preempt_disable();
}

__rust_helper void rust_helper_preempt_enable(void)
{
	preempt_enable();
}

__rust_helper unsigned long rust_helper_local_irq_save(void)
{
	unsigned long flags;

	local_irq_save(flags);
	return flags;
}

__rust_helper void rust_helper_local_irq_restore(unsigned long flags)
{
	local_irq_restore(flags);
}
