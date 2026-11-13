// SPDX-License-Identifier: GPL-2.0

#include <linux/dma-fence-chain.h>

#ifdef CONFIG_DMA_SHARED_BUFFER

__rust_helper struct dma_fence_chain *rust_helper_dma_fence_chain_alloc(void)
{
	return dma_fence_chain_alloc();
}

__rust_helper
void rust_helper_dma_fence_chain_free(struct dma_fence_chain *chain)
{
	dma_fence_chain_free(chain);
}

#endif
