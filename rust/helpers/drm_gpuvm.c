// SPDX-License-Identifier: GPL-2.0 or MIT

#include <drm/drm_gpuvm.h>

struct drm_gpuvm *rust_helper_drm_gpuvm_get(struct drm_gpuvm *obj)
{
	return drm_gpuvm_get(obj);
}

void rust_helper_drm_gpuva_init_from_op(struct drm_gpuva *va, struct drm_gpuva_op_map *op)
{
	drm_gpuva_init_from_op(va, op);
}

struct drm_gpuvm_bo *rust_helper_drm_gpuvm_bo_get(struct drm_gpuvm_bo *vm_bo)
{
	return drm_gpuvm_bo_get(vm_bo);
}
