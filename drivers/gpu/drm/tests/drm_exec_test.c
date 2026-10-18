// SPDX-License-Identifier: MIT
/*
 * Copyright 2022 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt) "drm_exec: " fmt

#include <kunit/test.h>

#include <linux/completion.h>
#include <linux/dma-resv.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/prime_numbers.h>

#include <drm/drm_exec.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_kunit_helpers.h>

struct drm_exec_priv {
	struct device *dev;
	struct drm_device *drm;
};

static int drm_exec_test_init(struct kunit *test)
{
	struct drm_exec_priv *priv;

	priv = kunit_kzalloc(test, sizeof(*priv), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv);

	test->priv = priv;

	priv->dev = drm_kunit_helper_alloc_device(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv->dev);

	priv->drm = __drm_kunit_helper_alloc_drm_device(test, priv->dev, sizeof(*priv->drm), 0,
							DRIVER_MODESET);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, priv->drm);

	return 0;
}

static void sanitycheck(struct kunit *test)
{
	struct drm_exec exec;

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_fini(&exec);
	KUNIT_SUCCEED(test);
}

static void test_lock(struct kunit *test)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_gem_object gobj = { };
	struct drm_exec exec;
	int ret;

	drm_gem_private_object_init(priv->drm, &gobj, PAGE_SIZE);

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_until_all_locked(&exec) {
		ret = drm_exec_lock_obj(&exec, &gobj);
		drm_exec_retry_on_contention(&exec);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			break;
	}
	drm_exec_fini(&exec);
}

static void test_lock_unlock(struct kunit *test)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_gem_object gobj = { };
	struct drm_exec exec;
	int ret;

	drm_gem_private_object_init(priv->drm, &gobj, PAGE_SIZE);

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_until_all_locked(&exec) {
		ret = drm_exec_lock_obj(&exec, &gobj);
		drm_exec_retry_on_contention(&exec);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			break;

		drm_exec_unlock_obj(&exec, &gobj);
		ret = drm_exec_lock_obj(&exec, &gobj);
		drm_exec_retry_on_contention(&exec);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			break;
	}
	drm_exec_fini(&exec);
}

static void test_duplicates(struct kunit *test)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_gem_object gobj = { };
	struct drm_exec exec;
	int ret;

	drm_gem_private_object_init(priv->drm, &gobj, PAGE_SIZE);

	drm_exec_init(&exec, DRM_EXEC_IGNORE_DUPLICATES, 0);
	drm_exec_until_all_locked(&exec) {
		ret = drm_exec_lock_obj(&exec, &gobj);
		drm_exec_retry_on_contention(&exec);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			break;

		ret = drm_exec_lock_obj(&exec, &gobj);
		drm_exec_retry_on_contention(&exec);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			break;
	}
	drm_exec_unlock_obj(&exec, &gobj);
	drm_exec_fini(&exec);
}

static void test_prepare(struct kunit *test)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_gem_object gobj = { };
	struct drm_exec exec;
	int ret;

	drm_gem_private_object_init(priv->drm, &gobj, PAGE_SIZE);

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_until_all_locked(&exec) {
		ret = drm_exec_prepare_obj(&exec, &gobj, 1);
		drm_exec_retry_on_contention(&exec);
		KUNIT_EXPECT_EQ(test, ret, 0);
		if (ret)
			break;
	}
	drm_exec_fini(&exec);

	drm_gem_private_object_fini(&gobj);
}

static void test_prepare_array(struct kunit *test)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_gem_object *gobj1;
	struct drm_gem_object *gobj2;
	struct drm_gem_object *array[] = {
		(gobj1 = kunit_kzalloc(test, sizeof(*gobj1), GFP_KERNEL)),
		(gobj2 = kunit_kzalloc(test, sizeof(*gobj2), GFP_KERNEL)),
	};
	struct drm_exec exec;
	int ret;

	if (!gobj1 || !gobj2) {
		KUNIT_FAIL(test, "Failed to allocate GEM objects.\n");
		return;
	}

	drm_gem_private_object_init(priv->drm, gobj1, PAGE_SIZE);
	drm_gem_private_object_init(priv->drm, gobj2, PAGE_SIZE);

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_until_all_locked(&exec)
		ret = drm_exec_prepare_array(&exec, array, ARRAY_SIZE(array),
					     1);
	KUNIT_EXPECT_EQ(test, ret, 0);
	drm_exec_fini(&exec);

	drm_gem_private_object_fini(gobj1);
	drm_gem_private_object_fini(gobj2);
}

static void test_multiple_loops(struct kunit *test)
{
	struct drm_exec exec;

	{
		__label__ drm_exec_retry;

		drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
		drm_exec_until_all_locked(&exec)
		{
			break;
		}
		drm_exec_fini(&exec);
	}

	{
		__label__ drm_exec_retry;

		drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
		drm_exec_until_all_locked(&exec)
		{
			break;
		}
		drm_exec_fini(&exec);
	}
	KUNIT_SUCCEED(test);
}

struct drm_exec_holder {
	struct drm_gem_object *obj;
	struct completion locked;
	struct completion release;
	struct completion done;
	int ret;
};

static int drm_exec_holder_fn(void *data)
{
	struct drm_exec_holder *holder = data;
	struct drm_exec exec;

	drm_exec_init(&exec, 0, 0);
	drm_exec_until_all_locked(&exec) {
		holder->ret = drm_exec_lock_obj(&exec, holder->obj);
		drm_exec_retry_on_contention(&exec);
	}
	complete(&holder->locked);
	wait_for_completion(&holder->release);
	drm_exec_fini(&exec);
	kthread_complete_and_exit(&holder->done, 0);
}

/* Lock @obj in another thread, with an acquire context older than the test's */
static struct drm_exec_holder *drm_exec_holder_start(struct kunit *test,
						     struct drm_gem_object *obj)
{
	struct drm_exec_holder *holder;
	struct task_struct *task;

	holder = kunit_kzalloc(test, sizeof(*holder), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, holder);

	holder->obj = obj;
	init_completion(&holder->locked);
	init_completion(&holder->release);
	init_completion(&holder->done);

	task = kthread_run(drm_exec_holder_fn, holder, "drm_exec_holder");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, task);
	wait_for_completion(&holder->locked);
	KUNIT_EXPECT_EQ(test, holder->ret, 0);

	return holder;
}

static void drm_exec_holder_stop(struct drm_exec_holder *holder)
{
	complete(&holder->release);
	wait_for_completion(&holder->done);
}

/* Allocate and initialize a GEM object, using @resv if set */
static struct drm_gem_object *drm_exec_test_alloc_obj(struct kunit *test,
						      struct dma_resv *resv)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_gem_object *obj;

	obj = kunit_kzalloc(test, sizeof(*obj), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, obj);

	obj->resv = resv;
	drm_gem_private_object_init(priv->drm, obj, PAGE_SIZE);

	return obj;
}

/*
 * Lock @obj and back off on the holder's object, then retry with @obj and, if
 * set, @dup, but without the holder's object.
 */
static void drm_exec_skip_contended(struct kunit *test, struct drm_exec *exec,
				    struct drm_exec_holder *holder,
				    struct drm_gem_object *obj,
				    struct drm_gem_object *dup)
{
	bool retried = false;
	int ret;

	drm_exec_until_all_locked(exec) {
		ret = drm_exec_lock_obj(exec, obj);
		drm_exec_retry_on_contention(exec);
		KUNIT_EXPECT_EQ(test, ret, 0);

		if (!retried) {
			retried = true;
			ret = drm_exec_lock_obj(exec, holder->obj);
			KUNIT_EXPECT_EQ(test, ret, -EDEADLK);
			drm_exec_holder_stop(holder);
			drm_exec_retry_on_contention(exec);
		} else if (dup) {
			ret = drm_exec_lock_obj(exec, dup);
			drm_exec_retry_on_contention(exec);
			KUNIT_EXPECT_EQ(test, ret, 0);
		}
	}
}

static void test_contended_not_locked_again(struct kunit *test)
{
	struct drm_exec_holder *holder;
	struct drm_gem_object *gobj1;
	struct drm_gem_object *gobj2;
	struct drm_gem_object *obj;
	struct drm_exec exec;

	gobj1 = drm_exec_test_alloc_obj(test, NULL);
	gobj2 = drm_exec_test_alloc_obj(test, NULL);
	holder = drm_exec_holder_start(test, gobj1);

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_skip_contended(test, &exec, holder, gobj2, NULL);
	drm_exec_for_each_locked_object(&exec, obj)
		KUNIT_EXPECT_PTR_NE(test, obj, gobj1);
	KUNIT_EXPECT_FALSE(test, dma_resv_is_locked(gobj1->resv));
	drm_exec_fini(&exec);

	drm_gem_private_object_fini(gobj1);
	drm_gem_private_object_fini(gobj2);
}

static void test_contended_shared_resv(struct kunit *test)
{
	struct drm_exec_holder *holder;
	struct drm_gem_object *gobj1;
	struct drm_gem_object *gobj2;
	struct drm_gem_object *gobj3;
	struct drm_gem_object *obj;
	struct drm_exec exec;
	bool found = false;

	gobj1 = drm_exec_test_alloc_obj(test, NULL);
	gobj2 = drm_exec_test_alloc_obj(test, NULL);
	gobj3 = drm_exec_test_alloc_obj(test, gobj1->resv);
	holder = drm_exec_holder_start(test, gobj1);

	drm_exec_init(&exec, DRM_EXEC_IGNORE_DUPLICATES, 0);
	drm_exec_skip_contended(test, &exec, holder, gobj2, gobj3);
	drm_exec_for_each_locked_object(&exec, obj)
		found |= obj->resv == gobj3->resv;
	KUNIT_EXPECT_TRUE(test, found);
	KUNIT_EXPECT_TRUE(test, dma_resv_is_locked(gobj3->resv));
	drm_exec_fini(&exec);

	drm_gem_private_object_fini(gobj1);
	drm_gem_private_object_fini(gobj2);
	drm_gem_private_object_fini(gobj3);
}

struct drm_exec_test_obj {
	struct drm_gem_object base;
	struct drm_gem_object *other;
	bool freed;
	bool other_locked;
};

static void drm_exec_test_obj_free(struct drm_gem_object *gobj)
{
	struct drm_exec_test_obj *tobj =
		container_of(gobj, struct drm_exec_test_obj, base);

	tobj->other_locked = dma_resv_is_locked(tobj->other->resv);
	tobj->freed = true;
	drm_gem_private_object_fini(gobj);
}

static const struct drm_gem_object_funcs drm_exec_test_obj_funcs = {
	.free = drm_exec_test_obj_free,
};

static void test_contended_last_put(struct kunit *test)
{
	struct drm_exec_priv *priv = test->priv;
	struct drm_exec_holder *holder;
	struct drm_exec_test_obj *tobj;
	struct drm_gem_object *gobj;
	struct drm_exec exec;

	tobj = kunit_kzalloc(test, sizeof(*tobj), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tobj);

	gobj = drm_exec_test_alloc_obj(test, NULL);
	tobj->base.funcs = &drm_exec_test_obj_funcs;
	tobj->other = gobj;
	drm_gem_private_object_init(priv->drm, &tobj->base, PAGE_SIZE);
	holder = drm_exec_holder_start(test, &tobj->base);

	/* Leave the last reference to the holder and then to the exec */
	drm_gem_object_put(&tobj->base);

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_skip_contended(test, &exec, holder, gobj, NULL);
	KUNIT_EXPECT_TRUE(test, tobj->freed);
	KUNIT_EXPECT_FALSE(test, tobj->other_locked);
	drm_exec_fini(&exec);

	drm_gem_private_object_fini(gobj);
}

static struct kunit_case drm_exec_tests[] = {
	KUNIT_CASE(sanitycheck),
	KUNIT_CASE(test_lock),
	KUNIT_CASE(test_lock_unlock),
	KUNIT_CASE(test_duplicates),
	KUNIT_CASE(test_prepare),
	KUNIT_CASE(test_prepare_array),
	KUNIT_CASE(test_multiple_loops),
	KUNIT_CASE(test_contended_not_locked_again),
	KUNIT_CASE(test_contended_shared_resv),
	KUNIT_CASE(test_contended_last_put),
	{}
};

static struct kunit_suite drm_exec_test_suite = {
	.name = "drm_exec",
	.init = drm_exec_test_init,
	.test_cases = drm_exec_tests,
};

kunit_test_suite(drm_exec_test_suite);

MODULE_AUTHOR("AMD");
MODULE_DESCRIPTION("Kunit test for drm_exec functions");
MODULE_LICENSE("GPL and additional rights");
