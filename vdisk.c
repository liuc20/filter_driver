#include "filter.h"

#define MEM_ERR_RAND_MASK	(0x7f)	/* control the error rate */

static void 
mem_vdisk_del_gendisk(struct mem_filter_vdisk_s *vdisk);

static void 
mem_filter_deinit_vdisk(struct mem_filter_vdisk_s *vdisk)
{
	#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
		blkdev_put(vdisk->vd_bdev, MEM_FILTER_OPEN_MODE);
	#else
		close_bdev_exclusive(vdisk->vd_bdev, MEM_FILTER_OPEN_MODE);
	#endif
}

static int
mem_filter_init_vdisk(struct mem_filter_vdisk_s *vdisk, char *path)
{
	struct block_device *bdev = NULL;
	int ret = 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
	bdev = blkdev_get_by_path(path, MEM_FILTER_OPEN_MODE, &g_mem_filter);
#else
	bdev = open_bdev_exclusive(path, MEM_FILTER_OPEN_MODE, &g_mem_filter);
#endif
	if (IS_ERR(bdev)) {
		printk(KERN_ERR "Get block device for %s failed!\n", path);
		ret = PTR_ERR(bdev);
		goto err_out0;
	}

	atomic_set(&vdisk->vd_opencnt, 0);
	sprintf(vdisk->vd_sys_devname, "%s", path);
	sprintf(vdisk->vd_devname, "%s_v", bdev->bd_disk->disk_name);
	vdisk->vd_bdev = bdev;
	vdisk->vd_status = MEM_VDISK_STATUS_NORMAL;
	vdisk->vd_first_minor = 
		atomic_read(&g_mem_filter.fi_vdisk_number) * MEM_FILTER_VDISK_MINORS;

	spin_lock_init(&vdisk->vd_list_lock);
	INIT_LIST_HEAD(&vdisk->vd_pending_list);

	rwlock_init(&vdisk->vd_io_rules.ioerr_lock);
	INIT_LIST_HEAD(&vdisk->vd_io_rules.ioerr_rule_list);
	INIT_LIST_HEAD(&vdisk->vd_ioctl_rules.ioctlerr_rule_list);

	spin_lock_init(&vdisk->vd_blk_rules.diskerr_lock);
	INIT_LIST_HEAD(&vdisk->vd_blk_rules.diskerr_rule_list);

	return ret;

	blkdev_put(bdev, MEM_FILTER_OPEN_MODE);
err_out0:
	return ret;
}

static void 
mem_vdisk_end_io(struct bio *vbio, int error)
{
	struct bio *bio = NULL;

	bio = (struct bio *)vbio->bi_private;

	if (bio->bi_end_io) {
		bio->bi_end_io(bio, error);
	}

	bio_put(vbio);
}

static void
__mem_vdisk_copy_bvec(struct bio *vbio, struct bio *bio)
{
	int i;

	for (i = 0; i < bio->bi_vcnt; i++) {
		vbio->bi_io_vec[i].bv_page = bio->bi_io_vec[i].bv_page;
		vbio->bi_io_vec[i].bv_len = bio->bi_io_vec[i].bv_len;
		vbio->bi_io_vec[i].bv_offset = bio->bi_io_vec[i].bv_offset;
	}
}

static struct bio*
mem_vdisk_clone_bio(struct mem_filter_vdisk_s *vdisk, struct bio *bio)
{
	struct bio *vbio = NULL;

	vbio = bio_alloc(GFP_KERNEL, bio->bi_vcnt);
	if (!bio) {
		printk(KERN_ALERT "alloc bio failed!\n");
		return ERR_PTR(-ENOMEM);
	}

	vbio->bi_bdev = vdisk->vd_bdev;

	vbio->bi_rw = bio->bi_rw;
	vbio->bi_sector = bio->bi_sector;
	vbio->bi_size = bio->bi_size;
	vbio->bi_vcnt = bio->bi_vcnt;
	vbio->bi_idx = bio->bi_idx;

	vbio->bi_private = bio;
	vbio->bi_end_io = mem_vdisk_end_io;

	__mem_vdisk_copy_bvec(vbio, bio);
	return vbio;
}

static int
mem_vdisk_submit_bio(struct mem_filter_vdisk_s *vdisk, struct bio *bio)
{
	struct bio *vbio = NULL;

	vbio = mem_vdisk_clone_bio(vdisk, bio);
	if (IS_ERR(vbio)) {
		printk(KERN_ALERT "Vdisk clone bio failed!\n");
		return PTR_ERR(vbio);
	}

	generic_make_request(vbio);
	return 0;
}

static int 
mem_vdisk_push_bio(struct mem_filter_vdisk_s *vdisk, struct bio *bio,
				   struct flt_io_rule_s *rule)
{
	struct mem_bio_handle_s *bio_handle = NULL;

	bio_handle = kmalloc(sizeof(*bio_handle), GFP_ATOMIC);
	if (!bio_handle) {
		printk(KERN_ALERT "Alloc memory for bio_handle failed!\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&bio_handle->bh_self);
	bio_handle->bh_bio = bio;
	bio_handle->bh_errtype = rule->ir_inject_type;
	bio_handle->bh_error = rule->ir_error;
	bio_handle->bh_latency_jiffies = jiffies + rule->ir_latency_jiffie;
	bio_handle->bh_rand_rate = rule->ir_trigger_rate;

	spin_lock_bh(&vdisk->vd_list_lock);
	list_add(&bio_handle->bh_self, &vdisk->vd_pending_list);
	spin_unlock_bh(&vdisk->vd_list_lock);

	return 0;
}

static void
mem_vdisk_latency_callback(struct bio *bio, int error)
{
	struct mem_bio_ctx_s *context = (struct mem_bio_ctx_s *)bio->bi_private;
	struct mem_filter_vdisk_s *vdisk = context->ctx_vdisk;
	struct flt_io_rule_s *rule = context->ctx_rule;
	int ret = 0;

	bio->bi_private = context->ctx_private;
	bio->bi_end_io = context->ctx_callback;
	kfree(context);

	ret = mem_vdisk_push_bio(vdisk, bio, rule);
	if (ret) {
		bio_endio(bio, -ENOMEM);
	}
}

static int 
mem_vdisk_submit_latency_bio(struct mem_filter_vdisk_s *vdisk, 
							 struct bio *bio, struct flt_io_rule_s *rule)
{
	struct mem_bio_ctx_s *context = NULL;
	int ret = 0;

	if (rule->ir_inject_type != MEM_FILTER_IO_NOERROR) {
		ret = mem_vdisk_push_bio(vdisk, bio, rule);
		return ret;
	} 

	context = kmalloc(sizeof(*context), GFP_KERNEL);
	if (!context) {
		printk(KERN_ALERT "Alloc memory for latency context failed!\n");
		return -ENOMEM;
	}

	context->ctx_vdisk = vdisk;
	context->ctx_rule = rule;
	context->ctx_private = bio->bi_private;
	context->ctx_callback = bio->bi_end_io;

	bio->bi_private = context;
	bio->bi_end_io = mem_vdisk_latency_callback;

	mem_vdisk_submit_bio(vdisk, bio);

	return 0;
}

static int 
mem_vdisk_iorule_match(struct mem_filter_vdisk_s *vdisk, struct bio *bio, 
					   struct flt_io_rule_s *rule)
{
	unsigned int rand_seed = 0;

	if (MEM_IORULE_PERIOD_ENABLE(rule->ir_enable_flag)) {
		if (time_before(jiffies, rule->ir_expires)) {
			return 0;
		} 
		rule->ir_io_applies --;	
		if (rule->ir_io_applies == 0) {
			rule->ir_io_applies = rule->ir_io_num;	

			if (time_after(jiffies, rule->ir_expires + rule->ir_period * 2)) {
				rule->ir_expires = jiffies + rule->ir_period;
			} else {
				rule->ir_expires += rule->ir_period;
			}
		}
	}

	if (MEM_IORULE_OP_ENABLE(rule->ir_enable_flag)) {
		if (bio_data_dir(bio) != rule->ir_op) {
			return 0;
		}
	}

	if (MEM_IORULE_RANGE_ENABLE(rule->ir_enable_flag)) {
		if (bio->bi_sector > rule->ir_end ||
			bio->bi_sector + MEM_BYTES_TO_SECTOR(bio->bi_size) < 
			rule->ir_start) {
			return 0;
		} 
	}

	if (MEM_IORULE_SIZE_ENABLE(rule->ir_enable_flag)) {
		if (bio->bi_size < rule->ir_bio_size) {
			return 0;
		} 
	}

	if (rule->ir_trigger_rate) {
		get_random_bytes(&rand_seed, sizeof(rand_seed));
		if (rand_seed % rule->ir_trigger_rate) {
			return 0;
		}
	}

	return 1;
}

static struct flt_io_rule_s*
mem_vdisk_get_io_errtype(struct mem_filter_vdisk_s *vdisk, struct bio *bio)
{
	struct flt_io_ruleset_s *rule_set = &vdisk->vd_io_rules;
	struct flt_io_rule_s *rule = NULL;
	int is_match = 0;

	read_lock(&rule_set->ioerr_lock);
	list_for_each_entry(rule, &rule_set->ioerr_rule_list, ir_self) {
		is_match = mem_vdisk_iorule_match(vdisk, bio, rule);
		if (is_match) {
			read_unlock(&rule_set->ioerr_lock);
			return rule;
		}
	}
	read_unlock(&rule_set->ioerr_lock);

	return NULL;
}

static void 
mem_vdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct mem_filter_vdisk_s *vdisk = NULL;
	struct flt_io_rule_s *rule = NULL;
	int ret = 0;
	io_error_type_t	error_type;

	vdisk = q->queuedata;
	MEM_ASSERT(vdisk);

	if (vdisk->vd_status == MEM_VDISK_STATUS_DESTROY) {
		ret = -EIO;
		goto out;
	}

	rule = mem_vdisk_get_io_errtype(vdisk, bio);
	if (!rule) {
		ret = mem_vdisk_submit_bio(vdisk, bio);
		goto out;
	}

	error_type = rule->ir_inject_type;
	MEM_ASSERT(error_type == MEM_FILTER_IO_TIMEOUT ||
			   error_type == MEM_FILTER_IO_ERROR ||
			   error_type == MEM_FILTER_IO_DATA_CORRUPT ||
			   error_type == MEM_FILTER_IO_NOERROR);

	if (rule->ir_latency_jiffie) {
		ret = mem_vdisk_submit_latency_bio(vdisk, bio, rule);
	} else {
		ret = mem_vdisk_push_bio(vdisk, bio, rule);
	}
	
out:
	if (ret) {
		bio_endio(bio, -EIO);
	}
	return;
}

static int 
mem_filter_init_device_queue(struct mem_filter_vdisk_s *vdisk)
{
	int ret = 0;
	struct request_queue *q = bdev_get_queue(vdisk->vd_bdev);

	MEM_ASSERT(q);
	vdisk->vd_queue = blk_alloc_queue(GFP_KERNEL);
	if (!vdisk->vd_queue) {
		printk(KERN_ERR "Vdisk alloc queue failed!\n");
		ret = -ENOMEM;
		goto err_out0;
	}

	blk_queue_make_request(vdisk->vd_queue, mem_vdisk_make_request);

	/* the filter deivce must looks like the physical device. */
	vdisk->vd_queue->nr_requests = q->nr_requests;
	vdisk->vd_queue->queuedata = vdisk;

	blk_queue_logical_block_size(vdisk->vd_queue, 
								 q->limits.logical_block_size);
	blk_queue_physical_block_size(vdisk->vd_queue, 
								  q->limits.physical_block_size);
	blk_queue_io_min(vdisk->vd_queue, q->limits.io_min);
	blk_queue_io_opt(vdisk->vd_queue, q->limits.io_opt);
	blk_queue_max_hw_sectors(vdisk->vd_queue, q->limits.max_hw_sectors);

	return ret;

err_out0:
	return ret;
}

static void 
mem_filter_deinit_device_disk(struct mem_filter_vdisk_s *vdisk)
{
	MEM_ASSERT(vdisk->vd_disk);
	del_gendisk(vdisk->vd_disk);
	vdisk->vd_disk = NULL;
}

static void
mem_filter_deinit_device_queue(struct mem_filter_vdisk_s *vdisk)
{
	MEM_ASSERT(vdisk->vd_queue);
	blk_cleanup_queue(vdisk->vd_queue);
	vdisk->vd_queue = NULL;
}

static int 
mem_filter_vdisk_open(struct block_device *bdev, fmode_t mode)
{
	struct gendisk *disk = bdev->bd_disk;
	struct mem_filter_vdisk_s *vdisk = NULL;

	vdisk = disk->queue->queuedata;
	atomic_inc(&vdisk->vd_opencnt);
	return 0;
}


static void 
mem_filter_vdisk_release(struct gendisk *gd, fmode_t mode)
{
	struct mem_filter_vdisk_s *vdisk = NULL;

	vdisk = gd->queue->queuedata;
	atomic_dec(&vdisk->vd_opencnt);
	return;
}

static int 
mem_filter_vdisk_ioctl(struct block_device *bdev, 
					   fmode_t mode, unsigned cmd, unsigned long args)
{
	return 0;
}

const struct block_device_operations mem_filter_vdisk_ops = {
	.open = mem_filter_vdisk_open,
	.release = mem_filter_vdisk_release,
	.ioctl = mem_filter_vdisk_ioctl,
	.owner = THIS_MODULE,
};

static int
mem_filter_init_device_disk(struct mem_filter_vdisk_s *vdisk)
{
	struct gendisk *bd_disk = NULL;
	int ret = 0;

	MEM_ASSERT(vdisk && vdisk->vd_queue);

	bd_disk = vdisk->vd_bdev->bd_disk;
	MEM_ASSERT(bd_disk);

	vdisk->vd_disk = alloc_disk(MEM_FILTER_VDISK_MINORS);
	if (!vdisk->vd_disk) {
		printk(KERN_ERR "alloc gendisk failed!\n");
		ret = -ENOMEM;
		goto err_out0;
	}

	vdisk->vd_disk->major = g_mem_filter.fi_vdisk_major;
	vdisk->vd_disk->first_minor = vdisk->vd_first_minor;
	vdisk->vd_disk->minors = MEM_FILTER_VDISK_MINORS; 

	vdisk->vd_disk->fops = &mem_filter_vdisk_ops;
	vdisk->vd_disk->queue = vdisk->vd_queue;
	vdisk->vd_disk->private_data = vdisk;

	snprintf(vdisk->vd_disk->disk_name, 32, "%s", vdisk->vd_devname);
	set_capacity(vdisk->vd_disk, get_capacity(bd_disk));
	add_disk(vdisk->vd_disk);

	return ret;

err_out0:
	return ret;
}

static void 
mem_filter_destory_filter_device(struct mem_filter_vdisk_s *vdisk)
{
	mem_filter_deinit_device_disk(vdisk);
	mem_filter_deinit_device_queue(vdisk);
}

static int
mem_filter_create_filter_device(struct mem_filter_vdisk_s *vdisk)
{
	int ret = 0;

	ret = mem_filter_init_device_queue(vdisk);
	if (ret) {
		printk(KERN_ERR "init device queue failed!\n");
		goto err_out0;
	}

	ret = mem_filter_init_device_disk(vdisk);
	if (ret) {
		printk(KERN_ERR "init device queue failed!\n");
		goto err_out1;
	}

	return ret;

err_out1:
	mem_filter_deinit_device_queue(vdisk);
err_out0:
	return ret;
}

void 
mem_filter_del_vdisk(struct mem_filter_vdisk_s *vdisk)
{
	spin_lock_bh(&g_mem_filter.fi_vdisklist_lock);
	list_del(&vdisk->vd_self);
	atomic_dec(&g_mem_filter.fi_vdisk_number);
	spin_unlock_bh(&g_mem_filter.fi_vdisklist_lock);
}

void 
mem_filter_add_vdisk(struct mem_filter_vdisk_s *vdisk)
{
	spin_lock_bh(&g_mem_filter.fi_vdisklist_lock);
	list_add(&vdisk->vd_self, &g_mem_filter.fi_vdisk_list);
	atomic_inc(&g_mem_filter.fi_vdisk_number);
	spin_unlock_bh(&g_mem_filter.fi_vdisklist_lock);
}

struct mem_filter_vdisk_s *
mem_create_vdisk(char *dev_path)
{
	struct mem_filter_vdisk_s *vdisk = NULL;
	int ret = 0;

	vdisk = kzalloc(sizeof(*vdisk), GFP_KERNEL);
	if (!vdisk) {
		printk(KERN_ERR "Alloc memory for vdisk failed!\n");
		ret = -ENOMEM;
		goto err_out0;
	}

	ret = mem_filter_init_vdisk(vdisk, dev_path);
	if (ret) {
		printk(KERN_ERR "Init vdisk failed!\n");
		goto err_out1;
	}

	ret = mem_filter_create_filter_device(vdisk);
	if (ret) {
		printk(KERN_ERR "Create filter device for vdisk 0x%p failed!\n", vdisk);
		goto err_out2;
	}

	return vdisk;

	mem_filter_destory_filter_device(vdisk);
err_out2:
	mem_filter_deinit_vdisk(vdisk);
err_out1:
	kfree(vdisk);
err_out0:
	return NULL;
}

static void 
mem_vdisk_cleanup_pendinglist(struct mem_filter_vdisk_s *vdisk)
{
	struct mem_bio_handle_s *bh = NULL, *tmp_bh = NULL;

	spin_lock_bh(&vdisk->vd_list_lock);
	list_for_each_entry_safe(bh, tmp_bh, &vdisk->vd_pending_list, bh_self) {
		list_del(&bh->bh_self);
		bio_endio(bh->bh_bio, -EIO);
		kfree(bh);
	}
	spin_unlock_bh(&vdisk->vd_list_lock);
}

static void 
mem_vdisk_cleanup_ioctl_rules(struct flt_ioctl_ruleset_s *rule_set)
{
	struct flt_ioctl_rule_s *rule = NULL, *tmp_rule = NULL;
	list_for_each_entry_safe(rule, tmp_rule, 
							 &rule_set->ioctlerr_rule_list, ctr_self) {
		list_del(&rule->ctr_self);
		kfree(rule);
	}
}

static void 
mem_vdisk_cleanup_blk_rules(struct flt_blk_ruleset_s *rule_set)
{
	struct flt_disk_rule_s *rule = NULL, *tmp_rule = NULL;

	list_for_each_entry_safe(rule, tmp_rule, 
							 &rule_set->diskerr_rule_list, disk_self) {
		list_del(&rule->disk_self);
		kfree(rule);
	}
}

static void 
mem_vdisk_cleanup_io_rules(struct flt_io_ruleset_s *rule_set)
{
	struct flt_io_rule_s *rule = NULL, *tmp_rule = NULL;
	list_for_each_entry_safe(rule, tmp_rule, 
							 &rule_set->ioerr_rule_list, ir_self) {
		list_del(&rule->ir_self);
		kfree(rule);
	}
}

static void 
mem_vdisk_cleanup_rules(struct mem_filter_vdisk_s *vdisk)
{
	mem_vdisk_cleanup_io_rules(&vdisk->vd_io_rules);
	mem_vdisk_cleanup_ioctl_rules(&vdisk->vd_ioctl_rules);
	mem_vdisk_cleanup_blk_rules(&vdisk->vd_blk_rules);
}

void 
mem_vdisk_clear_rules(struct mem_filter_vdisk_s *vdisk)
{
	struct flt_io_ruleset_s *rule_set = &vdisk->vd_io_rules;

	write_lock(&rule_set->ioerr_lock);
	mem_vdisk_cleanup_io_rules(&vdisk->vd_io_rules);
	write_unlock(&rule_set->ioerr_lock);
}

void 
mem_destroy_vdisk(struct mem_filter_vdisk_s *vdisk)
{
	mem_vdisk_cleanup_rules(vdisk);
	mem_vdisk_del_gendisk(vdisk);
	mem_filter_deinit_vdisk(vdisk);
	kfree(vdisk);
}

/*
static void 
mem_vdisk_rand_fill_bvec(struct bio_iovec *bvec)
{
	unsigned char *addr = NULL;
	int len = 0;
	char ch;

	addr = page_address(bvec->bv_page) + bvec->bv_offset;
	len = bvec->bv_len;
	get_random_bytes(&ch, 1);

	memset(addr, ch, len);
} */

static void 
mem_vdisk_rand_fill_bio(struct bio *bio)
{
	/*
	struct bio_iovec *bvec = NULL;
	int i = 0;
	for (i = 0; i < bio->bi_vcnt; i++) {
		bvec = &bio->bi_io_vec[i];
		mem_vdisk_rand_fill_bvec(bvec);
	}
	*/
}

static void 
mem_vdisk_handle_bio_error(struct mem_bio_handle_s *bio_handle)
{
	struct bio *bio = bio_handle->bh_bio;

	if (bio_handle->bh_latency_jiffies) {
		if (time_before(jiffies, bio_handle->bh_latency_jiffies)) {
			return;
		}
	}

	switch (bio_handle->bh_errtype) {
	case MEM_FILTER_IO_NOERROR:
		list_del(&bio_handle->bh_self);
		bio_endio(bio, 0);
		kfree(bio_handle);
		break;
	case MEM_FILTER_IO_TIMEOUT:
		/* Just leave the bio and do nothing. */
		break;
	case MEM_FILTER_IO_ERROR:
		list_del(&bio_handle->bh_self);
		bio_endio(bio, -EIO);
		kfree(bio_handle);
		break;
	case MEM_FILTER_IO_DATA_CORRUPT:
		list_del(&bio_handle->bh_self);
		mem_vdisk_rand_fill_bio(bio);
		bio_endio(bio, 0);
		kfree(bio_handle);
		break;
	}
}

static void 
mem_vdisk_del_gendisk(struct mem_filter_vdisk_s *vdisk)
{
	if (vdisk->vd_status != MEM_VDISK_STATUS_NORMAL) {
		return;
	}

	if (!vdisk->vd_queue) {
		return;
	}

	vdisk->vd_status = MEM_VDISK_STATUS_DESTROY;
	schedule_timeout_uninterruptible(50);
	mem_vdisk_cleanup_pendinglist(vdisk);
	mem_filter_destory_filter_device(vdisk);
}

static void 
mem_vdisk_add_gendisk(struct mem_filter_vdisk_s *vdisk)
{
	if (vdisk->vd_status != MEM_VDISK_STATUS_DESTROY) {
		return;
	}

	if (vdisk->vd_queue) {
		return;
	}

	vdisk->vd_status = MEM_VDISK_STATUS_NORMAL;
	mem_filter_create_filter_device(vdisk);
}

static void 
mem_vdisk_handle_block_event(struct mem_filter_vdisk_s *vdisk, 
							 struct flt_disk_rule_s *rule)
{
	int i;

	if (rule->disk_error_type == MEM_FILTER_DISK_DISAPPRE) {
		mem_vdisk_del_gendisk(vdisk);
		return;
	}

	if (rule->disk_error_type == MEM_FILTER_DISK_APPRE) {
		mem_vdisk_add_gendisk(vdisk);
		return;
	}

	for (i = 0; i < rule->disk_times; i++) {
		mem_vdisk_del_gendisk(vdisk);
		schedule_timeout_uninterruptible(rule->disk_blink_interval);
		mem_vdisk_add_gendisk(vdisk);
		schedule_timeout_uninterruptible(rule->disk_blink_interval);
	}
}

void 
mem_vdisk_handle_block(struct mem_filter_vdisk_s *vdisk)
{
	struct flt_disk_rule_s *rule = NULL, *tmp_rule = NULL;

	spin_lock(&vdisk->vd_blk_rules.diskerr_lock);
	list_for_each_entry_safe(rule, tmp_rule, 
						 &vdisk->vd_blk_rules.diskerr_rule_list, disk_self) {
		if (time_after_eq(jiffies, rule->disk_delay_time)) {
			list_del(&rule->disk_self);
			spin_unlock(&vdisk->vd_blk_rules.diskerr_lock);
			mem_vdisk_handle_block_event(vdisk, rule);
			return;
		}
	}
	spin_unlock(&vdisk->vd_blk_rules.diskerr_lock);
}

/* NOTE: this function run in softirq context! */
void
mem_vdisk_handle_bio(struct mem_filter_vdisk_s *vdisk)
{
	struct mem_bio_handle_s *bh = NULL, *tmp_bh = NULL;
	int counter = 0;

	spin_lock_bh(&vdisk->vd_list_lock);
	list_for_each_entry_safe(bh, tmp_bh, &vdisk->vd_pending_list, bh_self) {
		mem_vdisk_handle_bio_error(bh);
		if (++counter > MEM_FILTER_HANDLE_BIO_BATCH) {
			break;
		}
	}
	spin_unlock_bh(&vdisk->vd_list_lock);
}

int
mem_vdisk_is_opened(struct mem_filter_vdisk_s *vdisk)
{
	return (atomic_read(&vdisk->vd_opencnt));
}


