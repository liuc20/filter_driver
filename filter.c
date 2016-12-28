
#include "filter.h"

MODULE_LICENSE("Dual BSD/GPL");

struct mem_filter_s g_mem_filter;

static int
mem_filter_ctrl_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int
mem_filter_ctrl_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long
mem_filter_ctrl_create_vdisk(unsigned int cmd, unsigned long args)
{
	struct filter_ioctl_create_s create_info;
	struct mem_filter_vdisk_s *vdisk = NULL;
	long ret = 0;

	ret = copy_from_user(&create_info, (void *)args, sizeof(create_info));
	if (ret) {
		printk(KERN_ERR "Copy args from user failed!\n");
		ret = -ENOMEM;
		goto err_out0;
	}

	create_info.ctl_sensecode = 0;

	vdisk = mem_create_vdisk(create_info.ctl_path);
	if (!vdisk) {
		printk(KERN_ERR "create vdisk for path %s failed!\n", 
			   create_info.ctl_path);
		ret = -ENODEV;
		create_info.ctl_sensecode = ret;
		goto err_out0;
	}

	mem_filter_add_vdisk(vdisk);
	return ret;

err_out0:
	ret = copy_to_user((void *)args, &create_info, sizeof(create_info));
	return ret;
	}

static struct mem_filter_vdisk_s *
mem_filter_find_vdisk(char *vdisk_path)
{
	struct mem_filter_vdisk_s *vdisk = NULL;

	list_for_each_entry(vdisk, &g_mem_filter.fi_vdisk_list, vd_self) {
		if (!strcmp(vdisk_path, vdisk->vd_devname)) {
			return vdisk;
		}
	}

	return NULL;
}

static long 
mem_filter_ctrl_clear_rule(unsigned int cmd, unsigned long args)
{
	long ret = 0;
	struct filter_ioctl_clearrule_s clear_rule;
	struct mem_filter_vdisk_s *vdisk = NULL;

	ret = copy_from_user(&clear_rule, (void *)args, sizeof(clear_rule));
	if (ret) {
		printk(KERN_ERR "Copy form user failed!\n");
		goto err_out0;
	}

	vdisk = mem_filter_find_vdisk(clear_rule.ctl_vdisk_path);
	if (!vdisk) {
		printk(KERN_ERR "Can't find vdisk by name %s!\n", 
			   clear_rule.ctl_vdisk_path);
		ret = -ENODEV;
		goto err_out0;
	}

	mem_vdisk_clear_rules(vdisk);
	return ret;

err_out0:
	return ret;
}

static long 
mem_filter_ctrl_destroy_vdisk(unsigned int cmd, unsigned long args)
{
	long ret = 0;
	struct filter_ioctl_destroy_s destroy_info;
	struct mem_filter_vdisk_s *vdisk = NULL;

	ret = copy_from_user(&destroy_info, (void *)args, sizeof(destroy_info));
	if (ret) {
		printk(KERN_ERR "Copy form user failed!\n");
		goto err_out0;
	}

	vdisk = mem_filter_find_vdisk(destroy_info.ctl_vdisk_path);
	if (!vdisk) {
		printk(KERN_ERR "Can't find vdisk by name %s!\n", 
			   destroy_info.ctl_vdisk_path);
		ret = -ENODEV;
		goto err_out0;
	}

	mem_filter_del_vdisk(vdisk);
	mem_destroy_vdisk(vdisk);
	return ret;

err_out0:
	return ret;
}

static struct flt_io_rule_s* 
mem_filter_generate_iorule(struct filter_ioctl_iorule_s *ioctl_rule)
{
	struct flt_io_rule_s *rule = NULL;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		printk(KERN_ERR "Alloc memory for io_rule failed!\n");
		goto err_out0;
	}

	INIT_LIST_HEAD(&rule->ir_self);

	if (ioctl_rule->ctl_op != -1) {
		rule->ir_op = ioctl_rule->ctl_op;
		MEM_IORULE_SET_OP_ENABLE(rule->ir_enable_flag);
	}

	if (ioctl_rule->ctl_start != ioctl_rule->ctl_end) {
		if (ioctl_rule->ctl_start >= ioctl_rule->ctl_end) {
			printk(KERN_ERR "IORULE range error, start %lu end %lu!\n",
				   ioctl_rule->ctl_start, ioctl_rule->ctl_end);
			goto err_out1;
		}
		rule->ir_start = ioctl_rule->ctl_start;
		rule->ir_end = ioctl_rule->ctl_end;
		MEM_IORULE_SET_RANGE_ENABLE(rule->ir_enable_flag);
	}

	if (ioctl_rule->ctl_bio_size != 0) {
		rule->ir_bio_size = ioctl_rule->ctl_bio_size;
		MEM_IORULE_SET_SIZE_ENABLE(rule->ir_enable_flag);
	}

	rule->ir_inject_type = ioctl_rule->ctl_inject_type;
	rule->ir_latency_jiffie = ioctl_rule->ctl_latency_val * (HZ / 10);
	rule->ir_trigger_rate = ioctl_rule->ctl_randomm_rate;

	if (ioctl_rule->ctl_period != 0 && ioctl_rule->ctl_io_num != 0) {
		rule->ir_period = msecs_to_jiffies((ioctl_rule->ctl_period) * MSEC_PER_SEC);
		rule->ir_expires = jiffies + rule->ir_period;

		rule->ir_io_num = ioctl_rule->ctl_io_num;
		rule->ir_io_applies = rule->ir_io_num;

		MEM_IORULE_SET_PERIOD_ENABLE(rule->ir_enable_flag);
	}

	return rule;

err_out1:
	kfree(rule);
err_out0:
	return NULL;
}

static void
mem_vdisk_add_iorule(struct mem_filter_vdisk_s *vdisk, 
					 struct flt_io_rule_s *io_rule)
{
	struct flt_io_ruleset_s *rule_set = &vdisk->vd_io_rules;

	write_lock(&rule_set->ioerr_lock);
	list_add(&io_rule->ir_self, &rule_set->ioerr_rule_list);
	write_unlock(&rule_set->ioerr_lock);
}

static struct flt_disk_rule_s *
mem_filter_generate_blkrule(struct filter_ioctl_blkrule_s *ioctl_rule)
{
	struct flt_disk_rule_s *rule = NULL;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		printk(KERN_ERR "Alloc memory for io_rule failed!\n");
		goto err_out0;
	}

	INIT_LIST_HEAD(&rule->disk_self);
	rule->disk_error_type = ioctl_rule->ctl_type;
	rule->disk_delay_time = jiffies + ioctl_rule->ctl_delay_time * HZ;
	rule->disk_blink_interval = ioctl_rule->ctl_inter_time * HZ / 1000;
	rule->disk_times = ioctl_rule->ctl_count;
	return rule;

err_out0:
	return NULL;
}

static long 
mem_filter_ctrl_set_iorule(unsigned int cmd, unsigned long args)
{
	struct filter_ioctl_iorule_s rule;
	struct flt_io_rule_s *io_rule = NULL;
	struct mem_filter_vdisk_s *vdisk = NULL;
	long ret = 0;

	ret = copy_from_user(&rule, (void *)args, sizeof(rule));
	if (ret) {
		printk(KERN_ERR "Copy rule from user failed!\n");
		goto err_out0;
	}

	vdisk = mem_filter_find_vdisk(rule.ctl_vdisk_path);
	if (!vdisk) {
		printk(KERN_ERR "Can't find disk by path %s!\n", rule.ctl_vdisk_path);
		ret = -ENOMEM;
		goto err_out0;
	}

	io_rule = mem_filter_generate_iorule(&rule);
	if (!io_rule) {
		printk(KERN_ERR "Can't generate iorule!\n");
		ret = -ENOMEM;
		goto err_out0;
	}

	mem_vdisk_add_iorule(vdisk, io_rule);
	return ret;

err_out0:
	return ret;
}

static long 
mem_filter_ctrl_set_ioctlrule(unsigned int cmd, unsigned long args)
{
	long ret = 0;
	return ret;
}

static void
mem_vdisk_add_blkrule(struct mem_filter_vdisk_s *vdisk, 
					 struct flt_disk_rule_s *blk_rule)
{
	spin_lock(&vdisk->vd_blk_rules.diskerr_lock);
	list_add(&blk_rule->disk_self, &vdisk->vd_blk_rules.diskerr_rule_list);
	spin_unlock(&vdisk->vd_blk_rules.diskerr_lock);
}

static long 
mem_filter_ctrl_set_blkrule(unsigned int cmd, unsigned long args)
{
	struct filter_ioctl_blkrule_s ioctl_blk_rule;
	struct flt_disk_rule_s *blk_rule = NULL;
	struct mem_filter_vdisk_s *vdisk = NULL;
	long ret = 0;

	ret = copy_from_user(&ioctl_blk_rule, (void *)args, sizeof(ioctl_blk_rule));
	if (ret) {
		printk(KERN_ERR "Copy rule from user failed!\n");
		goto err_out0;
	}

	vdisk = mem_filter_find_vdisk(ioctl_blk_rule.ctl_vdisk_path);
	if (!vdisk) {
		printk(KERN_ERR "Can't find disk by path %s!\n", 
			   ioctl_blk_rule.ctl_vdisk_path);
		ret = -ENOMEM;
		goto err_out0;
	}

	blk_rule = mem_filter_generate_blkrule(&ioctl_blk_rule);
	if (!blk_rule) {
		printk(KERN_ERR "Can't generate blkrule !\n");
		ret = -ENOMEM;
		goto err_out0;
	}

	mem_vdisk_add_blkrule(vdisk, blk_rule);
err_out0:
	return ret;
}

static long
mem_filter_ctrl_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = 0;

	switch (cmd) {
	case MEM_FILTER_CREATE_VDISK:
		ret = mem_filter_ctrl_create_vdisk(cmd, args);
		break;
	case MEM_FILTER_DESTROY_VDISK:
		ret = mem_filter_ctrl_destroy_vdisk(cmd, args);
		break;
	case MEM_FILTER_SET_IO_RULE:
		ret = mem_filter_ctrl_set_iorule(cmd, args);
		break;
	case MEM_FILTER_SET_IOCTL_RULE:
		ret = mem_filter_ctrl_set_ioctlrule(cmd, args);
		break;
	case MEM_FILTER_SET_BLOCK_RULE:
		ret = mem_filter_ctrl_set_blkrule(cmd, args);
		break;
	case MEM_FILTER_CLEAR_RULE:
		ret = mem_filter_ctrl_clear_rule(cmd, args);
		break;
	default:
		printk(KERN_ERR "illegal ioctl cmd 0x%x!\n", cmd);
	}

	return ret;
}

static const struct file_operations mem_filter_ctrl_ops = {
	.owner = THIS_MODULE,
	.open = mem_filter_ctrl_open,
	.release = mem_filter_ctrl_release,
	.unlocked_ioctl = mem_filter_ctrl_ioctl,
};

static int
mem_create_config_interface(void)
{
	struct mem_filter_interface_s *interface = &g_mem_filter.fi_interface;
	int ret = 0;

	sprintf(interface->i_chardev_name, "%s", MEM_FILTER_CTRL_NAME);
	interface->i_chardev_major = register_chrdev(0, interface->i_chardev_name, 
												 &mem_filter_ctrl_ops);
	if (interface->i_chardev_major < 0) {
		printk(KERN_ERR "Register character device failed!\n");
		ret = -ENODEV;
		goto err_out0;
	}

	interface->i_chardev_class = class_create(THIS_MODULE, 
											  interface->i_chardev_name);
	if (IS_ERR(interface->i_chardev_class)) {
		printk(KERN_ERR "Create class %s failed!\n", 
			   interface->i_chardev_name);
		ret = -ENODEV;
		goto err_out1;
	}

	interface->i_chardev_device = 
		device_create(interface->i_chardev_class, NULL, 
					  MKDEV(interface->i_chardev_major, 1), NULL, 
					  interface->i_chardev_name);
	if (IS_ERR(interface->i_chardev_device)) {
		printk(KERN_ERR "Create character device failed!\n");
		ret = -ENODEV;
		goto err_out2;
	}

	return ret;

err_out2:
	class_destroy(interface->i_chardev_class);
err_out1:
	unregister_chrdev(interface->i_chardev_major, interface->i_chardev_name);
err_out0:
	return ret;
}

static void 
mem_filter_wakeup_thread(struct mem_filter_s *filter)
{
	complete(&filter->fi_thread_completion);
}

static void 
mem_filter_timer_fn(unsigned long arg)
{
	struct mem_filter_s *filter = (struct mem_filter_s *)arg;

	tasklet_schedule(&filter->fi_tasklet);
	mem_filter_wakeup_thread(filter);
	filter->fi_timer.expires = jiffies + MEM_TIMER_DELTA_VAL;
	add_timer(&filter->fi_timer);
}

static void
mem_filter_init_timer(struct mem_filter_s *filter)
{
	init_timer(&filter->fi_timer);
	filter->fi_timer.function = mem_filter_timer_fn;
	filter->fi_timer.data = (unsigned long)filter;
	filter->fi_timer.expires = jiffies;
	add_timer(&filter->fi_timer);
}

static void 
mem_filter_deinit_timer(struct mem_filter_s *filter)
{
	del_timer_sync(&filter->fi_timer);
}

static void 
mem_filter_handle_bio(void)
{
	struct mem_filter_vdisk_s *vdisk = NULL;
	struct mem_filter_s *filter = &g_mem_filter;

	spin_lock(&filter->fi_vdisklist_lock);
	list_for_each_entry(vdisk, &g_mem_filter.fi_vdisk_list, vd_self) {
		mem_vdisk_handle_bio(vdisk);
	}
	spin_unlock(&filter->fi_vdisklist_lock);
}

static void 
mem_filter_tasklet_fn(unsigned long arg)
{
	mem_filter_handle_bio();
}

static void 
mem_filter_init_tasklet(struct mem_filter_s *filter)
{
	tasklet_init(&filter->fi_tasklet, mem_filter_tasklet_fn, 
				 (unsigned long)filter);
}

static void 
mem_filter_handle_block(struct mem_filter_s *filter)
{
	struct mem_filter_vdisk_s *vdisk = NULL;

	spin_lock_bh(&filter->fi_vdisklist_lock);
	list_for_each_entry(vdisk, &g_mem_filter.fi_vdisk_list, vd_self) {
		spin_unlock_bh(&filter->fi_vdisklist_lock);
		mem_vdisk_handle_block(vdisk);
		spin_lock_bh(&filter->fi_vdisklist_lock);
	}
	spin_unlock_bh(&filter->fi_vdisklist_lock);
}

static int 
mem_filter_kthread_fn(void *arg)
{
	struct mem_filter_s *filter = (struct mem_filter_s *)arg;

	while (!filter->fi_thread_stop) {
		mem_filter_handle_block(filter);
		wait_for_completion(&filter->fi_thread_completion);
	}

	filter->fi_thread_stop = 0;
	return 0;
}

static int 
mem_filter_init_blk_thread(struct mem_filter_s *filter)
{
	filter->fi_thread_stop = 0;
	filter->fi_task_struct = kthread_run(mem_filter_kthread_fn, 
										 filter, "filter");
	if (IS_ERR(filter->fi_task_struct)) {
		printk(KERN_ERR "Create thread for filter failed!\n");
		return -EFAULT;
	}
	return 0;
}

static void 
mem_filter_deinit_tasklet(struct mem_filter_s *filter)
{
	tasklet_kill(&filter->fi_tasklet);
}

static int 
mem_filter_init_service(struct mem_filter_s *filter)
{
	int ret = 0;
	init_completion(&filter->fi_thread_completion);
	mem_filter_init_tasklet(filter);
	ret = mem_filter_init_blk_thread(filter);
	mem_filter_init_timer(filter);
	return ret;
}


static int 
mem_filter_init_global(void)
{
	int ret = 0;

	memset(&g_mem_filter, 0, sizeof(g_mem_filter));

	spin_lock_init(&g_mem_filter.fi_vdisklist_lock);
	INIT_LIST_HEAD(&g_mem_filter.fi_vdisk_list);
	g_mem_filter.fi_vdisk_major = 
		register_blkdev(g_mem_filter.fi_vdisk_major, "mem_vdisk");
	atomic_set(&g_mem_filter.fi_vdisk_number, 0);

	if (g_mem_filter.fi_vdisk_major < 0) {
		printk(KERN_ERR "register major number for vdisk failed!");
		return -ENODEV;
	}

	ret = mem_filter_init_service(&g_mem_filter);
	if (ret) {
		printk(KERN_ERR "Register filter service failed!\n");
		return -EINVAL;
	}

	return 0;
}

static void 
mem_filter_deinit_task(struct mem_filter_s *filter)
{
	filter->fi_thread_stop = 1;
	while (filter->fi_thread_stop) {
		schedule_timeout(HZ / 10);
	}
}

static void 
mem_filter_deinit_global(void)
{
	unregister_blkdev(g_mem_filter.fi_vdisk_major, "mem_vdisk");
	mem_filter_deinit_task(&g_mem_filter);
	mem_filter_deinit_tasklet(&g_mem_filter);
	mem_filter_deinit_timer(&g_mem_filter);
}

static int 
mem_filter_init(void)
{
	int ret = 0;

	ret = mem_filter_init_global();
	if (ret) {
		printk(KERN_ERR "init global filter failed!\n");
		goto err_out0;
	}

	ret = mem_create_config_interface();
	if (ret) {
		printk("create proc interface failed!\n");
		goto err_out1;
	} 

	return ret;

err_out1:
	mem_filter_deinit_global();
err_out0:
	return ret;
}

static void
mem_destroy_all_vdisk(void)
{
	struct mem_filter_s *filter = &g_mem_filter;
	struct mem_filter_vdisk_s *vdisk = NULL, *vdisk_tmp;

	spin_lock_bh(&filter->fi_vdisklist_lock);
	list_for_each_entry_safe(vdisk, vdisk_tmp, 
							 &filter->fi_vdisk_list, vd_self) {
		spin_unlock_bh(&filter->fi_vdisklist_lock);
		mem_filter_del_vdisk(vdisk);
		mem_destroy_vdisk(vdisk);
		spin_lock_bh(&filter->fi_vdisklist_lock);
	}
	spin_unlock_bh(&filter->fi_vdisklist_lock);
}

static void 
mem_destroy_config_interface(void)
{
	struct mem_filter_interface_s *interface = &g_mem_filter.fi_interface;

	device_destroy(interface->i_chardev_class, 
				   MKDEV(interface->i_chardev_major, 1));
	class_destroy(interface->i_chardev_class);
	unregister_chrdev(interface->i_chardev_major, interface->i_chardev_name);
}

static void 
mem_filter_exit(void)
{
	mem_destroy_config_interface();
	mem_destroy_all_vdisk();
	mem_filter_deinit_global();
}

module_init(mem_filter_init);
module_exit(mem_filter_exit);

