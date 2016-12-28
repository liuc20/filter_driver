#ifndef __FILTER_H__
#define __FILTER_H__

#include "filter_pub.h"

#include <linux/init.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kmod.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/err.h>
#include <linux/kthread.h>

#define MEM_FILTER_HANDLE_BIO_BATCH		(128)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)

#define MAKE_REQUEST_FN_TYPE		void
#define MAKE_REQUEST_FN_TYPE_OK
#define MAKE_REQUEST_FN_TYPE_EIO

#define FCLOSE_FN_TYPE 				void
#define FCLOSE_FN_TYPE_NODEV
#define FCLOSE_FN_TYPE_OK

#else

#define MAKE_REQUEST_FN_TYPE		int
#define MAKE_REQUEST_FN_TYPE_OK		(0)
#define MAKE_REQUEST_FN_TYPE_EIO	(-MEM_EIO)

#define FCLOSE_FN_TYPE 				int
#define FCLOSE_FN_TYPE_NODEV 		(-MEM_ENODEV)
#define FCLOSE_FN_TYPE_OK			(0)

#endif

#define MEM_ASSERT(condition) 					\
	do {										\
		if (!(condition)) {						\
			printk(KERN_EMERG "\nmemfilter Assert Failed at %s:%d\n",	\
				   __FILE__, __LINE__);			\
			panic(#condition);					\
		}										\
	} while (0);

/* global filter's interface, a character device. */
struct mem_filter_interface_s {
	unsigned int 		i_chardev_major;
	struct class		*i_chardev_class;
	struct device 		*i_chardev_device;
	char 				i_chardev_name[MEM_FILTER_NAME_LENGTH];
};

#define MEM_TIMER_DELTA_VAL				(HZ / 10)
#define	MEM_IORULE_OP_SHIFT				(1)
#define	MEM_IORULE_RANGE_SHIFT			(2)
#define	MEM_IORULE_SIZE_SHIFT			(3)
#define	MEM_IORULE_PERIOD_SHIFT			(4)

#define MEM_IORULE_OP_MASK				(1 << MEM_IORULE_OP_SHIFT)
#define MEM_IORULE_RANGE_MASK			(1 << MEM_IORULE_RANGE_SHIFT)
#define MEM_IORULE_SIZE_MASK			(1 << MEM_IORULE_SIZE_SHIFT)
#define MEM_IORULE_PERIOD_MASK			(1 << MEM_IORULE_PERIOD_SHIFT)

#define MEM_IORULE_OP_ENABLE(x)			((x) & (MEM_IORULE_OP_MASK))
#define MEM_IORULE_RANGE_ENABLE(x)		((x) & (MEM_IORULE_RANGE_MASK))
#define MEM_IORULE_SIZE_ENABLE(x)		((x) & (MEM_IORULE_SIZE_MASK))
#define MEM_IORULE_PERIOD_ENABLE(x)		((x) & (MEM_IORULE_PERIOD_MASK))

#define MEM_IORULE_SET_OP_ENABLE(x)			(x |= MEM_IORULE_OP_MASK)
#define MEM_IORULE_SET_RANGE_ENABLE(x)		(x |= MEM_IORULE_RANGE_MASK)
#define MEM_IORULE_SET_SIZE_ENABLE(x)		(x |= MEM_IORULE_SIZE_MASK)
#define MEM_IORULE_SET_PERIOD_ENABLE(x)		(x |= MEM_IORULE_PERIOD_MASK)

struct mem_bio_ctx_s {
	struct mem_filter_vdisk_s 	*ctx_vdisk;
	struct flt_io_rule_s		*ctx_rule;
	void 						*ctx_private;
	bio_end_io_t				*ctx_callback;
};

struct flt_io_rule_s {
	struct list_head	ir_self;
	int					ir_error;
	unsigned int 		ir_enable_flag;
	unsigned int 		ir_op;
	sector_t 			ir_start;
	sector_t			ir_end;
	unsigned int 		ir_bio_size;
	io_error_type_t		ir_inject_type;
	unsigned long 		ir_latency_jiffie;	/* set latency for hi-latency */
	unsigned long 		ir_trigger_rate;	/* set rate for random trigger */

	unsigned long		ir_period;			/* how long this rule takes effect for once */
	unsigned long 		ir_expires;			/* the next time this rule takes effect */
	unsigned int		ir_io_num;		    /* how many I/Os this rule applies to once it takes effect */
	unsigned int		ir_io_applies;		/* how many I/Os this rule has already applies to in this period */
};

struct flt_ioctl_rule_s {
	struct list_head		ctr_self;
	unsigned long 			ctr_cmd;
	ioctl_error_type_t		ctr_err_type;
	ioctl_trigger_type_t	ctr_trigger_type;
};

struct flt_disk_rule_s {
	struct list_head		disk_self;
	disk_error_type_t		disk_error_type;
	unsigned long 			disk_delay_time;
	unsigned int 			disk_blink_interval;
	unsigned int 			disk_times;
};

/* all ioerr rule on this list */
struct flt_io_ruleset_s {
	unsigned int 		ioerr_nr;
	rwlock_t			ioerr_lock;
	struct list_head	ioerr_rule_list;
};

/* all ioctl error rule on this list */
struct flt_ioctl_ruleset_s {
	unsigned int 		ioctlerr_nr;
	struct list_head	ioctlerr_rule_list;
};

/* all blk error rule on this list */
struct flt_blk_ruleset_s {
	unsigned int 		diskerr_nr;
	spinlock_t			diskerr_lock;
	struct list_head 	diskerr_rule_list;
};

struct mem_bio_handle_s {
	int					bh_error;
	struct list_head	bh_self;
	struct bio 			*bh_bio;
	unsigned long		bh_latency_jiffies;
	io_error_type_t		bh_errtype;
	unsigned int 		bh_rand_rate;
};

enum {
	MEM_VDISK_STATUS_NORMAL = 0,
	MEM_VDISK_STATUS_DESTROY
};

struct mem_filter_vdisk_s {
	struct list_head 				vd_self;
	atomic_t						vd_opencnt;
	unsigned long					vd_status;
	struct block_device				*vd_bdev;
	struct request_queue			*vd_queue;
	struct gendisk					*vd_disk;
	char 							vd_sys_devname[MEM_FILTER_NAME_LENGTH];
	char 							vd_devname[MEM_FILTER_NAME_LENGTH];
	int								vd_first_minor;

	/* the injection rules of the vdisk. */
	struct flt_io_ruleset_s 		vd_io_rules;
	struct flt_ioctl_ruleset_s 		vd_ioctl_rules;
	struct flt_blk_ruleset_s 		vd_blk_rules;

	/* bio pending on this list. */
	spinlock_t						vd_list_lock;
	struct list_head				vd_pending_list;
};

struct mem_filter_s {
	struct mem_filter_interface_s 	fi_interface;
	struct timer_list				fi_timer;
	struct tasklet_struct			fi_tasklet;
	spinlock_t						fi_vdisklist_lock;
	struct list_head 				fi_vdisk_list;
	int 							fi_vdisk_major;
	atomic_t						fi_vdisk_number;
	struct task_struct				*fi_task_struct;
	int								fi_thread_stop;
	struct completion				fi_thread_completion;
};

extern struct mem_filter_s g_mem_filter;

void mem_destroy_vdisk(struct mem_filter_vdisk_s *vdisk);

struct mem_filter_vdisk_s * mem_create_vdisk(char *dev_path);

void mem_filter_add_vdisk(struct mem_filter_vdisk_s *vdisk);

void mem_filter_del_vdisk(struct mem_filter_vdisk_s *vdisk);

void mem_vdisk_handle_bio(struct mem_filter_vdisk_s *vdisk);

void mem_vdisk_handle_block(struct mem_filter_vdisk_s *vdisk);

int mem_vdisk_is_opened(struct mem_filter_vdisk_s *vdisk);

void mem_vdisk_clear_rules(struct mem_filter_vdisk_s *vdisk);

#endif
