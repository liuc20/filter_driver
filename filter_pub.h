#ifndef __FILTER_PUB_H__
#define __FILTER_PUB_H__

typedef enum {
	MEM_FILTER_IO_ERROR,
	MEM_FILTER_IO_TIMEOUT,
	MEM_FILTER_IO_DATA_CORRUPT,
	MEM_FILTER_IO_NOERROR,
} io_error_type_t;

typedef enum {
	MEM_FILTER_IO_TRIGGER_RAND,		/* rand error */
	MEM_FILTER_IO_TRIGGER_PERI,		/* 1 error every number. */
} io_trigger_type_t;

typedef enum {
	MEM_FILTER_IOCTL_TIMEOUT,
	MEM_FILTER_IOCTL_LATENCY,
	MEM_FILTER_IOCTL_ERROR,
} ioctl_error_type_t;

typedef enum {
	MEM_FILTER_DISK_DISAPPRE,
	MEM_FILTER_DISK_APPRE,
	MEM_FILTER_DISK_BLINKING,
} disk_error_type_t;

typedef enum {
	MEM_FILTER_IOCTL_TRIGGER_RAND,		/* rand error */
	MEM_FILTER_IOCTL_TRIGGER_PERI,		/* 1 error every number. */
} ioctl_trigger_type_t;


#define MEM_FILTER_CTRL_NAME			"filter_ctl"
#define MEM_FILTER_CTRL_PATH			"/dev/filter_ctl"

#define MEM_FILTER_OPEN_MODE			(FMODE_READ | FMODE_WRITE | FMODE_EXCL)
#define MEM_FILTER_VDISK_MINORS			(8)

#define MEM_FILTER_NAME_LENGTH			(64)
#define MEM_FILTER_PATH_LENGTH			(128)
#define MEM_ERR_NO_ERROR 				(0)

#define	MEM_SECTOR_SHIFT				(9)
#define MEM_BYTES_TO_SECTOR(x)			(x >> MEM_SECTOR_SHIFT)

#define MEM_FILTER_BLOCK_DROP			(0)
#define MEM_FILTER_BLOCK_BLINK			(1)

struct filter_ioctl_create_s {
	/*  input */
	char 	ctl_path[MEM_FILTER_PATH_LENGTH];
	/*  output */
	int 	ctl_sensecode;
};

struct filter_ioctl_destroy_s {
	/*  input */
	char 	ctl_vdisk_path[MEM_FILTER_PATH_LENGTH];
};

struct filter_ioctl_clearrule_s {
	/*  input */
	char 	ctl_vdisk_path[MEM_FILTER_PATH_LENGTH];
};

struct filter_ioctl_iorule_s {
	/*  input */
	char 				ctl_vdisk_path[MEM_FILTER_PATH_LENGTH];
	unsigned int 		ctl_op;
	unsigned long		ctl_start;
	unsigned long		ctl_end;
	unsigned int 		ctl_bio_size;
	unsigned long		ctl_inject_type;
	unsigned long		ctl_latency_val;	/* in 100 ms */
	unsigned long		ctl_randomm_rate;	/* = 1 / rate */
	unsigned long		ctl_period;		/* in second */
	unsigned int		ctl_io_num;
};

struct filter_ioctl_ioctlrule_s {
	char 	ctl_vdisk_path[MEM_FILTER_PATH_LENGTH];
};

struct filter_ioctl_blkrule_s {
	char 	ctl_vdisk_path[MEM_FILTER_PATH_LENGTH];
	unsigned int 	ctl_type;
	unsigned int 	ctl_delay_time;
	unsigned int 	ctl_count;
	unsigned int 	ctl_inter_time;
};

/* define IOCTL COMMANDS */
#define MEM_FILTER_MAJOR				(0x71)
#define MEM_FILTER_CREATE_VDISK		\
	_IOWR(MEM_FILTER_MAJOR, 0x00, struct filter_ioctl_create_s)
#define MEM_FILTER_DESTROY_VDISK	\
	_IOW(MEM_FILTER_MAJOR, 0x01, struct filter_ioctl_destroy_s)
#define MEM_FILTER_SET_IO_RULE		\
	_IOW(MEM_FILTER_MAJOR, 0x02, struct filter_ioctl_iorule_s)
#define MEM_FILTER_SET_IOCTL_RULE	\
	_IOW(MEM_FILTER_MAJOR, 0x03, struct filter_ioctl_ioctlrule_s)
#define MEM_FILTER_SET_BLOCK_RULE	\
	_IOW(MEM_FILTER_MAJOR, 0x04, struct filter_ioctl_blkrule_s)
#define MEM_FILTER_CLEAR_RULE 		\
	_IOW(MEM_FILTER_MAJOR, 0x05, struct filter_ioctl_clearrule_s)

#endif
