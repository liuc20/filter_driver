#ifndef __FILTER_TOOL_H__
#define __FILTER_TOOL_H__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "argtable3.h"

#include "filter_pub.h"

typedef int (*cmd_handler_fn)(int cmd, char **argv);

#define ARRAY_SIZE(x)				(sizeof(x) / sizeof(x[0]))
#define MEM_FILTER_ARG_END_LENGTH	(20)

struct mem_cmd_entry {
	char 				*cmd;
	cmd_handler_fn		cmd_handler_fn;
};

int mem_filter_tool_create_vdisk(int cmd, char **args);
int mem_filter_tool_destroy_vdisk(int cmd, char **args);
int mem_filter_tool_set_iorules(int cmd, char **args);
int mem_filter_tool_clear_iorules(int cmd, char **args);
int mem_filter_tool_set_ioctlrules(int cmd, char **args);
int mem_filter_tool_set_blkrules(int cmd, char **args);

struct mem_cmd_entry cmd_entry_table[] = {
	{"create", mem_filter_tool_create_vdisk},
	{"destroy", mem_filter_tool_destroy_vdisk},
	{"ioinject", mem_filter_tool_set_iorules},
	{"clearinject", mem_filter_tool_clear_iorules},
	{"ioctlinject", mem_filter_tool_set_ioctlrules},
	{"blkinject", mem_filter_tool_set_blkrules},
};

#endif
