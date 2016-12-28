#include "filter_tool.h"

static int 
mem_filter_send_ioctl(int cmd, void *ioctl_info)
{
	int fd = 0;
	int ret = 0;

	fd = open(MEM_FILTER_CTRL_PATH, "r");
	if (fd < 0) {
		printf("open file %s failed for %s!\n", 
			   MEM_FILTER_CTRL_PATH, strerror(errno));
		return fd;
	}

	ret = ioctl(fd, cmd, ioctl_info);
	if (ret < 0) {
		printf("ioctl failed!\n");
	}

	close(fd);

	return ret;
}

int 
mem_filter_tool_help_usage(void)
{
	int i = 0;
	for (i = 0; i < ARRAY_SIZE(cmd_entry_table); i++) {
		printf("%s\n", cmd_entry_table[i].cmd);
	}
}

int
mem_filter_tool_create_vdisk(int argc, char **argv)
{
	struct arg_lit *help = arg_lit0("h", "help", "Display Usage!");
	struct arg_str *path = arg_str1("p", "path", "path", 
									"Devcie path used to create vdisk");
	struct arg_end *end = arg_end(MEM_FILTER_ARG_END_LENGTH);
	void *arg_table[] = {help, path, end};
	int nr_error = arg_parse(argc, argv, arg_table);

	struct filter_ioctl_create_s create_info;
	int ret;

	if (nr_error > 0 || help->count > 0) {
		arg_print_errors(stdout, end, "filter_tool");
		arg_print_syntax(stdout, arg_table, "\n");
		arg_print_glossary_gnu(stdout, arg_table);
		return 0;
	}

	memset(&create_info, 0, sizeof(create_info));
	memcpy(create_info.ctl_path, path->sval[0], MEM_FILTER_PATH_LENGTH);

	ret = mem_filter_send_ioctl(MEM_FILTER_CREATE_VDISK, &create_info);
	if (ret) {
		printf("send create command failed!\n");
		goto err_out;
	}

	return ret;

err_out:
	return ret;
}

int 
mem_filter_tool_destroy_vdisk(int argc, char **argv)
{
	struct arg_lit *help = arg_lit0("h", "help", "Display Usage!");
	struct arg_str *path = arg_str1("n", "name", "vdiskname", 
									"Vdisk name like sda_v, sdb_v");
	struct arg_end *end = arg_end(MEM_FILTER_ARG_END_LENGTH);
	void *arg_table[] = {help, path, end};
	int nr_error = arg_parse(argc, argv, arg_table);

	struct filter_ioctl_destroy_s destroy_info;
	int ret;

	if (nr_error > 0 || help->count > 0) {
		arg_print_errors(stdout, end, "\n");
		arg_print_syntax(stdout, arg_table, "\n");
		arg_print_glossary_gnu(stdout, arg_table);
		return 0;
	}

	memcpy(destroy_info.ctl_vdisk_path, path->sval[0], MEM_FILTER_PATH_LENGTH);
	
	ret = mem_filter_send_ioctl(MEM_FILTER_DESTROY_VDISK, &destroy_info);
	if (ret) {
		printf("send destroy command failed!\n");
		goto err_out;
	}

	return ret;
err_out:
	return ret;
}

int
mem_filter_tool_set_iorules(int argc, char **argv)
{
	char err_type_desc[1024];

	sprintf(err_type_desc, "%d : io timeout,  %d : io error "
			"%d : io data corrupt, %d : io no error", 
			MEM_FILTER_IO_TIMEOUT, MEM_FILTER_IO_ERROR, 
			MEM_FILTER_IO_DATA_CORRUPT, MEM_FILTER_IO_NOERROR);

	struct arg_lit *help = arg_lit0("h", "help", "Display Usage!");
	struct arg_str *path = arg_str1("n", "name", "vdiskname", 
									"Vdisk name like sda_v, sdb_v");
	struct arg_int *op = arg_int0("o", "operation", "<0/1>", 
								  "0 for read and 1 for write");
	struct arg_str *start_lba = arg_str0("s", "start_lba", "<n>",
										 "start lba of ther region");
	struct arg_str *end_lba = arg_str0("e", "end_lba", "<n>",
										 "end lba of ther region");
	struct arg_int *bio_size = arg_int0("l", "size", "<n>", 
										"bio size");
	struct arg_int *error_type = arg_int0("t", "error_type", "<n>",
										  err_type_desc);
	struct arg_int *latency_val = arg_int0("v", "value", "<n>",
										   "latency value in 100ms");
	struct arg_int *rand_rate = arg_int0("r", "rate", "<n>",
										 "error rate in every <n> times");
	struct arg_int *error_period = arg_int0("p", "period", "<n>",
										 "error period in seconds");
	struct arg_int *error_num = arg_int0("c", "count", "<n>",
										 "error count in one period");
	struct arg_end *end = arg_end(MEM_FILTER_ARG_END_LENGTH);
	void *arg_table[] = {help, path, op, start_lba, end_lba, bio_size, 
						error_type, latency_val, rand_rate, error_period, error_num,  end};

	int nr_error = arg_parse(argc, argv, arg_table);
	int ret = 0;

	struct filter_ioctl_iorule_s io_rule;

	if (nr_error > 0 || help->count > 0) {
		arg_print_errors(stdout, end, "\n");
		arg_print_syntax(stdout, arg_table, "\n");
		arg_print_glossary_gnu(stdout, arg_table);
		return 0;
	}

	memset(&io_rule, 0, sizeof(io_rule));
	memcpy(io_rule.ctl_vdisk_path, path->sval[0], strlen(path->sval[0]));

	if (op->count > 0) {
		io_rule.ctl_op = op->ival[0];
	} else {
		io_rule.ctl_op = -1;
	}

	if (start_lba->count > 0) {
		sscanf(start_lba->sval[0], "%lu", &io_rule.ctl_start);
		if (end_lba->count > 0) {
			sscanf(end_lba->sval[0], "%lu", &io_rule.ctl_end);
		} else {
			io_rule.ctl_end = -1;
		}
	} else {
		io_rule.ctl_start = io_rule.ctl_end = 0;
	}

	if (bio_size->count > 0) {
		io_rule.ctl_bio_size = bio_size->ival[0];
	}

	if (error_type->count > 0) {
		io_rule.ctl_inject_type = error_type->ival[0];
	} else {
		io_rule.ctl_inject_type = MEM_FILTER_IO_ERROR;
	}

	if (latency_val->count > 0) {
		io_rule.ctl_latency_val = latency_val->ival[0];
	} else {
		io_rule.ctl_latency_val = 0;
	}

	if (rand_rate->count > 0) {
		io_rule.ctl_randomm_rate = rand_rate->ival[0];
	} else {
		io_rule.ctl_randomm_rate = 0;
	}

	if (error_period->count > 0) {
		io_rule.ctl_period = error_period->ival[0];
	} else {
		io_rule.ctl_period = 0;
	}

	if (error_num->count > 0) {
		io_rule.ctl_io_num = error_num->ival[0];
	} else {
		io_rule.ctl_io_num = 0;
	}

	ret = mem_filter_send_ioctl(MEM_FILTER_SET_IO_RULE, &io_rule);
	if (ret) {
		printf("send set iorule command failed!\n");
		goto err_out;
	}
	return ret;

err_out:
	return ret;
}

int mem_filter_tool_clear_iorules(int argc, char **argv)
{
	struct arg_lit *help = arg_lit0("h", "help", "Display Usage!");
	struct arg_str *name = arg_str1("n", "name", "vdiskname", 
									"Vdisk name like sda_v, sdb_v");
	struct arg_end *end = arg_end(MEM_FILTER_ARG_END_LENGTH);
	void *arg_table[] = {help, name, end};
	int nr_error = arg_parse(argc, argv, arg_table);

	struct filter_ioctl_clearrule_s clear_rule;
	int ret = 0;

	if (nr_error > 0 || help->count > 0) {
		arg_print_errors(stdout, end, "\n");
		arg_print_syntax(stdout, arg_table, "\n");
		arg_print_glossary_gnu(stdout, arg_table);
		return 0;
	}

	memcpy(clear_rule.ctl_vdisk_path, name->sval[0], MEM_FILTER_PATH_LENGTH);
	
	ret = mem_filter_send_ioctl(MEM_FILTER_CLEAR_RULE, &clear_rule);
	if (ret) {
		printf("send clear command failed!\n");
		goto err_out;
	}

	return ret;
err_out:
	return ret;
}

int
mem_filter_tool_set_ioctlrules(int argc, char **argv)
{
}

int
mem_filter_tool_set_blkrules(int argc, char **argv)
{
	struct arg_lit *help = arg_lit0("h", "help", "Display Usage!");
	struct arg_str *path = arg_str1("n", "name", "vdiskname", 
									"Vdisk name like sda_v, sdb_v");
	char string[28];
	sprintf(string, "%d: drop, %d: add, %d: blink", 
			MEM_FILTER_DISK_DISAPPRE,
			MEM_FILTER_DISK_APPRE,
			MEM_FILTER_DISK_BLINKING);
	struct arg_int *inject_type = arg_int1("t", "type", "<n>", string);
	struct arg_int *delay_time = arg_int0("d", "delay", "<n>", 
								   "delay time, in seconds, default 0");
	struct arg_int *repeat_count = arg_int0("c", "count", "<n>", 
								   "blink count");
	struct arg_int *inter_time = arg_int0("i", "interval", "<n>", 
								   "time between on and off, in ms, default 1");
	struct arg_end *end = arg_end(MEM_FILTER_ARG_END_LENGTH);

	void *arg_table[] = {help, path, inject_type, delay_time, 
		repeat_count, inter_time, end};
	int nr_error = arg_parse(argc, argv, arg_table);
	int ret = 0;

	struct filter_ioctl_blkrule_s blk_rule;

	if (nr_error > 0 || help->count > 0) {
		arg_print_errors(stdout, end, "\n");
		arg_print_syntax(stdout, arg_table, "\n");
		arg_print_glossary_gnu(stdout, arg_table);
		return 0;
	}

	memset(&blk_rule, 0, sizeof(blk_rule));
	memcpy(blk_rule.ctl_vdisk_path, path->sval[0], strlen(path->sval[0]));

	blk_rule.ctl_type = inject_type->ival[0];
	if (blk_rule.ctl_type == MEM_FILTER_BLOCK_DROP) {
		goto done;
	} 

	if (delay_time->count > 0) {
		blk_rule.ctl_delay_time = delay_time->ival[0];
	} else {
		blk_rule.ctl_delay_time = 0;
	}

	if (repeat_count->count > 0) {
		blk_rule.ctl_count = repeat_count->ival[0];
	} else {
		blk_rule.ctl_count = 1;
	}

	if (inter_time->count > 0) {
		blk_rule.ctl_inter_time = inter_time->ival[0];
	} else {
		blk_rule.ctl_inter_time = 1;
	}

done:
	ret = mem_filter_send_ioctl(MEM_FILTER_SET_BLOCK_RULE, &blk_rule);
	if (ret) {
		printf("send set blkrule command failed!\n");
	}

	return ret;
}

int main(int argc, char **argv)
{
	int nr_entry = ARRAY_SIZE(cmd_entry_table);
	struct mem_cmd_entry *entry = NULL;
	int ret = 0;
	int i;

	if (argc < 2) {
		return mem_filter_tool_help_usage();
	}

	for (i = 0; i < nr_entry; i++) {
		if (!strcmp(argv[1], cmd_entry_table[i].cmd)) {
			entry = &cmd_entry_table[i];
			ret = entry->cmd_handler_fn(argc - 1, &argv[1]);
			break;
		}
	}

	if (i == nr_entry) {
		printf("cmd %s was not found!\n", argv[1]);
		ret = -EINVAL;
	}

	return ret;
}

