LIB_DIR= ../../../lib/argtable/
INCLUDE_DIR= ../
INSTALL=install
CFLAGS=-I$(LIB_DIR)	\
	   -I$(INCLUDE_DIR) \
	   -g
LD_FLAG=-lpthread -lrt
INSTALL_PATH=/usr/local/bin

EXTRA_CFLAG=-DMEM_RAID_DESKTOP

SRCS = filter_tool.c	\
	   argtable3.c	\

RAID_TOOL = filter_tool 

vpath %.c ./:$(SHARE_DIR) $(LIB_DIR) \
		  $(RAID_SHARE_LIB) $(POSIX_DIR) $(THREAD_DIR)

OBJ = $(SRCS:%.c=%.o)

all: $(RAID_TOOL)

${RAID_TOOL}: ${OBJ}
	$(CC) ${CFLAGS} -o ${RAID_TOOL} ${OBJ} ${LD_FLAG}

install:
	@$(INSTALL) ${RAID_TOOL} ${INSTALL_PATH}

clean:
	@$(RM) ${OBJ} ${RAID_TOOL}

uninstall:
	@$(RM) ${INSTALL_PATH}/${RAID_TOOL}
