CC = gcc
LD = ld

PROGRAM = fuse_stub
CLIENT = fuse_client

CFLAGS = -c -O2 -Wall -Werror -ggdb
BUILDFLAGS = `pkg-config fuse --cflags --libs` $(CFLAGS)

LIBS = -lfuse -lulockmgr -lpthread

OBJ = main.o gateway.o util.o proxy.o stub.o context.o log.o interface.o golem.o

DEPS=$(OBJ:%.o=%.d)

%.d: %.c
	$(CC) $(BUILDFLAGS) -MM -MP -o $@ $<

%.o: %.c
	$(CC) $(BUILDFLAGS) -o $@ $<

all: $(PROGRAM) $(CLIENT)

$(PROGRAM): $(OBJ)
	$(CC) $(OBJ) $(LIBS) -o $@

$(CLIENT): fuse_client.c
	$(CC)  $(CFLAGS) $^ -o $@

tags:
	find . -name '*.[hc]' -print | xargs ctags

clean:
	rm -rf $(PROGRAM) $(CLIENT) $(OBJ) $(DEPS) $(CLIENT) tags *~

.PHONY: clean tags

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(DEPS)
endif
