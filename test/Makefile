CC=gcc

OPT=-O2 -Wall -c
#OPT=-Wall -Wstrict-prototypes -Wnested-externs -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast -c -g3 -ggdb

TARGETS=flood drought hail bomb tornado
OBJS=flood.o drought.o hail.o bomb.o tornado.o common.o

ALL: clean $(TARGETS)
	@strip $(TARGETS)

flood: flood.o common.o
	@$(CC) -o $@ $^

drought: drought.o common.o
	@$(CC) -o $@ $^

hail: hail.o common.o
	@$(CC) -o $@ $^

bomb: bomb.o common.o
	@$(CC) -o $@ $^

tornado: tornado.o common.o
	@$(CC) -o $@ $^

clean:
	@echo "CLEAN (test)"
	@rm -f $(TARGETS) $(OBJS)

.c.o:
	@echo " CC $<"
	@$(CC) $(OPT) $<

