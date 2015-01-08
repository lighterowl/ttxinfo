CFLAGS += -std=c99 -Wall -Wextra -pedantic -g

all : ttxinfo

ttxinfo : ttxinfo.o

.PHONY : clean all

clean :
	$(RM) ttxinfo.o
