CFLAGS += -std=c99 -Wall -Wextra -Werror -pedantic -g
PROGNAME := ttxinfo
OBJECTS := $(PROGNAME).o

$(PROGNAME) : $(OBJECTS)

.PHONY : clean

clean :
	$(RM) $(OBJECTS)
