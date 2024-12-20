# indicating that target "all" and "clean" are not files
.PHONY: all clean

# set some variables
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -Wpedantic
LDFLAGS = -pthread -lrt
OUTPUT_OPTION = -MMD -MP -o $@

SOURCE = sched_demo_312512023.c
OBJS = $(SOURCE:.c=.o)
DEPS = $(SOURCE:.c=.d)

TARGET = sched_demo_312512023

# first command of make
all: $(TARGET)

# import the dependencies of .h .c files from the compiler
-include $(DEPS)

# compile rules
%.o: %.c
	$(CC) $(CFLAGS) -c $< $(OUTPUT_OPTION)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	@rm -f $(TARGET) $(OBJS) $(DEPS)
