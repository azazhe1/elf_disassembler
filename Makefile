NAME := azazhel_disassembler
INC_DIR := include
MAIN := elf_disassembler
SRC_C := $(wildcard src/*.c)
CFLAGS := -Og -g -Wall -Wextra -I$(INC_DIR) -lm

$(MAIN): $(SRC_C)
	gcc $^ -o $@ $(CFLAGS)

clean:
	rm -f $(MAIN) src/*~ src/*.swap
