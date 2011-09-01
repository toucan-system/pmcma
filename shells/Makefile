CC := gcc 
CFLAGS := -W
all::
	$(CC) sh_stack.c -o sh_stack $(CFLAGS)
	$(CC) sh_heap.c -o sh_heap $(CFLAGS)
	$(CC) sh_data.c -o sh_data $(CFLAGS)
	$(CC) sh_bss.c -o sh_bss $(CFLAGS)
	$(CC) sh_stack_mprotect.c -o sh_stack_mprotect $(CFLAGS)
	$(CC) sh_heap_mprotect.c -o sh_heap_mprotect $(CFLAGS)
	$(CC) sh_data_mprotect.c -o sh_data_mprotect $(CFLAGS)
	$(CC) sh_bss_mprotect.c -o sh_bss_mprotect $(CFLAGS)

clean::
	rm sh_stack sh_heap sh_bss sh_data sh_stack_mprotect sh_heap_mprotect sh_bss_mprotect sh_data_mprotect
