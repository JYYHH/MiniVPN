HEADER = com_h.h
FLAGS = -lssl -lcrypto -o

normal: $(HEADER) simpletun.c my_aes.c
		gcc simpletun.c my_aes.c $(FLAGS) simpletun 
test_aes: $(HEADER) test_aes.c my_aes.c
		gcc test_aes.c my_aes.c $(FLAGS) test_aes 
clean: 
		rm simpletun test_aes


