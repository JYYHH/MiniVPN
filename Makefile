HEADER = com_h.h
FLAGS = -lcrypto -o

normal: $(HEADER) simpletun.c my_aes.c my_mac.c
		gcc simpletun.c my_aes.c my_mac.c $(FLAGS) simpletun 
test_aes: $(HEADER) test_aes.c my_aes.c
		gcc test_aes.c my_aes.c $(FLAGS) test_aes 
clean: 
		rm simpletun test_aes


