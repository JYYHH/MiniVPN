HEADER = com_h.h
FLAGS = -lrt -lssl -lcrypto -o

normal: $(HEADER) simpletun.c my_aes.c my_mac.c my_ssl.c com_h.c
		gcc simpletun.c my_aes.c my_mac.c my_ssl.c com_h.c $(FLAGS) simpletun 
clean: 
		rm simpletun


