#include "com_h.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(){
    unsigned char key[32];
    unsigned char iv[32];

    init_key_iv();
    set_key(key);
    set_iv(iv);
    init_AES();

    unsigned char my_text[168] = "I have a pen which is my company from my childhood.\nI wish I can always be with it till my death.\0";
    int len = strlen(my_text);

    printf("Initial Length = %d\n", len);
    aes_encrypt(my_text, &len);
    printf("Now cipher looks like: %.168s\nLen = %d\n", my_text, len);
    aes_decrypt(my_text, &len);
    printf("Final plaintext: %s\nLen = %d\n", my_text, len);

    end_AES();
    return 0;
}