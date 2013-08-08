//
//  rijndael_crypt.c
//  
//  rijndael 256 bit CBC mode.
//
//  Created by afon on 13-8-6.
//  Copyright (c) 2013年 afon. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "rijndael_crypt.h"

void rijndael256Encrypt(const char *plaindata, unsigned char password[KEYLENGTH(KEYBITS)], unsigned char cipherdata[]) {
    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)];
    int nrounds;
    for (int i = 0; i < sizeof(key); i++)
        key[i] = *password != 0 ? *password++ : 0;
    
    // Add PKCS7 padding.
    unsigned long data_len = strlen(plaindata);
    unsigned char new_plaindata[data_len];
    memcpy(new_plaindata, plaindata, data_len);
    unsigned int pad = 16 - (data_len%16);
    if (pad < 16) {
        int y = 0;
        for (; y < pad; new_plaindata[data_len + y++] = (char)pad);
        new_plaindata[data_len + y + 1] = 0;
        data_len = data_len + y;
    }

    nrounds = rijndaelSetupEncrypt(rk, key, KEYBITS);
    unsigned char iv[16];
    for (int i = 0; i < sizeof(iv); i++) {
        iv[i] = 0;
    }
    for (int i = 0; i < data_len/16; i++) {
        unsigned char plainblock[16];
        unsigned char cipherblock[16];
        for (int j = 0; j < sizeof(plainblock); j++) {
            plainblock[j] = new_plaindata[i*16+j] ^ iv[j];
        }
        rijndaelEncrypt(rk, nrounds, plainblock, cipherblock);
        for (int k = 0; k < sizeof(cipherblock); k++) {
            cipherdata[i*16+k] = iv[k] = cipherblock[k];
        }
    }
}

void rijndael256Decrypt(const char *cipherdata, unsigned char password[KEYLENGTH(KEYBITS)], unsigned char plaindata[]) {
    unsigned long rk[RKLENGTH(KEYBITS)];
    unsigned char key[KEYLENGTH(KEYBITS)];
    int nrounds;
    for (int i = 0; i < sizeof(key); i++)
        key[i] = *password != 0 ? *password++ : 0;
    
    unsigned long data_len = strlen(cipherdata);
    
    nrounds = rijndaelSetupDecrypt(rk, key, KEYBITS);
    unsigned char iv[16];
    for (int i = 0; i < sizeof(iv); i++) {
        iv[i] = 0;
    }
    unsigned char tmp_plaindata[data_len];
    for (int i = 0; i < data_len/16; i++) {
        unsigned char plainblock[16];
        unsigned char cipherblock[16];
        for (int j = 0; j < sizeof(cipherblock); j++) {
            cipherblock[j] = cipherdata[i*16+j];
        }
        rijndaelDecrypt(rk, nrounds, cipherblock, plainblock);
        for (int k = 0; k < sizeof(plainblock); k++) {
            tmp_plaindata[i*16+k] = plainblock[k] ^ iv[k];
            iv[k] = cipherblock[k];
        }
    }
    // Strip PKCS7 padding.
    unsigned int padding = 1;
    unsigned int pad = tmp_plaindata[data_len - 1];
    if (pad < 16) {
        for (int i = 0; i < pad; i++) {
            if ((unsigned int)tmp_plaindata[data_len - i - 1] != pad) {
                padding = 0;
                break;
            }
        }
    }
    if (padding == 1) {
        data_len = data_len - pad;
    }
    memcpy(plaindata, tmp_plaindata, data_len);
    plaindata[data_len] = 0;
}
