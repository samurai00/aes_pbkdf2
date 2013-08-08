//
//  rijndael_crypt.h
//  
//  rijndael 256 bit CBC mode.
//
//  Created by afon on 13-8-6.
//  Copyright (c) 2013年 afon. All rights reserved.
//

#ifndef pbkdf2_rijndael_crypt_h
#define pbkdf2_rijndael_crypt_h

#include "rijndael.h"
#define KEYBITS 256

void rijndael256Encrypt(const char *plaindata, unsigned char password[KEYLENGTH(KEYBITS)], unsigned char cipherdata[]);
void rijndael256Decrypt(const char *cipherdata, unsigned char password[KEYLENGTH(KEYBITS)], unsigned char plaindata[]);

#endif
