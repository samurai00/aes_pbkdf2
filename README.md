AES_PBKDF2
==========

AES-256-CBC (PKCS7 Padding) with PBKDF2 key for Objective-C and PHP(>=5.5.0)

AES-256-CBC (PKCS7 Padding) C implementation. (pbkdf2 to be added.)

The Objective-C Base64 code is from [nicklockwood/Base64](https://github.com/nicklockwood/Base64)

The Main AESCrypt-ObjC code is from [Gurpartap/AESCrypt-ObjC](https://github.com/Gurpartap/AESCrypt-ObjC)

The main rijndael c code is from [http://www.efgh.com/software/rijndael.htm](http://www.efgh.com/software/rijndael.htm)



## Installation
#### Objective-C
Add this line to your class:

    #import "AESCrypt.h"

## Usage
#### Objective-C
    NSString *message = @"the secret message";
    NSString *password = @"passworddrowssap";

Encrypting

    NSString *encryptedData = [AESCrypt encrypt:message password:password];

Decrypting

    NSString *message = [AESCrypt decrypt:encryptedData password:password];
