AES_PBKDF2
==========

AES-256-CBC with PBKDF2 key for Objective-C and PHP(>=5.5.0)

The Objective-C Base64 code is from [nicklockwood/Base64](https://github.com/nicklockwood/Base64)

The Main AESCrypt-ObjC code is from [Gurpartap/AESCrypt-ObjC](https://github.com/Gurpartap/AESCrypt-ObjC)

## Installation

Add this line to your class:

    #import "AESCrypt.h"

## Usage

    NSString *message = @"the secret message";
    NSString *password = @"passworddrowssap";

Encrypting

    NSString *encryptedData = [AESCrypt encrypt:message password:password];

Decrypting

    NSString *message = [AESCrypt decrypt:encryptedData password:password];