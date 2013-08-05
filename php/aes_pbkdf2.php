<?php
/**
 * Author: afon
 */
const SALT_LEN = 32;
const ITERATIONS = 10000;
const KEY_LENGTH = 32;
const KET_ALGO = "sha512";

function rand_str($length) {
    $s = 'abcdefghijklmnokprstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $ret = '';
    $count = strlen($s);
    for ($i=0; $i<$length; $i++) {
        $ret .= $s[mt_rand(0,$count - 1)];
    }
    return $ret;
}

function aes_encrypt($data, $password) {
    $salt = rand_str(SALT_LEN);
    $encrypted = mcrypt_encrypt(
        MCRYPT_RIJNDAEL_128,
        hash_pbkdf2(KET_ALGO, $password, $salt, ITERATIONS, KEY_LENGTH, true),
        $data,
        MCRYPT_MODE_CBC,
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    return $salt . base64_encode($encrypted);
}

function aes_decrypt($data, $password) {
    $salt = substr($data, 0, SALT_LEN);
    $data = substr($data, SALT_LEN);
    return mcrypt_decrypt(
        MCRYPT_RIJNDAEL_128,
        hash_pbkdf2(KET_ALGO, $password, $salt, ITERATIONS, KEY_LENGTH, true),
        base64_decode($data),
        MCRYPT_MODE_CBC,
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
}