<?php
/**
 * Author: afon
 */
const SALT_LEN = 32;
const ITERATIONS = 10000;
const KEY_LENGTH = 32;
const KEY_ALGO = "sha512";

function rand_str($length) {
    $s = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $ret = '';
    $count = strlen($s);
    for ($i=0; $i<$length; $i++) {
        $ret .= $s[mt_rand(0,$count - 1)];
    }
    return $ret;
}

function aes_encrypt($data, $password) {
    // Add PKCS7 padding.
    $block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    if (($pad = $block - (strlen($data) % $block)) < $block) {
      $data .= str_repeat(chr($pad), $pad);
    }
    $salt = rand_str(SALT_LEN);
    $encrypted = mcrypt_encrypt(
        MCRYPT_RIJNDAEL_128,
        hash_pbkdf2(KEY_ALGO, $password, $salt, ITERATIONS, KEY_LENGTH, true),
        $data,
        MCRYPT_MODE_CBC,
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    return $salt . base64_encode($encrypted);
}

function aes_decrypt($data, $password) {
    $salt = substr($data, 0, SALT_LEN);
    $data = substr($data, SALT_LEN);
    $decrypted = mcrypt_decrypt(
        MCRYPT_RIJNDAEL_128,
        hash_pbkdf2(KEY_ALGO, $password, $salt, ITERATIONS, KEY_LENGTH, true),
        base64_decode($data),
        MCRYPT_MODE_CBC,
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    // Strip padding out.
    $block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $pad = ord($decrypted[strlen($decrypted) - 1]);
    if ($pad && $pad < $block && preg_match('/'.chr($pad).'{'.$pad.'}$/', $decrypted)) {
        return substr($decrypted, 0, strlen($decrypted) - $pad);
    }
    return $decrypted;
}
