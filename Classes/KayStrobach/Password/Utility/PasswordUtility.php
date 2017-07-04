<?php
namespace KayStrobach\Password\Utility;

class PasswordUtility
{
    /**
     * Characters for the password
     */
    const CHARACTERS = '23456789qwertzupasdfghkyxcvbnmWERTZUPLKJHGFDSAYXCVBNM!$%#+-*/';

    const LETTERS = "abcdefghijklmnopqrstuvwxyz";

    const NUMBERS = "123456789";

    /**
     * Generates a password in the given length
     *
     * @param int $length
     * @return string
     */
    public static function generate($length = 8, $chars = null)
    {
        if ($chars === null) {
            $chars = self::CHARACTERS;
        }

        $password = '';
        $characterListLength = strlen($chars);
        srand((double)microtime() * 1000000);
        for ($passwordLength = 0; $passwordLength < $length; $passwordLength++) {
            $password .= substr($chars, (rand() % ($characterListLength)), 1);
        }
        return $password;
    }
}