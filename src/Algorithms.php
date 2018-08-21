<?php

namespace jwt;

class Algorithms
{
    const HS256 = 1;
    const HS384 = 2;
    const HS512 = 3;
    const RS256 = 4;
    const RS384 = 5;
    const RS512 = 6;

    public static function getAlgorithm($int)
    {
        switch ($int)
        {
            case self::HS256:
                return 'sha256';
            case self::HS384:
                return 'sha384';
            case self::HS512:
                return 'sha512';
            case self::RS256:
                return 'sha256';
            case self::RS384:
                return 'sha384';
            case self::RS512:
                return 'sha512';
            default:
                return false;
        }
    }

    public static function getName($int)
    {
        switch ($int)
        {
            case self::HS256:
                return 'HS256';
            case self::HS384:
                return 'HS384';
            case self::HS512:
                return 'HS512';
            case self::RS256:
                return 'RS256';
            case self::RS384:
                return 'RS384';
            case self::RS512:
                return 'RS512';
            default:
                return false;
        }
    }

    public static function getType($int)
    {
        switch ($int)
        {
            case self::HS256:
                return 'hash_hmac';
            case self::HS384:
                return 'hash_hmac';
            case self::HS512:
                return 'hash_hmac';
            case self::RS256:
                return 'openssl';
            case self::RS384:
                return 'openssl';
            case self::RS512:
                return 'openssl';
            default:
                return false;
        }
    }
}