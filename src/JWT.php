<?php

namespace jwt;

use jwt\Algorithms;

class JWT
{

    public static function encoded($payload, $private_key, $alg = Algorithms::HS256)
    {
        $header['alg'] = Algorithms::getName($alg);
        $header['typ'] = 'JWT';

        $header = json_encode($header);

        $base64UrlHeader = self::base64urlEncode($header);

        $base64UrlPayload = self::base64urlEncode($payload);

        $signature = self::sign($base64UrlHeader . "." . $base64UrlPayload, $private_key, $alg);

        $base64UrlSignature = self::base64urlEncode($signature);

        $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        return $jwt;
    }

    public static function decoded($jwt, $private_key)
    {
        return 'TODO';
    }

    private static function base64urlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(str_replace(['-', '_'],['+', '/'],  $input));
    }

    private static function base64urlEncode($input)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($input));
    }


    private static function sign($str, $private_key, $alg = Algorithms::HS256)
    {
        if (false === Algorithms::getAlgorithm($alg)) {
            return 'Algorithm unknown';
        }

        switch(Algorithms::getType($alg)) {
            case 'hash_hmac':
                echo Algorithms::getAlgorithm($alg);
                return hash_hmac(Algorithms::getAlgorithm($alg), $str, $private_key, true);
            case 'openssl':
                $signature = '';
                if (!openssl_sign($str, $signature, $private_key, Algorithms::getAlgorithm($alg))) {
                    return 'Sign error';
                } else {
                    return $signature;
                }
        }
    }
}
