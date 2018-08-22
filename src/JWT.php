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

    private static function verify($msg, $signature, $key, $alg)
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = static::$supported_algs[$alg];
        switch($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new DomainException(
                    'OpenSSL error: ' . openssl_error_string()
                );
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $msg, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $len = min(static::safeStrlen($signature), static::safeStrlen($hash));

                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

                return ($status === 0);
        }
    }
}
