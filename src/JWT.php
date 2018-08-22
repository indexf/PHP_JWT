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
        $jwt_parts = explode('.',$jwt);

        if (count($jwt_parts) === 3) {
            $header_b64 = $jwt_parts[0];
            $payload_b64 = $jwt_parts[1];
            $signature = self::base64urlDecode($jwt_parts[2]);
        }

        $header = json_decode(self::base64urlDecode($header_b64), true);
        $alg =  Algorithms::getNumber($header['alg']);

       if (self::verify("$header_b64.$payload_b64",$signature,$private_key,$alg)) {
           $result['data'] = json_decode(self::base64urlDecode($payload_b64), true);
           $result['status'] = 'valid';
       } else {
           $result['status'] = 'not valid';
       }
        return $result;
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
        switch(Algorithms::getType($alg)) {
            case 'hash_hmac':
                $hash = hash_hmac(Algorithms::getAlgorithm($alg), $msg, $key, true);
                return hash_equals($signature, $hash);
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, Algorithms::getAlgorithm($alg));
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }

        }
    }
}
