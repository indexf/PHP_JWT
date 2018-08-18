<?php

namespace jwt;

class JWT
{
    private $header;
    private $payload;
    private $signature;


    public static function encoded($payload, $signature)
    {

        $header['alg'] = 'HS256';
        $header['typ'] = 'JWT';

        $header = json_encode($header);

        $base64UrlHeader = self::base64urlsEncode($header);

        $base64UrlPayload = self::base64urlsEncode($payload);

        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $signature, true);

        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        return $jwt;
    }

    public static function decoded($jwt, $key)
    {

    }
    public static function get_base64($str)
    {
//        return base64_encode($str);
        return base64_decode($str);
    }

    public static function base64urlsDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(str_replace(['-', '_'],['+', '/'],  $input));
    }

    public static function base64urlsEncode($input)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($input));
    }
}

//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
//eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
//XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o