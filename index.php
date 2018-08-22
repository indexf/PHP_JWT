<?php

require_once './src/JWT.php';
require_once './src/Algorithms.php';

use jwt\Algorithms;
use jwt\JWT;


$params['sub'] = '1234567890';
$params['name'] = 'John Doe';
$params['iat'] = 1516239022;

$payload = json_encode($params);
$private_key = 'secret';
$alg = Algorithms::HS256;

echo $jwt = JWT::encoded($payload, $private_key, $alg).PHP_EOL;

$result = JWT::decoded($jwt, $private_key);

print_r($result);