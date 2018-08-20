<?php

require_once './src/JWT.php';
require_once './src/Algorithms.php';

use jwt\JWT;


$params['sub'] = '1234567890';
$params['name'] = 'Filipp Vasin';
$params['iat'] = 1516239022;

$payload = json_encode($params);
$private_key = 'secret777';

echo JWT::encoded($payload, $private_key).PHP_EOL;
