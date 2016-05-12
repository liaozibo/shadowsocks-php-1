<?php
require 'vendor/autoload.php';
use Liubinzh\ShadowSocks\ShadowSocksLocal;

$s = new ShadowSocksLocal();
$s->start();