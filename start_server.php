<?php
require 'vendor/autoload.php';
use Liubinzh\ShadowSocks\ShadowSocksServer;

$s = new ShadowSocksServer();
$s->start();