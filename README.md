
基于[swoole](https://github.com/swoole/swoole-src)扩展的shadowsocks实现

# Installation

Use [Composer](https://getcomposer.org/):

```sh
composer require liubinzh/shadowsocks-php dev-master
```

# Usage(服务端）
start_server.php

```php
<?php
require 'vendor/autoload.php';
use Liubinzh\ShadowSocks\ShadowSocksServer;

$s = new ShadowSocksServer();
$s->start();
```

启动:

```sh

php  start_server.php -d -c ./shadowsocks.json

```
# Usage(本地端）
start_local.php

```php
<?php
require 'vendor/autoload.php';
use Liubinzh\ShadowSocks\ShadowSocksLocal;

$s = new ShadowSocksLocal();
$s->start();
```

启动:

```sh

php  start_local.php -d -c ./shadowsocks.json

```
# 其他
加密类使用了[workerman版本](https://github.com/walkor/shadowsocks-php)的实现 