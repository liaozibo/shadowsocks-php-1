<?php
namespace Liubinzh\ShadowSocks;

// 状态相关
define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_DESTROYED', -1);
// 命令
define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

// 请求地址类型
define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);

class ShadowSocksServer
{
	protected $serv = array();
	// 前端
	protected $frontends;
	// 后端
	protected $backends;
	// logger
	protected $logger;
	// config
	protected $config;

	public function __construct()
	{
		$this->config = [
			'daemon'=>false,
			'server'=>'',
			'server_port'=>'',
			'password'=>'',
			'method'=>'aes-256-cfb'
		];
		$argv = getopt('c:d');
		$config = empty($argv['c']) ? getcwd() . '/shadowsocks.json' : getcwd() . '/' . $argv['c'];
		if($config){
			if (!file_exists($config)){
				throw new \Exception('config file is not exists');
			}
			$config = file_get_contents($config);
			if($config){
				$config = json_decode($config, true);
			}
		}
		if(is_array($config)){
			$this->config = array_merge($this->config, $config);
		}
		if(isset($argv['d'])){
			$this->config['daemon'] = true;
		}
		$this->serv = new \swoole_server($this->config['server'], $this->config['server_port'], SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
		$this->serv->on('connect', [$this, 'onConnect']);
		$this->serv->on('receive', [$this, 'onReceive']);
		$this->serv->on('close', [$this, 'onClose']);
	}

	public function onConnect($serv, $fd)
	{
		// 设置当前连接的状态为STAGE_INIT，初始状态
		if (!isset($this->frontends[$fd])) {
			$this->frontends[$fd]['stage'] = STAGE_ADDR;
		}
		$this->frontends[$fd]['encryptor'] = new Encryptor($this->config['password'], $this->config['method']);
	}

	public function onReceive($serv, $fd, $from_id, $data)
	{
		switch ($this->frontends[$fd]['stage']) {
			case STAGE_ADDR:
				// 先解密数据
				$data = $this->frontends[$fd]['encryptor']->decrypt($data);
				// 解析socket5头
				$header = $this->parse_socket5_header($data);
				// 解析头部出错，则关闭连接
				if (!$header) {
					return $serv->close($fd);
				}
				// 头部长度
				$header_len = $header[3];
				//尚未建立连接
				if (!isset($this->frontends[$fd]['socket'])) {
					$this->frontends[$fd]['stage'] = STAGE_CONNECTING;
					//连接到后台服务器
					$socket = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
					$socket->closing = false;
					$socket->on('connect', function (\swoole_client $socket) use ($data, $fd, $header_len) {
						$this->backends[$socket->sock] = $fd;
						$this->frontends[$fd]['socket'] = $socket;
						// shadowsocks客户端第一次发来的数据超过头部，则要把头部后面的数据发给远程服务端
						if (strlen($data) > $header_len) {
							$this->frontends[$fd]['socket']->send(substr($data, $header_len));
						}
						if (isset($this->frontends[$fd]['queue'])) {
							foreach ($this->frontends[$fd]['queue'] as $k => $v) {
								$this->frontends[$fd]['socket']->send($v);
								unset($this->frontends[$fd]['queue'][$k]);
							}
						}
						$this->frontends[$fd]['stage'] = STAGE_STREAM;
					});
					$socket->on('error', function (\swoole_client $socket) use ($fd) {
						$this->serv->send($fd, "backend server not connected. please try reconnect.");
						$this->serv->close($fd);
					});
					$socket->on('close', function (\swoole_client $socket) use ($fd) {
						unset($this->backends[$socket->sock]);
						unset($this->frontends[$fd]);
						if (!$socket->closing) {
							$this->serv->close($fd);
						}
					});
					$socket->on('receive', function (\swoole_client $socket, $_data) use ($fd) {
						$this->serv->send($fd, $this->frontends[$fd]['encryptor']->encrypt($_data));
					});

					if ($header[0] == ADDRTYPE_HOST) {
						\swoole_async_dns_lookup($header[1], function ($host, $ip) use ($header, $socket, $fd) {
							$connection_info = $this->serv->connection_info($fd);
							$this->logger->info("connecting {$host}:{$header[2]} from {$connection_info['remote_ip']}:{$connection_info['remote_port']}");
							$socket->connect($ip, $header[2]);
							$this->frontends[$fd]['stage'] = STAGE_CONNECTING;
						});
					} elseif ($header[0] == ADDRTYPE_IPV4) {
						$socket->connect($header[1], $header[2]);
						$this->frontends[$fd]['stage'] = STAGE_CONNECTING;
					} else {

					}
				}
				break;
			case STAGE_CONNECTING:
				$this->frontends[$fd]['queue'][] = $this->frontends[$fd]['encryptor']->decrypt($data);
				break;
			case STAGE_STREAM:
				if (isset($this->frontends[$fd]['socket'])) {
					$this->frontends[$fd]['socket']->send($this->frontends[$fd]['encryptor']->decrypt($data));
				}
				break;
			default:
				break;
		}
	}

	function onClose($serv, $fd, $from_id)
	{
		//清理掉后端连接
		if (isset($this->frontends[$fd]['socket'])) {
			$backend_socket = $this->frontends[$fd]['socket'];
			$backend_socket->closing = true;
			$backend_socket->close();
			unset($this->backends[$backend_socket->sock]);
			unset($this->frontends[$fd]);
		}
	}

	public function start()
	{
		$default = ['daemonize' => $this->config['daemon'],
			'timeout' => 1,
			'poll_thread_num' => 1,
			'worker_num' => 1,
			'backlog' => 128,
			'dispatch_mode' => 2,
			'log_file' => './swoole.log'
		];
		$this->serv->set($default);
		$this->serv->start();
	}

	/**
	 * 解析shadowsocks客户端发来的socket5头部数据
	 * @param string $buffer
	 */
	function parse_socket5_header($buffer)
	{
		$addr_type = ord($buffer[0]);
		switch ($addr_type) {
			case ADDRTYPE_IPV4:
				$dest_addr = ord($buffer[1]) . '.' . ord($buffer[2]) . '.' . ord($buffer[3]) . '.' . ord($buffer[4]);
				$port_data = unpack('n', substr($buffer, 5, 2));
				$dest_port = $port_data[1];
				$header_length = 7;
				break;
			case ADDRTYPE_HOST:
				$addrlen = ord($buffer[1]);
				$dest_addr = substr($buffer, 2, $addrlen);
				$port_data = unpack('n', substr($buffer, 2 + $addrlen, 2));
				$dest_port = $port_data[1];
				$header_length = $addrlen + 4;
				break;
			case ADDRTYPE_IPV6:
				$this->logger->error("todo ipv6 not support yet");
				return false;
			default:
				$this->logger->error("unsupported addrtype $addr_type");
				return false;
		}
		return array($addr_type, $dest_addr, $dest_port, $header_length);
	}
}