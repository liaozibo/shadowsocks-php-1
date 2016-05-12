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

class ShadowSocksLocal
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
			'local_address'=>'0.0.0.0',
			'local_port'=>1080,
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
		$this->serv = new \swoole_server($this->config['local_address'], $this->config['local_port'], SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
		$this->serv->on('connect', [$this, 'onConnect']);
		$this->serv->on('receive', [$this, 'onReceive']);
		$this->serv->on('close', [$this, 'onClose']);
		$this->logger = new \Katzgrau\KLogger\Logger(getcwd().'/logs');
	}

	public function onConnect($serv, $fd)
	{
		// 设置当前连接的状态为STAGE_INIT，初始状态
		if (!isset($this->frontends[$fd])) {
			$this->frontends[$fd]['stage'] = STAGE_INIT;
		}
		// 初始化加密类
		$this->frontends[$fd]['encryptor'] = new Encryptor($this->config['password'], $this->config['method']);
	}

	public function onReceive($serv, $fd, $from_id, $data)
	{
		switch ($this->frontends[$fd]['stage']) {
			case STAGE_INIT:
				//与客户端建立SOCKS5连接
				//参见: https://www.ietf.org/rfc/rfc1928.txt
				$serv->send($fd, "\x05\x00");
				$this->frontends[$fd]['stage'] = STAGE_ADDR;
				break;
			case STAGE_ADDR:
				$cmd = ord($data[1]);
				//仅处理客户端的TCP连接请求
				if ($cmd != CMD_CONNECT) {
					$this->logger->error("unsupport cmd");
					$serv->send($fd, "\x05\x07\x00\x01");
					return $this->serv->close($fd);
				}
				$header = $this->parse_socket5_header($data);
				if (!$header) {
					$serv->send($fd, "\x05\x08\x00\x01");
					return $this->serv->close($fd);
				}
				//尚未建立连接
				if (!isset($this->frontends[$fd]['socket'])) {
					$this->frontends[$fd]['stage'] = STAGE_CONNECTING;
					//连接到后台服务器
					$socket = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
					$socket->closing = false;
					$socket->on('connect', function (\swoole_client $socket) use ($data, $fd) {
						$this->backends[$socket->sock] = $fd;
						$this->frontends[$fd]['socket'] = $socket;
						$this->frontends[$fd]['stage'] = STAGE_STREAM;
						$socket->send($this->frontends[$fd]['encryptor']->encrypt(substr($data, 3)));
						// 接受代理请求
						$buf_replies = "\x05\x00\x00\x01\x00\x00\x00\x00" . pack('n', $this->config['local_port']);
						$this->serv->send($fd, $buf_replies);
					});
					$socket->on('error', function (\swoole_client $socket) use ($fd) {
						$this->logger->error("connect to backend server failed");
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
						$this->serv->send($fd, $this->frontends[$fd]['encryptor']->decrypt($_data));
					});

					$socket->connect($this->config['server'], $this->config['server_port']);
				}
				break;
			case STAGE_STREAM:
				if (isset($this->frontends[$fd]['socket'])) {
					$this->frontends[$fd]['socket']->send($this->frontends[$fd]['encryptor']->encrypt($data));
				}
				break;
			default:
				break;
		}
	}

	public function onClose($serv, $fd, $from_id)
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
		$default = [
			'daemonize' => $this->config['daemon'],
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
	 * 解析socket5头部数据
	 * @param string $buffer
	 */
	protected function parse_socket5_header($buffer)
	{
		$buffer = substr($buffer, 3);
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