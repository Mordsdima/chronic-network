module main

import cn
import time

fn test_server() {
	mut key := cn.generate_random(32)
	println(cn.generate_public_token(
		nonce: cn.generate_random(24)
		key: key
		exp: time.now().unix_milli() + 30 * 1000
		protocol_id: 1234
		timeout: -1
		s2c_key: cn.generate_random(32)
		c2s_key: cn.generate_random(32)
		server_addresses: ['127.0.0.1:10007']
		client_id: 0x1234567890
		user_data: 'Hello world!'
	)!)

	mut srv := cn.Server{
		protocol_id: 1234
		key: key
	}

	srv.init('0.0.0.0:10007')!

	for {
		srv.update()!
	}

	// assert 0 == 1
}
