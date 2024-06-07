module main

import chronic_network as cn
import time

fn test_main() {
	println(cn.generate_public_token(
		nonce: cn.generate_random(24)
		key: cn.generate_random(32)
		exp: time.now().unix_milli() + 30 * 1000
		protocol_id: 1234
		timeout: -1
		s2c_key: cn.generate_random(32)
		c2s_key: cn.generate_random(32)
		server_addresses: ['0.0.0.0']
		client_id: 0x1234567890
		user_data: 'Hello world!'
	)!)

	mut srv := cn.Server{}

	srv.init('0.0.0.0:10007')!

	for {
		srv.update()!
	}

	// assert 0 == 1
}
