module main

import os
import chronic_network as cn

pub fn test_client() {
	token := os.input('Enter your token please: ')
	if token == '' {
		panic('Token is not provided.')
	}

	mut client := cn.Client{}
	client.init(token)!

	for {
		client.update()!
		client.send(cn.flags_reliable, []u8{})!
	}
}
