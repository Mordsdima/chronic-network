module chronic_network

import net
import encoding.base64

pub struct Client {
pub mut:
	socket &net.UdpConn = unsafe { nil }
	state ClientState = .disconnected
	lseq u64
	rseq u64
	s2c_key          []u8 // Base64 encoded Server-To-Client key
	c2s_key          []u8 // Base64 encoded Client-To-Server key
}

pub fn (mut client Client) init(token string) ! {
	mut pt := PublicToken.decode(token)!

	client.c2s_key = base64.decode(pt.c2s_key)
	client.s2c_key = base64.decode(pt.s2c_key)
	for server in pt.server_addresses {
		client.socket = net.dial_udp(server)! // ok
		client.try_connect() or { println(err); continue }
		if client.state == .connected {
			return // we have connected!
		}
	}
} 

pub fn (mut client Client) try_connect() ! {
	// try connect to server
	mut attempts := 0

	for {
		if attempts >= 10 {
			return error("Failed to connect")
		}
	}
}