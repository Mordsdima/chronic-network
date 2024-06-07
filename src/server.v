module chronic_network

import net
import encoding.binary
import encoding.leb128
import encoding.base64
import time

pub struct SClient {
pub mut:
	cht_seq u64
	state ClientState = .disconnected
	lseq u64
	rseq u64
	client_id u64
	timeout i16
	s2c_key          []u8 // Base64 encoded Server-To-Client key
	c2s_key          []u8 // Base64 encoded Client-To-Server key
	user_data        string // Anything but should be string, for example you can save json here as base64
}

pub struct Server {
pub mut:
	challenge_token_seq u64
	challenge_token_key []u8
	socket &net.UdpConn = unsafe { nil }
	protocol_id u64
	key []u8
mut: 
	clients map[string]SClient
}

pub fn (mut server Server) init(bind_addr string) ! {
	server.socket = net.listen_udp(bind_addr)!
	net.set_blocking(server.socket.sock.handle, false)!
	server.challenge_token_key = generate_random(32)
}

pub fn (mut server Server) update() ! {
	np, mut npdata, npfrom := server.recv_new_packets()!

	if np {
		// cool we have new packets!
		if npdata[0] == 0 {
			// Its "Connection Request Packet", next byte will be always reliable but not sequenced (1 << 0)
			if npdata[1] != (1 << 0) {
				//println("Connection Request Packet is not a reliable! Here is flags: " + npdata[1].str())
				return
			}

			pid := binary.little_endian_u64_at(npdata, 2)
			if pid != server.protocol_id {
				println("Uh oh, client tried to connect with invalid protocol ID")
				return 
			}

			exp := i64(binary.little_endian_u64_at(npdata, 10))
			if exp <= time.now().unix_milli() {
				println("Token is expired!")
				return
			}

			npdata.delete_many(0, 18)
			mut nonce := npdata[..24].clone()
			npdata.delete_many(0, 24)

			pl, pll := leb128.decode_u64(npdata)
			npdata.delete_many(0, pll)

			mut private := npdata[..pl].clone()
			npdata.delete_many(0, int(pl))

			mut ps := unsafe { tos(private.data, private.len) }

			// finally we have private!
			mut pp := PrivateToken.decode(exp, pid, nonce, server.key, ps)!

			server.clients[npfrom.str()] = SClient{
				s2c_key: base64.decode(pp.s2c_key),
				c2s_key: base64.decode(pp.c2s_key),
				cht_seq: server.challenge_token_seq
			}

			println("Valid packet!")
			server.challenge_token_seq += 1
			mut pkt := []u8{}
			pkt << u8(2)
			pkt << leb128.encode_u64((server.clients[npfrom.str()] or { panic("wtff") }).lseq)
			mut cht := ChallengeToken{
				client_id: pp.client_id,
				user_data: pp.user_data
			}

			mut buf := []u8{len: 12}
			binary.little_endian_put_u32(mut buf, 0)
			binary.little_endian_put_u64_end(mut buf, (server.clients[npfrom.str()] or { panic("wtff") }).cht_seq)

			pkt << [u8(0), 0, 0, 0, 0, 0, 0, 0]
			binary.little_endian_put_u64_end(mut pkt, (server.clients[npfrom.str()] or { panic("wtff") }).cht_seq)
			
			pkt << (encrypt_aead(cht.encode().bytes(), []u8{}, buf, server.challenge_token_key)!)

			server.socket.write_to(npfrom, pkt)!
		}
	}

	//assert 0 == 1
}

pub fn (mut server Server) recv_new_packets() !(bool, []u8, net.Addr) {
	mut buf := []u8{len: 2048}
	mut successful := true
	mut readed, from := server.socket.read(mut &buf) or {
		successful = false
		return successful, buf, net.Addr{}
	}
	buf.trim(readed)
	return successful, buf, from
}
