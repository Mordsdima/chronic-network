module chronic_network

import net
import encoding.base64
import encoding.binary
import encoding.leb128
import time

pub struct Client {
pub mut:
	socket      &net.UdpConn = unsafe { nil }
	state       ClientState  = .disconnected
	lseq        u64
	rseq        u64
	s2c_key     []u8 // Base64 encoded Server-To-Client key
	c2s_key     []u8 // Base64 encoded Client-To-Server key
	protocol_id u64
}

pub fn (mut client Client) init(token string) ! {
	mut pt := PublicToken.decode(token)!

	client.c2s_key = base64.decode(pt.c2s_key)
	client.s2c_key = base64.decode(pt.s2c_key)
	client.protocol_id = pt.protocol_id
	for server in pt.server_addresses {
		client.socket = net.dial_udp(server)! // ok
		net.set_blocking(client.socket.sock.handle, false)!
		client.try_connect(pt) or {
			println(err)
			continue
		}
		if client.state == .connected {
			return
		}
	}
}

fn (mut client Client) generate_nonce(seq u64) []u8 {
	mut buf := []u8{len: 12}
	binary.little_endian_put_u32(mut buf, 0)
	binary.little_endian_put_u64_end(mut buf, seq)
	return buf
}

fn (mut client Client) generate_ad(prefix u8) []u8 {
	mut buf := []u8{len: 9}
	binary.little_endian_put_u64(mut buf, client.protocol_id)
	buf[8] = prefix
	return buf
}

fn (mut client Client) recv_packet() !([]u8, []u8) {
	mut buf := []u8{len: 2048}
	nplen, npfrom := client.socket.read(mut buf)!

	buf.trim(nplen)

	rseq, rseql := leb128.decode_u64(buf[2..])

	if rseq < client.rseq {
		println('Too late received packet!')
	}

	hdr := buf[..(2 + rseql)].clone()

	buf = decrypt_aead(buf[(2 + rseql)..], client.generate_ad(buf[0]), client.generate_nonce(rseq),
		client.s2c_key)!

	return hdr, buf
}

pub fn (mut client Client) try_connect(pt PublicToken) ! {
	// try connect to server
	mut attempts := 0

	for {
		if attempts >= 10 {
			return error('Failed to connect')
		}

		mut pkt := []u8{}
		pkt << u8(0)
		pkt << u8(1 << 0)
		unsafe { pkt.grow_len(16) }
		binary.little_endian_put_u64_at(mut pkt, pt.protocol_id, 2)
		binary.little_endian_put_u64_end(mut pkt, u64(pt.exp))
		pkt << base64.decode(pt.nonce)
		pkt << leb128.encode_u64(u64(pt.private.len))
		pkt << pt.private.bytes()

		client.socket.write(pkt)!
		client.lseq += 1

		time.sleep(500000000) // wait 500 ms, if still no packet received (when server enabled) then you have 2g connection or idk

		mut hdr, mut buf := client.recv_packet() or {
			attempts += 1
			continue
		}

		// Valid packet

		pkt = []u8{}
		pkt << u8(3)
		pkt << u8(1 << 0)
		pkt << leb128.encode_u64(client.lseq)

		pkt << encrypt_aead(buf, client.generate_ad(0x03), client.generate_nonce(client.lseq),
			client.c2s_key)!

		client.lseq += 1
		client.socket.write(pkt)!

		// Now wait a new packet
		if pt.timeout == -1 {
			// still wait 100 ms
			time.sleep(100000000)

			hdr, buf = client.recv_packet() or {
				attempts += 1
				continue
			}
		}

		if hdr[0] == 1 {
			return error('Connection denied. Maybe invalid token?')
		} else if hdr[0] == 4 {
			client.state = .connected // We connected!
			return
		}

		attempts += 1
	}
}
