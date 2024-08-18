module cn

import net
import time
import eventbus
import encoding.base64
import encoding.binary
import encoding.leb128

pub struct Client {
pub mut:
	socket             &net.UdpConn = unsafe { nil }
	state              ClientState  = .disconnected
	lseq               u64
	rseq               u64
	s2c_key            []u8 // Base64 encoded Server-To-Client key
	c2s_key            []u8 // Base64 encoded Client-To-Server key
	protocol_id        u64
	packet_cache       map[u64][]u8
	ptimeout           time.Time
	eb                 eventbus.EventBus[string] //= eventbus.new[string]()
}

pub fn (mut client Client) init(token string) ! {
	mut pt := PublicToken.decode(token)!

	client.c2s_key = base64.decode(pt.c2s_key)
	client.s2c_key = base64.decode(pt.s2c_key)
	client.protocol_id = pt.protocol_id
}

pub fn (mut client Client) connect() ! {
	mut last_error := error("none")
	for server in pt.server_addresses {
		client.socket = net.dial_udp(server)! // ok
		net.set_blocking(client.socket.sock.handle, false)!
		// client.socket.set_read_timeout(time.microsecond * 500)
		client.try_connect(pt) or {
			last_error = err
			continue
		}
		if client.state == .connected {
			client.ptimeout = time.now().add(time.second * 9)
			// firing event
			if client.eb.subscriber.is_subscribed("connect") {
				client.eb.publish("connect", unsafe { nil }, &client)
			}

			return
		}
	}
	// If reached here then its not connected
	return last_error
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

fn (mut client Client) generate_hdr(ptype u8, flags u8, seq u64) []u8 {
	mut buf := []u8{}
	buf << ptype
	buf << flags
	buf << leb128.encode_u64(seq)
	return buf
}

// Encrypts packet if required and returns ready for send packet
fn (mut client Client) create_packet(hdr []u8, data []u8) ![]u8 {
	// second byte is flags, so we need to read, if encrypted then encrypt the packet
	mut pkt := hdr.clone()
	if (hdr[1] & flags_encrypted) != 0 {
		// Encrypted
		pkt << encrypt_aead(data, client.generate_ad(hdr[0]), client.generate_nonce(client.lseq),
			client.c2s_key)!
	} else {
		pkt << data // then just add unencrypted data to packet
	}

	return pkt
}

fn (mut client Client) send_packet(ptype u8, flags u8, data []u8) ! {
	buf := client.create_packet(client.generate_hdr(ptype, flags, client.lseq), data)!
	client.lseq += 1

	// Reliability is not ready yet ok
	client.socket.write(buf)!
}

fn (mut client Client) recv_packet() !([]u8, []u8) {
	mut buf := []u8{len: 2048}
	nplen, _ := client.socket.read(mut buf)!

	buf.trim(nplen)

	rseq, rseql := leb128.decode_u64(buf[2..])
	if rseq < client.rseq {
		println('Too late received packet!')
	}

	hdr := buf[..(2 + rseql)].clone()

	if (hdr[1] & flags_encrypted) != 0 {
		buf = decrypt_aead(buf[(2 + rseql)..], client.generate_ad(buf[0]), client.generate_nonce(rseq),
			client.s2c_key)!
	} else {
		buf = buf[(2 + rseql)..].clone()
	}

	if rseq < client.rseq && (buf[1] & flags_reliable) != 0 {
		println('${rseq} < ${client.rseq}')
		mut missed_seq := []u64{}

		for seq in rseq .. client.rseq {
			missed_seq << seq
		}

		for seq in missed_seq {
			client.send_packet(nack_ptype, 0, leb128.encode_u64(seq))!
			println('NACKed: ${seq}')
		}
	}

	// ACK it if reliable

	return hdr, buf
}

pub fn (mut client Client) update() ! {
	if client.state != .connected {
		return
	}

	if client.ptimeout < time.now() {
		println('Timed out.')
		client.state = .disconnected
		client.send_packet(disconnect_ptype, 0, []u8{})!
		if client.eb.subscriber.is_subscribed("disconnect") {
			client.eb.publish("disconnect", DisconnectReason.timeout, &client)
		}
	}

	hdr, buf := client.recv_packet() or { return }

	if hdr[0] == ping_ptype {
		client.ptimeout = time.now().add(time.second * 9)
		client.send_packet(pong_ptype, 0, []u8{})!
	} else if hdr[0] == payload_ptype {
		rseq, _ := leb128.decode_u64(hdr[2..])
		client.send_packet(ack_ptype, 0, leb128.encode_u64(rseq))!
		// process it
		if client.eb.subscriber.is_subscribed("payload") {
			client.eb.publish("payload", IncomingPacket{
				flags: hdr[1],
				buf: buf
			}, &client)
		}
	} else if hdr[0] == nack_ptype {
		seq, _ := leb128.decode_u64(buf)
		client.socket.write(client.packet_cache[seq])!
	} else if hdr[0] == disconnect_ptype {
		// Server disconnect
		client.state = .disconnected
		if client.eb.subscriber.is_subscribed("disconnect") {
			client.eb.publish("disconnect", DisconnectReason.remote_disconnect, &client)
		}
	} else if hdr[0] == ack_ptype {
		// + миска риса и кошкожена
		seq, _ := leb128.decode_u64(buf)
		client.packet_cache.delete(seq)
	}
}

pub fn (mut client Client) send(flags u8, data []u8) ! {
	if client.state != .connected {
		return
	}
	client.send_packet(payload_ptype, flags | flags_encrypted, data)!
}

pub fn (mut client Client) try_connect(pt PublicToken) ! {
	// try connect to server
	mut attempts := 0

	for {
		if attempts >= 10 {
			return error('Failed to connect')
		}

		mut data := []u8{}
		unsafe { data.grow_len(16) }
		binary.little_endian_put_u64_at(mut data, pt.protocol_id, 0)
		binary.little_endian_put_u64_end(mut data, u64(pt.exp))
		data << base64.decode(pt.nonce)
		data << leb128.encode_u64(u64(pt.private.len))
		data << pt.private.bytes()

		client.send_packet(request_ptype, 0, data)!

		client.socket.set_read_timeout(time.second) // wait 1s, if still no packet received (when server enabled) then you have 2g connection or idk

		mut hdr, mut buf := client.recv_packet() or {
			attempts += 1
			continue
		}

		// Valid packet

		client.send_packet(response_ptype, flags_encrypted, buf)!

		// Now wait a new packet
		if pt.timeout == -1 {
			// still wait 100 ms
			client.socket.set_read_timeout(time.millisecond * 100)

			hdr, buf = client.recv_packet() or {
				attempts += 1
				continue
			}
		} else {
			client.socket.set_read_timeout(pt.timeout * time.second)

			hdr, buf = client.recv_packet() or {
				attempts += 1
				continue
			}
		}

		if hdr[0] == denied_ptype {
			return error('Connection denied. Maybe invalid token?')
		} else if hdr[0] == connected_ptype {
			client.socket.set_read_timeout(time.microsecond * 500)
			client.state = .connected // We connected!
			return
		}

		attempts += 1
	}
}
