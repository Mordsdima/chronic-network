module cn

import net
import encoding.binary
import encoding.leb128
import encoding.base64
import time

struct LazyPacket {
pub:
	hdr []u8
	buf []u8
}

pub struct SClient {
pub mut:
	cht_seq      u64
	state        ClientState = .disconnected
	lseq         u64
	rseq         u64
	client_id    u64
	timeout      i16
	ptimeout     time.Time
	pnextping    time.Time
	addr         net.Addr
	s2c_key      []u8   // Base64 encoded Server-To-Client key
	c2s_key      []u8   // Base64 encoded Client-To-Server key
	user_data    string // Anything but should be string, for example you can save json here as base64
	packet_cache map[u64][]u8
}

pub struct Server {
pub mut:
	challenge_token_seq u64
	challenge_token_key []u8
	socket              &net.UdpConn = unsafe { nil }
	protocol_id         u64
	key                 []u8
	max_clients         u64
	cur_clients         u64
	payload_handler     ServerPayloadHandler = unsafe { nil }
	connect_handler     ServerConnectHandler = unsafe { nil }
	disconnect_handler  ServerDisconnectHandler = unsafe { nil }
mut:
	clients map[string]SClient
}

pub fn (mut server Server) init(bind_addr string) ! {
	server.socket = net.listen_udp(bind_addr)!
	net.set_blocking(server.socket.sock.handle, false)!
	server.socket.set_read_timeout(time.microsecond * 500)
	server.challenge_token_key = generate_random(32)
}

fn (mut server Server) generate_nonce(seq u64) []u8 {
	mut buf := []u8{len: 12}
	binary.little_endian_put_u32(mut buf, 0)
	binary.little_endian_put_u64_end(mut buf, seq)
	return buf
}

fn (mut server Server) generate_ad(prefix u8) []u8 {
	mut buf := []u8{len: 9}
	binary.little_endian_put_u64(mut buf, server.protocol_id)
	buf[8] = prefix
	return buf
}

fn (mut server Server) generate_hdr(ptype u8, flags u8, seq u64) []u8 {
	mut buf := []u8{}
	buf << ptype
	buf << flags
	buf << leb128.encode_u64(seq)
	return buf
}

// Encrypts packet if required and returns ready for send packet
fn (mut server Server) create_packet(client SClient, hdr []u8, data []u8) ![]u8 {
	// second byte is flags, so we need to read, if encrypted then encrypt the packet
	mut pkt := hdr.clone()
	if (hdr[1] & flags_encrypted) != 0 {
		// Encrypted
		pkt << encrypt_aead(data, server.generate_ad(hdr[0]), server.generate_nonce(client.lseq),
			client.s2c_key)!
	} else {
		pkt << data // then just add unencrypted data to packet
	}

	return pkt
}

fn (mut server Server) send_packet(ptype u8, flags u8, mut client SClient, data []u8) ! {
	buf := server.create_packet(client, server.generate_hdr(ptype, flags, client.lseq),
		data)!

	client.packet_cache[client.lseq] = buf

	client.lseq += 1

	// Reliability is not ready yet ok
	server.socket.write_to(client.addr, buf)!
}

pub fn (mut server Server) update() ! {
	np, mut npdata, npfrom := server.recv_new_packets()!
	if np {
		mut client := (server.clients[npfrom.str()] or { SClient{} })
		// cool we have new packets!
		if npdata[0] == request_ptype {
			// Its "Connection Request Packet", next byte will be always reliable but not sequenced (1 << 0)
			_, rseql := leb128.decode_u64(npdata[2..])

			pid := binary.little_endian_u64_at(npdata, 2 + rseql)
			if pid != server.protocol_id {
				println(pid)
				println('Uh oh, client tried to connect with invalid protocol ID')
				return
			}

			exp := i64(binary.little_endian_u64_at(npdata, 10 + rseql))
			if exp <= time.now().unix_milli() {
				println('Token is expired!')
				return
			}

			npdata.delete_many(0, 18 + rseql)
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
				s2c_key: base64.decode(pp.s2c_key)
				c2s_key: base64.decode(pp.c2s_key)
				cht_seq: server.challenge_token_seq
				rseq: 1
				addr: npfrom
				client_id: pp.client_id
			}

			server.challenge_token_seq += 1

			client = (server.clients[npfrom.str()] or { panic('wtff') })

			mut cht := ChallengeToken{
				client_id: pp.client_id
				user_data: pp.user_data
			}

			mut buf := []u8{len: 12}
			binary.little_endian_put_u32(mut buf, 0)
			binary.little_endian_put_u64_end(mut buf, client.cht_seq)

			mut data := []u8{}

			data << [u8(0), 0, 0, 0, 0, 0, 0, 0]
			binary.little_endian_put_u64_end(mut data, client.cht_seq)

			data << (encrypt_aead(cht.encode().bytes(), []u8{}, buf, server.challenge_token_key)!)

			server.send_packet(challenge_ptype, flags_reliable, mut
				client, data)!
		} else if npdata[0] == response_ptype {
			if !((npdata[1] & flags_encrypted) != 0) {
				println('Connection Response Packet is not a encrypted one! Here is flags: ' +
					npdata[1].str())
				return
			}

			//mut client := (server.clients[npfrom.str()] or { panic('wtff') })

			// Cool, lets verify encrypted challenge token
			_, rseql := leb128.decode_u64(npdata[2..])
			cht_seq := binary.little_endian_u64_at(npdata, 2 + rseql)
			if client.cht_seq != cht_seq {
				// Deny this connection
				server.send_packet(denied_ptype, flags_reliable, mut client, []u8{})!
				println('Connection denied.')
				return
			}

			mut buf := []u8{len: 12}
			binary.little_endian_put_u32(mut buf, 0)
			binary.little_endian_put_u64_end(mut buf, client.cht_seq)

			cht_encrypted := npdata[(10 + rseql)..].clone()
			cht_decrypted := decrypt_aead(cht_encrypted, []u8{}, buf, server.challenge_token_key) or {
				server.send_packet(denied_ptype, flags_reliable, mut client, []u8{})!
				println('Connection denied.')
				return
			}
			cht_str := unsafe { tos(cht_decrypted.data, cht_decrypted.len) }

			cht := ChallengeToken.decode(cht_str) or {
				server.send_packet(denied_ptype, flags_reliable, mut client, []u8{})!
				println('Connection denied.')
				return
			}

			if cht.client_id != client.client_id {
				server.send_packet(denied_ptype, flags_reliable, mut client, []u8{})!
				println('Connection denied.')
				return
			}

			client.state = .connected
			client.ptimeout = time.now().add(time.second * 9) // set initial timeout
			server.clients[npfrom.str()] = client
			server.send_packet(connected_ptype, flags_reliable, mut client, []u8{})!
			if server.connect_handler != unsafe { nil } {
				server.connect_handler(client)!
			}
			println('New connection!')
		} else if npdata[0] == pong_ptype {
			//mut client := (server.clients[npfrom.str()] or { panic('wtff') })
			client.ptimeout = time.now().add(time.second * 9)
			server.clients[npfrom.str()] = client
		} else if npdata[0] == payload_ptype {
			_, rseql := leb128.decode_u64(npdata[2..])
			data := npdata[(2 + rseql)..]
			if server.payload_handler != unsafe { nil } {
				server.payload_handler(data, client)!
			}
		} else if npdata[0] == nack_ptype {
			//mut client := (server.clients[npfrom.str()] or { panic('wtff') })
			_, rseql := leb128.decode_u64(npdata[2..])
			seq, _ := leb128.decode_u64(npdata[(2 + rseql)..])
			server.socket.write_to(client.addr, client.packet_cache[seq])!
		} else if npdata[0] == ack_ptype {
			
			_, rseql := leb128.decode_u64(npdata[2..])
			// delete from cache
			seq, _ := leb128.decode_u64(npdata[(2 + rseql)..])
			client.packet_cache.delete(seq)
			server.clients[npfrom.str()] = client
		} else {
			println('Seems invalid packet!')
		}
	}

	for ip, mut client in server.clients {
		// Send ping if connected and received pong otherwise disconnect
		if client.state == .connected {
			if client.pnextping < time.now() {
				client.pnextping = time.now().add(time.second)
				server.send_packet(ping_ptype, 0, mut client, []u8{})!
			}

			if client.ptimeout < time.now() {
				println('Timed out.')
				server.send_packet(disconnect_ptype, 0, mut client, []u8{})!
				server.clients.delete(ip)
				if server.disconnect_handler != unsafe { nil } {
					server.disconnect_handler(client, DisconnectReason.timeout)!
				}
				continue
			}

			server.clients[ip] = client
		}
	}

	// assert 0 == 1
}

pub fn (mut server Server) recv_new_packets() !(bool, []u8, net.Addr) {
	mut buf := []u8{len: 2048}
	mut successful := true
	mut readed, from := server.socket.read(mut buf) or {
		successful = false
		return successful, buf, net.Addr{}
	}
	defer { server.clients[from.str()].rseq += 1 }
	buf.trim(readed)
	if (buf[1] & flags_encrypted) != 0 && from.str() in server.clients {
		mut client := server.clients[from.str()]
		rseq, rseql := leb128.decode_u64(buf[2..])

		if rseq > client.rseq {
			println('${rseq} > ${client.rseq}')
			println('Too late received packet!')
		}

		if rseq < client.rseq && (buf[1] & flags_reliable) != 0 {
			println('${rseq} < ${client.rseq}')
			mut missed_seq := []u64{}

			for seq in rseq .. client.rseq {
				missed_seq << seq
			}

			for seq in missed_seq {
				server.send_packet(nack_ptype, 0, mut client, leb128.encode_u64(seq))!
				println('NACKed: ${seq}')
			}
		}

		hdr := buf[..(2 + rseql)].clone()

		buf = decrypt_aead(buf[(2 + rseql)..], server.generate_ad(buf[0]), server.generate_nonce(rseq),
			client.c2s_key)!

		mut fpkt := hdr.clone()
		fpkt << buf

		return successful, fpkt, from
	} else {
		if buf[0] == payload_ptype && (buf[1] & flags_encrypted) == 0 {
			return false, buf, from
		}
		return successful, buf, from // should be ok on connect token blah blah
	}
}
