module chronic_network

import libsodium
import x.json2
import encoding.base64
import encoding.binary
import time

pub enum ClientState {
	connect_token_expired         = -6
	invalid_connect_token         = -5
	connection_timed_out          = -4
	connection_response_timed_out = -3
	connection_request_timed_out  = -2
	connection_denied             = -1
	disconnected                  = 0
	sending_connection_request    = 1
	sending_connection_response   = 2
	connected                     = 3
}

pub const request_ptype = 0
pub const denied_ptype = 1
pub const challenge_ptype = 2
pub const response_ptype = 3
pub const keepalive_ptype = 4
pub const payload_ptype = 5
pub const disconnect_ptype = 6
pub const ack_ptype = 7

pub const flags_reliable = 1 << 0
pub const flags_sequenced = 1 << 1
pub const flags_encrypted = 1 << 2

fn encrypt_xaead(message []u8, additional []u8, nonce []u8, key []u8) ![]u8 {
	assert key.len == 32
	assert nonce.len == 24

	encrypted_len_raw := u64(message.len) +
		u64(libsodium.crypto_aead_xchacha20poly1305_ietf_abytes())

	assert encrypted_len_raw <= u64(max_i32)
	encrypted_len := int(encrypted_len_raw)

	mut encrypted := []u8{len: encrypted_len}

	mut elen := u64(0)
	result := libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted.data, &elen,
		message.data, u64(message.len), additional.data, u64(additional.len), unsafe { nil },
		nonce.data, key.data)

	assert result == 0

	encrypted.trim(int(elen))

	return encrypted
}

fn decrypt_xaead(message []u8, additional []u8, nonce []u8, key []u8) ![]u8 {
	assert key.len == 32
	assert nonce.len == 24

	mut decrypted := []u8{len: message.len}

	mut elen := u64(0)
	result := libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data, &elen,
		unsafe { nil }, message.data, u64(message.len), additional.data, u64(additional.len),
		nonce.data, key.data)

	assert result == 0

	decrypted.trim(int(elen))

	return decrypted
}

fn encrypt_aead(message []u8, additional []u8, nonce []u8, key []u8) ![]u8 {
	assert key.len == 32
	assert nonce.len == 12

	encrypted_len_raw := u64(message.len) +
		u64(libsodium.crypto_aead_chacha20poly1305_ietf_abytes())

	assert encrypted_len_raw <= u64(max_i32)
	encrypted_len := int(encrypted_len_raw)

	mut encrypted := []u8{len: encrypted_len}

	mut elen := u64(0)
	result := libsodium.crypto_aead_chacha20poly1305_ietf_encrypt(encrypted.data, &elen,
		message.data, u64(message.len), additional.data, u64(additional.len), unsafe { nil },
		nonce.data, key.data)

	assert result == 0

	encrypted.trim(int(elen))

	return encrypted
}

fn decrypt_aead(message []u8, additional []u8, nonce []u8, key []u8) ![]u8 {
	assert key.len == 32
	assert nonce.len == 12

	mut decrypted := []u8{len: message.len}

	mut elen := u64(0)
	result := libsodium.crypto_aead_chacha20poly1305_ietf_decrypt(decrypted.data, &elen,
		unsafe { nil }, message.data, u64(message.len), additional.data, u64(additional.len),
		nonce.data, key.data)

	assert result == 0

	decrypted.trim(int(elen))

	return decrypted
}

pub fn generate_random(len usize) []u8 {
	mut buf := []u8{len: int(len)}
	libsodium.randombytes_buf(buf.data, len)
	return buf
}

pub struct PublicToken {
pub mut:
	// Its public token, encoded into base64 later
	version          string = '1.0.0' // Should be semver
	protocol_id      u64
	iat              i64 = time.now().unix_milli() // Issued At Time (create timestamp) in milliseconds (by default current time
	exp              i64 = time.now().unix_milli() + 30 * 1000 // Expires (expire timestamp) in milliseconds (by default current time + 30 seconds)
	nonce            string // Base64 encoded 24 bytes
	private          string // Encrypted and then encoded private token
	timeout          i16    // in seconds
	server_addresses []string
	s2c_key          string // Base64 encoded Server-To-Client key
	c2s_key          string // Base64 encoded Client-To-Server key
}

pub fn (mut pt PublicToken) encode() string {
	return base64.encode_str(json2.encode(pt))
}

pub fn PublicToken.decode(pt string) !PublicToken {
	return json2.decode[PublicToken](base64.decode_str(pt))
}

pub struct PrivateToken {
pub mut:
	client_id        u64
	timeout          i16
	server_addresses []string
	s2c_key          string // Base64 encoded Server-To-Client key
	c2s_key          string // Base64 encoded Client-To-Server key
	user_data        string // Anything but should be string, for example you can save json here as base64
}

pub fn (mut pt PrivateToken) encode(exp i64, protocol_id u64, nonce []u8, key []u8) !string {
	mut assoc := []u8{len: 16}
	binary.little_endian_put_u64(mut assoc, u64(exp))
	binary.little_endian_put_u64_end(mut assoc, protocol_id)
	return base64.encode(encrypt_xaead(json2.encode(pt).bytes(), assoc, nonce, key) or {
		return err
	})
}

pub fn PrivateToken.decode(exp i64, protocol_id u64, nonce []u8, key []u8, pt string) !PrivateToken {
	mut assoc := []u8{len: 16}
	binary.little_endian_put_u64(mut assoc, u64(exp))
	binary.little_endian_put_u64_end(mut assoc, protocol_id)

	bt := decrypt_xaead(base64.decode(pt), assoc, nonce, key)!

	str := unsafe { tos(bt.data, bt.len) }

	return json2.decode[PrivateToken](str)
}

pub struct ChallengeToken {
	client_id u64
	user_data string
}

pub fn (mut pt ChallengeToken) encode() string {
	return base64.encode_str(json2.encode(pt))
}

pub fn ChallengeToken.decode(pt string) !ChallengeToken {
	return json2.decode[ChallengeToken](base64.decode_str(pt))
}

@[params]
pub struct GenerateToken {
pub mut:
	nonce            []u8
	key              []u8
	exp              i64
	protocol_id      u64
	timeout          i16
	s2c_key          []u8
	c2s_key          []u8
	server_addresses []string
	client_id        u64
	user_data        string
}

pub fn generate_public_token(params GenerateToken) !string {
	mut public_token := PublicToken{
		protocol_id: params.protocol_id
		exp: params.exp
		nonce: base64.encode(params.nonce)
		server_addresses: params.server_addresses
		timeout: params.timeout
		c2s_key: base64.encode(params.c2s_key)
		s2c_key: base64.encode(params.s2c_key)
	}

	mut private_token := PrivateToken{
		client_id: params.client_id
		timeout: params.timeout
		server_addresses: params.server_addresses
		c2s_key: base64.encode(params.c2s_key)
		s2c_key: base64.encode(params.s2c_key)
		user_data: params.user_data
	}

	public_token.private = private_token.encode(params.exp, params.protocol_id, params.nonce,
		params.key)!
	return public_token.encode()
}

fn init() {
	// assert libsodium.sodium_init() >= 0
}
