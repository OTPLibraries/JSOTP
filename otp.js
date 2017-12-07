
const OTP_DEFAULT_BASE32_CHARS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'];

const OTPType = {OTP : 0, TOTP : 1, HOTP : 2};

class OTP {
	
	constructor(base32_secret, bits, algo, digest, digits) {
		this.base32_secret = base32_secret;
		this.bits = bits;
		this.algo = algo;
		this.digest = digest;
		this.digits = digits;
		this.method = OTPType.OTP;
	}
	
	generate(input, out) {
		let secret_len = this.base32_secret.length;
		let desired_secret_len = (secret_len / 8) * 5;
		
		if (this.bits % 8 != 0)
			console.exception("generate `this.bits` must be divisble by 8 (got ", this.bits, ")");
		
		let bit_size = this.bits / 8;
		
		let byte_string = this.int_to_bytestring(input);
		let byte_secret = this.byte_secret(secret_len, desired_secret_len + 1);
		let hmac = this.algo(byte_secret, byte_string);
		
		if (hmac == null)
			console.exception("generate `hmac` returned null from supplied decrypt function");
		
		let offset = (hmac[bit_size - 1] & 0xF);
		let code =
			(
			 (hmac[offset] & 0x7F) << 24 |
			 (hmac[offset+1] & 0xFF) << 16 |
			 (hmac[offset+2] & 0xFF) << 8 |
			 (hmac[offset+3] & 0xFF)
			) % parseInt(Math.pow(10, this.digits));
		
		return out ? code.toString().padStart(this.digits, '0').split('') : code;
	}
	
	byte_secret(size, len) {
		if (size % 8 != 0)
			console.exception("byte_secret `size` must be divisble by 8 (got ", size, ")");
		
		let out_str = new Int8Array(len);
		
		let n = 5;
		for (let i=0; ; i++) {
			n = -1;
			out_str[i*5] = 0;
			for (let block=0; block<8; block++) {
				let offset = (3 - (5*block) % 8);
				let octet = (block*5) / 8;
				
				let c = 0;
				if(i*8+block < size)
					c = this.base32_secret.charCodeAt(i*8 + block) & 0xFF;
				
				if (c >= 65 && c <= 90)
					n = c - 65;
				if (c >= 50 && c <= 55)
					n = 26 + c - 50;
				if (n < 0) {
					n = octet;
					break;
				}
				
				out_str[parseInt(i*5+octet)] |= -offset > 0 ? n >> -offset : n << offset;
				if (offset < 0)
					out_str[parseInt(i*5+octet+1)] = -(8 + offset) > 0 ? n >> -(8 + offset) : n << (8 + offset);
			}
			if (n < 5)
				break;
		}
		return out_str;
	}
	
	int_to_bytestring(integer) {
		return new Int8Array(['\0', '\0', '\0', '\0', (integer >> 24), (integer >> 16), (integer >> 8), integer], '\0');
	}
	
	random_base32(len, chars) {
		len = len > 0 ? len : 16;
		if (len % 8 != 0)
			console.exception("random_base32 `len` must be divisble by 8 (got", len, ")");
		let bytes = [];
		for (let i=0; i<len; i++)
			bytes[i] = chars[parseInt((Math.random() * (1024 - 0) + 0) % 32)];
		return bytes;
	}
	
}

class TOTP extends OTP {

	
	constructor(base32_secret, bits, algo, digest, digits, interval) {
		super(base32_secret, bits, algo, digest, digits);
		this.interval = interval;
		super.method = OTPType.TOTP;
	}
	
	compare(key, increment, for_time) {
		if(typeof(key) === "number")
			key = key.toString().padStart(this.digits, '0').split('');
		let time_str = this.at(for_time, increment, true);
		
		for (let i=0; i<key.length; i++)
			if(i > time_str.length || key[i] != time_str[i])
				return false;
		return true;
	}
	
	at(for_time, counter_offset, out) {
		return super.generate(this.timecode(for_time) + counter_offset, out);
	}
	
	now(out) {
		return super.generate(this.timecode(new Date().getTime()/1000), out);
	}
	
	verify(key, for_time, valid_window) {
		if (valid_window < 0)
			return false;
		if (valid_window > 0) {
			for (let i=-valid_window; i<valid_window; i++) {
				if (this.compare(key, i, for_time) === true)
					return true;
			}
		}
		return this.compare(key, 0, for_time);
	}
	
	valid_until(for_time, valid_window) {
		return for_time + (super.interval * valid_window);
	}
	
	timecode(for_time) {
		if (for_time <= 0)
			return 0;
		return parseInt(for_time/this.interval);
	}
	
}

class HOTP extends OTP {

	
	constructor(base32_secret, bits, algo, digest, digits) {
		super(base32_secret, bits, algo, digest, digits);
		super.method = OTPType.HOTP;
	}
	
	compare(key, counter) {
		if(typeof key === "number")
			key = key.toString().padStart(this.digits, '0').split('');
		let time_str = this.at(counter, true);
		
		for (let i=0; i<key.length; i++)
			if(i > time_str.length || key[i] != time_str[i])
				return false;
		return true;
	}
	
	at(counter, out) {
		return super.generate(counter, out);
	}
	
	verify(key, counter) {
		return this.compare(key, counter);
	}
	
}

class OTPURI {
	
	static build_uri(data, issuer, name, counter) {
		let cissuer = encodeURIComponent(issuer);
		
		let postarg = "";
		let otp_type = "";
		switch(data.method) {
			case OTPType.TOTP:
				otp_type = "totp";
				postarg += "&period=" + data.interval;
				break;
			case OTPType.HOTP:
				otp_type = "hotp";
				postarg += "&counter=" + counter;
				break;
			default:
				otp_type = "otp";
				break;
		}
		
		let pre = "otpauth://" + otp_type + "/" + cissuer + ":" + encodeURIComponent(name);
		let args =
			"?secret=" + encodeURIComponent(data.base32_secret) +
			"&issuer=" + cissuer +
			"&algorithm=" + encodeURIComponent(data.digest) +
			"&digits=" + data.digits;
		return pre + args + postarg;
	}
	
}

