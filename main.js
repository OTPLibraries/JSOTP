
function b64_hmac_sha1(k,d,_p,_z){
  if(!_p){_p='=';}if(!_z){_z=8;}function _f(t,b,c,d){if(t<20){return(b&c)|((~b)&d);}if(t<40){return b^c^d;}if(t<60){return(b&c)|(b&d)|(c&d);}return b^c^d;}function _k(t){return(t<20)?1518500249:(t<40)?1859775393:(t<60)?-1894007588:-899497514;}function _s(x,y){var l=(x&0xFFFF)+(y&0xFFFF),m=(x>>16)+(y>>16)+(l>>16);return(m<<16)|(l&0xFFFF);}function _r(n,c){return(n<<c)|(n>>>(32-c));}function _c(x,l){x[l>>5]|=0x80<<(24-l%32);x[((l+64>>9)<<4)+15]=l;var w=[80],a=1732584193,b=-271733879,c=-1732584194,d=271733878,e=-1009589776;for(var i=0;i<x.length;i+=16){var o=a,p=b,q=c,r=d,s=e;for(var j=0;j<80;j++){if(j<16){w[j]=x[i+j];}else{w[j]=_r(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);}var t=_s(_s(_r(a,5),_f(j,b,c,d)),_s(_s(e,w[j]),_k(j)));e=d;d=c;c=_r(b,30);b=a;a=t;}a=_s(a,o);b=_s(b,p);c=_s(c,q);d=_s(d,r);e=_s(e,s);}return[a,b,c,d,e];}function _b(s){var b=[],m=(1<<_z)-1;for(var i=0;i<s.length*_z;i+=_z){b[i>>5]|=(s.charCodeAt(i/8)&m)<<(32-_z-i%32);}return b;}function _h(k,d){var b=_b(k);if(b.length>16){b=_c(b,k.length*_z);}var p=[16],o=[16];for(var i=0;i<16;i++){p[i]=b[i]^0x36363636;o[i]=b[i]^0x5C5C5C5C;}var h=_c(p.concat(_b(d)),512+d.length*_z);return _c(o.concat(h),512+160);}function _n(b){var t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",s='';for(var i=0;i<b.length*4;i+=3){var r=(((b[i>>2]>>8*(3-i%4))&0xFF)<<16)|(((b[i+1>>2]>>8*(3-(i+1)%4))&0xFF)<<8)|((b[i+2>>2]>>8*(3-(i+2)%4))&0xFF);for(var j=0;j<4;j++){if(i*8+j*6>b.length*32){s+=_p;}else{s+=t.charAt((r>>6*(3-j))&0x3F);}}}return s;}function _x(k,d){return _n(_h(k,d));}return _x(k,d);
}


function encrypt_sha1(byte_secret, byte_string) {
	return new Int8Array(atob(b64_hmac_sha1(String.fromCharCode.apply(String, byte_secret), String.fromCharCode.apply(String, byte_string))).split('').map(x => x.charCodeAt(0)));
}


window.onload = function() {
	
	////////////////////////////////////////////////////////////////
	// Initialization Stuff                                       //
	////////////////////////////////////////////////////////////////
	
	let INTERVAL	= 30;
	let DIGITS		= 6;
	
	let BASE32_SECRET = "JBSWY3DPEHPK3PXP";
	let SHA1_DIGEST = "SHA1";
	
	let SHA1_BITS = 160;
	
	let tdata = new TOTP(BASE32_SECRET, SHA1_BITS, encrypt_sha1, SHA1_DIGEST, DIGITS, INTERVAL);
	let hdata = new HOTP(BASE32_SECRET, SHA1_BITS, encrypt_sha1, SHA1_DIGEST, DIGITS);
	
	console.log("\\\\ totp tdata \\\\");
	console.log("tdata.digits: `" + tdata.digits + "`");
	console.log("tdata.interval: `" + tdata.interval + "`");
	console.log("tdata.bits: `" + tdata.bits + "`");
	console.log("tdata.method: `" + tdata.method + "`");
	console.log("tdata.digest: `" + tdata.digest + "`");
	console.log("tdata.base32_secret: `" + tdata.base32_secret + "`");
	console.log("// totp tdata //\n");
	
	console.log("\\\\ hotp hdata \\\\");
	console.log("hdata.digits: `" + hdata.digits + "`");
	console.log("hdata.bits: `" + hdata.bits + "`");
	console.log("hdata.method: `" + hdata.method + "`");
	console.log("hdata.digest: `" + hdata.digest + "`");
	console.log("hdata.base32_secret: `" + hdata.base32_secret + "`");
	console.log("// hotp hdata //\n");
	
	console.log("Current Time: `" + parseInt(new Date().getTime()/1000) + "`");
	
	
	////////////////////////////////////////////////////////////////
	// URI Example                                                //
	////////////////////////////////////////////////////////////////
	
	let name1 = "name1";
	let name2 = "name2";
	let whatever1 = "account@whatever1.com";
	let whatever2 = "account@whatever2.com";
	
	// show example of URIs
	
	// totp uri
	let uri1 = OTPURI.build_uri(tdata, name1, whatever1, 0);
	
	// hotp uri
	let counter = 52;
	let uri2 = OTPURI.build_uri(hdata, name2, whatever2, counter);
	
	
	console.log("TOTP URI 1: `" + uri1 + "`\n");
	console.log("HOTP URI 2: `" + uri2 + "`\n");
	
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	// Already seeded the random generator and popped the first result
	
	let BASE32_LEN = 16;
	
	let base32_new_secret = tdata.random_base32(BASE32_LEN, OTP_DEFAULT_BASE32_CHARS);
	console.log("Generated BASE32 Secret: `" + base32_new_secret + "`");
	
	console.log(""); // line break for readability
	
	
	////////////////////////////////////////////////////////////////
	// TOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get TOTP for a time block
	//   1. Generate and load totp key into buffer
	//   2. Check for error
	
	// totp.now
	let totp_err_1 = tdata.now();
	console.log("TOTP Generated: `" + totp_err_1 + "`");
	
	// totp.at
	let totp_err_2 = tdata.at(1, 0);
	console.log("TOTP Generated: `" + totp_err_2 + "`");
	
	
	// Do a verification for a hardcoded code
	// Won't succeed, this code is for a timeblock far into the past
	let tv1 = tdata.verify(576203, parseInt(new Date().getTime()/1000), 4);
	
	// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
	let tv2 = tdata.verify(282760, 0, 4);
	console.log("TOTP Verification 1: `" + tv1 + "`");
	console.log("TOTP Verification 2: `" + tv2 + "`");
	
	console.log(""); // line break for readability
	
	
	////////////////////////////////////////////////////////////////
	// HOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get HOTP for token 1
	//   1. Generate and load hotp key into buffer
	//   2. Check for error
	
	let hotp_err_1 = hdata.at(1);
	console.log("HOTP Generated at 1: `" + hotp_err_1 + "`");
	
	// Do a verification for a hardcoded code
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	let hv = hdata.verify(996554, 1);
	console.log("HOTP Verification 1: `" + hv + "`");
	
}
