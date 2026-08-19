@load base/protocols/ssl

module CSJA4;

export {
	redef record SSL::Info += {
		ja4: string &optional &log;
	};
}

const grease: set[count] = {
	2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
	35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250
};

type Hello: record {
	exts: vector of count;
	alpn: string &default="00";
	sni: bool &default=F;
};

global pending: table[string] of Hello &default=Hello($exts=vector());

function tls_ver(v: count): string
	{
	if ( v == 0x0304 )
		return "13";
	if ( v == 0x0303 )
		return "12";
	if ( v == 0x0302 )
		return "11";
	if ( v == 0x0301 )
		return "10";
	return "00";
	}

function two(n: count): string
	{
	if ( n > 99 )
		n = 99;
	if ( n < 10 )
		return fmt("0%d", n);
	return fmt("%d", n);
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( ! is_orig || code in grease )
		return;
	local uid = c$uid;
	if ( uid !in pending )
		pending[uid] = Hello($exts=vector());
	pending[uid]$exts += code;
	if ( code == 0 )
		pending[uid]$sni = T;
	}

event ssl_client_hello(c: connection, version: count, record_version: count,
    possible_ts: time, client_random: string, session_id: string,
    ciphers: index_vec, comp_methods: index_vec)
	{
	if ( ! c?$ssl )
		return;

	local kept: vector of string;
	for ( i in ciphers )
		{
		if ( ciphers[i] !in grease )
			kept += fmt("%04x", ciphers[i]);
		}

	local hello: Hello;
	if ( c$uid in pending )
		hello = pending[c$uid];
	else
		hello = Hello($exts=vector());

	local ext_hex: vector of string;
	for ( j in hello$exts )
		ext_hex += fmt("%04x", hello$exts[j]);

	local sni_flag = hello$sni ? "d" : "i";
	local alpn = hello$alpn;
	local cipher_hash = sha256_hash(join_string_vec(kept, ","))[0:12];
	local ext_hash = sha256_hash(join_string_vec(ext_hex, ","))[0:12];
	c$ssl$ja4 = fmt("t%s%s%s%s%s_%s_%s", tls_ver(version), sni_flag,
	    two(|kept|), two(|hello$exts|), alpn, cipher_hash, ext_hash);

	delete pending[c$uid];
	}
