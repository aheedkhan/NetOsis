@load base/protocols/ssh

redef record SSH::Info += {
	hassh: string &optional &log;
	hasshAlgorithms: string &optional &log;
};

event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities)
	{
	if ( capabilities$is_server )
		return;
	if ( ! c?$ssh )
		return;

	local kex = join_string_vec(capabilities$kex_algorithms, ",");
	local enc = join_string_vec(capabilities$encryption_algorithms$client_to_server, ",");
	local mac = join_string_vec(capabilities$mac_algorithms$client_to_server, ",");
	local cmp = join_string_vec(capabilities$compression_algorithms$client_to_server, ",");
	local algos = fmt("%s;%s;%s;%s", kex, enc, mac, cmp);
	c$ssh$hasshAlgorithms = algos;
	c$ssh$hassh = md5_hash(algos);
	}
