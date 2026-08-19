@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/http
@load base/protocols/dns

@load ./json-logs
@load ./hassh
@load ./ja4

redef ignore_checksums = T;
redef likely_server_ports += { 2222/tcp, 8080/tcp, 8443/tcp };

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_SSH, 2222/tcp);
	Analyzer::register_for_port(Analyzer::ANALYZER_SSL, 8443/tcp);
	}
