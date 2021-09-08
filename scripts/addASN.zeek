redef record Conn::Info += {
	orig_asn: count &optional &log;
	resp_asn: count &optional &log;
};

event connection_state_remove(c: connection)
{
	local oasn = lookup_asn(c$id$orig_h);
	local rasn = lookup_asn(c$id$resp_h);
	if ( oasn != 0 )
		c$conn$orig_asn = oasn;
	if ( rasn != 0 )
		c$conn$resp_asn = rasn;
}
