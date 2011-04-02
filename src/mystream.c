/* iksemel (XML parser for Jabber)
** Copyright (C) 2000-2007 Gurer Ozen
** This code is free software; you can redistribute it and/or
** modify it under the terms of GNU Lesser General Public License.
*/


#include "common.h"
#include "iksemel.h"

#define SF_TRY_SECURE 2
#define SF_SECURE 4

struct stream_data {
	iksparser *prs;
	ikstack *s;
	ikstransport *trans;	
	void *user_data;
	const char *server;
	iksXmppPacketHook *xmppHook;
	iksLogHook *logHook;
	iks *current;		
	unsigned int flags;
	iksid *jid;
	char *pass;
	int authorized;
	iksfilter *filter;
};

static void
xmpp_insert_attribs (iks *x, char **atts)
{
	if (atts) {
		int i = 0;
		while (atts[i]) {
			iks_insert_attrib (x, atts[i], atts[i+1]);
			i += 2;
		}
	}
}

#define CNONCE_LEN 4

static void
xmpp_parse_digest (char *message, const char *key, char **value_ptr, char **value_end_ptr)
{
	char *t;

	*value_ptr = NULL;
	*value_end_ptr = NULL;

	t = strstr(message, key);
	if (t) {
		t += strlen(key);
		*value_ptr = t;
		while (t[0] != '\0') {
			if (t[0] != '\\' && t[1] == '"') {
				++t;
				*value_end_ptr = t;
				return;
			}
			++t;
		}
	}
}

static iks *
xmpp_make_sasl_response (struct stream_data *data, char *message)
{
	iks *x = NULL;
	char *realm, *realm_end;
	char *nonce, *nonce_end;
	char cnonce[CNONCE_LEN*8 + 1];
	iksmd5 *md5;
	unsigned char a1_h[16], a1[33], a2[33], response_value[33];
	char *response, *response_coded;
	int i;

	xmpp_parse_digest(message, "realm=\"", &realm, &realm_end);
	xmpp_parse_digest(message, "nonce=\"", &nonce, &nonce_end);

	/* nonce is necessary for auth */
	if (!nonce || !nonce_end) return NULL;
	*nonce_end = '\0';

	/* if no realm is given use the server hostname */
	if (realm) {
		if (!realm_end) return NULL;
		*realm_end = '\0';
	} else {
		realm = (char *) data->server;
	}

	/* generate random client challenge */
	for (i = 0; i < CNONCE_LEN; ++i)
		sprintf (cnonce + i*8, "%08x", rand());

	md5 = iks_md5_new();
	if (!md5) return NULL;

	iks_md5_hash (md5, (const unsigned char*)data->jid->user, iks_strlen (data->jid->user), 0);
	iks_md5_hash (md5, (const unsigned char*)":", 1, 0);
	iks_md5_hash (md5, (const unsigned char*)realm, iks_strlen (realm), 0);
	iks_md5_hash (md5, (const unsigned char*)":", 1, 0);
	iks_md5_hash (md5, (const unsigned char*)data->pass, iks_strlen (data->pass), 1);
	iks_md5_digest (md5, a1_h);

	iks_md5_reset (md5);
	iks_md5_hash (md5, (const unsigned char*)a1_h, 16, 0);
	iks_md5_hash (md5, (const unsigned char*)":", 1, 0);
	iks_md5_hash (md5, (const unsigned char*)nonce, iks_strlen (nonce), 0);
	iks_md5_hash (md5, (const unsigned char*)":", 1, 0);
	iks_md5_hash (md5, (const unsigned char*)cnonce, iks_strlen (cnonce), 1);
	iks_md5_print (md5, (char*)a1);

	iks_md5_reset (md5);
	iks_md5_hash (md5, (const unsigned char*)"AUTHENTICATE:xmpp/", 18, 0);
	iks_md5_hash (md5, (const unsigned char*)data->server, iks_strlen (data->server), 1);
	iks_md5_print (md5, (char*)a2);

	iks_md5_reset (md5);
	iks_md5_hash (md5, (const unsigned char*)a1, 32, 0);
	iks_md5_hash (md5, (const unsigned char*)":", 1, 0);
	iks_md5_hash (md5, (const unsigned char*)nonce, iks_strlen (nonce), 0);
	iks_md5_hash (md5, (const unsigned char*)":00000001:", 10, 0);
	iks_md5_hash (md5, (const unsigned char*)cnonce, iks_strlen (cnonce), 0);
	iks_md5_hash (md5, (const unsigned char*)":auth:", 6, 0);
	iks_md5_hash (md5, (const unsigned char*)a2, 32, 1);
	iks_md5_print (md5, (char*)response_value);

	iks_md5_delete (md5);

	i = iks_strlen (data->jid->user) + iks_strlen (realm) +
		iks_strlen (nonce) + iks_strlen (data->server) +
		CNONCE_LEN*8 + 136;
	response = iks_malloc (i);
	if (!response) return NULL;

	sprintf (response, "username=\"%s\",realm=\"%s\",nonce=\"%s\""
		",cnonce=\"%s\",nc=00000001,qop=auth,digest-uri=\""
		"xmpp/%s\",response=%s,charset=utf-8",
		data->jid->user, realm, nonce, cnonce,
		data->server, response_value);

	response_coded = iks_base64_encode (response, 0);
	if (response_coded) {
		x = iks_new ("response");
		iks_insert_cdata (x, response_coded, 0);
		iks_free (response_coded);
	}
	iks_free (response);

	return x;
}

static void
xmpp_sasl_challenge (struct stream_data *data, iks *challenge)
{
	char *message;
	iks *x;
	char *tmp;

	tmp = iks_cdata (iks_child (challenge));
	if (!tmp) return;

	/* decode received blob */
	message = iks_base64_decode (tmp);
	if (!message) return;

	/* reply the challenge */
	if (strstr (message, "rspauth")) {
		x = iks_new ("response");
	} else {
		x = xmpp_make_sasl_response (data, message);
	}
	if (x) {
		iks_insert_attrib (x, "xmlns", IKS_NS_XMPP_SASL);
		xmpp_send (data->prs, x);
		iks_delete (x);
	}
	iks_free (message);
}

static void
xmpp_write_log (struct stream_data *data, const char *buf, size_t size, int type)
{
	if (data->logHook) data->logHook(data->user_data, buf, size, type);
}


static int
xmpp_start_tls (iksparser *prs)
{
	int ret;
	struct stream_data *data = iks_user_data (prs);	
	
	if (!data->trans) return IKS_NET_NOCONN;
	if (!data->trans->handshake) return IKS_NET_NOTSUPP;
	
	ret = xmpp_send_xml (prs, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
	if (ret != IKS_OK) return ret;
	data->flags |= SF_TRY_SECURE;
	return IKS_OK;
}

static int
xmpp_start_sasl (iksparser *prs, enum ikssasltype type, char *username, char *pass)
{
	iks *x;
	int err;

	x = iks_new ("auth");
	iks_insert_attrib (x, "xmlns", IKS_NS_XMPP_SASL);
	switch (type) {
		case IKS_SASL_PLAIN: {
			int len = iks_strlen (username) + iks_strlen (pass) + 2;
			char *s = iks_malloc (80+len);
			char *base64;

			iks_insert_attrib (x, "mechanism", "PLAIN");
			sprintf (s, "%c%s%c%s", 0, username, 0, pass);
			base64 = iks_base64_encode (s, len);
			iks_insert_cdata (x, base64, 0);
			iks_free (base64);
			iks_free (s);
			break;
		}
		case IKS_SASL_DIGEST_MD5: {
			iks_insert_attrib (x, "mechanism", "DIGEST-MD5");
			break;
		}
		default:
			iks_delete (x);
			return IKS_NET_NOTSUPP;
	}
	err = xmpp_send (prs, x);
	iks_delete (x);
	if (err != IKS_OK) return err;
	return IKS_OK;
}

static int
xmpp_internal_hook (struct stream_data *data, int type, iks *node)
{
	//int err;
	
	switch (type) {
		case IKS_NODE_START:
			break;
		case IKS_NODE_ERROR:
			xmpp_write_log (data, "stream error", 0, IKS_LOG_ERROR);
			if (node) iks_delete (node);
			return IKS_NET_DROPPED;
		case IKS_NODE_STOP:
			xmpp_write_log (data, "server disconnected [%s]", 0, IKS_LOG_ERROR);
            if (node) iks_delete (node);
            return IKS_NET_DROPPED;
		case IKS_NODE_NORMAL:
			if (strcmp ("stream:features", iks_name (node)) == 0) 
			{
				int feat = iks_stream_features (node);
				if (data->authorized)
				{
					iks *t;
					if (feat & IKS_STREAM_BIND) {
						t = iks_make_resource_bind (data->jid);
						xmpp_send (data->prs, t);
						iks_delete (t);
					}
					if (feat & IKS_STREAM_SESSION) {
						t = iks_make_session ();
						iks_insert_attrib (t, "id", "auth");
						xmpp_send (data->prs, t);
						iks_delete (t);
					}
				} else {
					if (feat & IKS_STREAM_STARTTLS) {
						xmpp_start_tls(data->prs);
						//if (node) iks_delete (node);
						//if (err) return err;
						//break;
					}				
					else if (feat & IKS_STREAM_SASL_MD5)
						xmpp_start_sasl(data->prs, IKS_SASL_DIGEST_MD5, data->jid->user, data->pass);
					else if (feat & IKS_STREAM_SASL_PLAIN)
						xmpp_start_sasl (data->prs, IKS_SASL_PLAIN, data->jid->user, data->pass);
				}
			} // features
			else if (strcmp ("proceed", iks_name(node)) == 0 ) {
				if (data->trans->handshake) data->trans->handshake(data->user_data);
			}
			else if (strcmp ("failure", iks_name (node)) == 0) {
				if (data->flags & SF_TRY_SECURE) {
					xmpp_write_log(data, "tls handshake failed", 0, IKS_LOG_ERROR);
				} else {
					xmpp_write_log (data, "sasl authentication failed", 0, IKS_LOG_ERROR);
				}
				if (node) iks_delete (node);
				xmpp_disconnect(data->prs);
				return IKS_NET_DROPPED;
			} else if (strcmp ("success", iks_name (node)) == 0) {
				data->authorized = 1;
				xmpp_send_header (data->prs, data->jid->server);
			} else {
				ikspak *pak;

				pak = iks_packet (node);
				//iks_filter_packet (data->filter, pak);
				if (data->xmppHook) data->xmppHook(data->user_data, pak);
			}
			//break;
	}
    if (node) iks_delete (node);
    return IKS_OK;
}

static int
xmpp_tagHook (struct stream_data *data, char *name, char **atts, int type)
{
	iks *x;
	int err;

	switch (type) {
		case IKS_OPEN:
		case IKS_SINGLE:
			if (data->current) {
				x = iks_insert (data->current, name);
				xmpp_insert_attribs (x, atts);
			} else {
				x = iks_new (name);
				xmpp_insert_attribs (x, atts);
				if (iks_strcmp (name, "stream:stream") == 0) {
					err = xmpp_internal_hook (data, IKS_NODE_START, x);
					if (err != IKS_OK) return err;
					break;
				}
			}
			data->current = x;
			if (IKS_OPEN == type) break;
		case IKS_CLOSE:
			x = data->current;
			if (NULL == x) {
				err = xmpp_internal_hook (data, IKS_NODE_STOP, NULL);
				if (err != IKS_OK) return err;
				break;
			}
			if (NULL == iks_parent (x)) {
				data->current = NULL;
				if (iks_strcmp (name, "challenge") == 0) {
					xmpp_sasl_challenge(data, x);
					iks_delete (x);
				} else if (iks_strcmp (name, "stream:error") == 0) {
					err = xmpp_internal_hook (data, IKS_NODE_ERROR, x);
					if (err != IKS_OK) return err;
				} else {
					err = xmpp_internal_hook (data, IKS_NODE_NORMAL, x);
					if (err != IKS_OK) return err;
				}
				break;
			}
			data->current = iks_parent (x);
	}
	return IKS_OK;	
}

static int
xmpp_cdataHook (struct stream_data *data, char *cdata, size_t len)
{
	if (data->current) iks_insert_cdata (data->current, cdata, len);
	return IKS_OK;	
}

static void
xmpp_deleteHook (struct stream_data *data)
{
	if (data->trans) data->trans->close (data->user_data);
	data->trans = NULL;	
	if (data->current) iks_delete (data->current);
	data->current = NULL;
	data->flags = 0;	
}

iksparser *
xmpp_init_parser (void *user_data, iksXmppPacketHook *xmppHook, iksLogHook *logHook)
{
	ikstack *s;
	struct stream_data *data;

	s = iks_stack_new (DEFAULT_STREAM_CHUNK_SIZE, 0);
	if (NULL == s) return NULL;
	data = iks_stack_alloc (s, sizeof (struct stream_data));
	memset (data, 0, sizeof (struct stream_data));
	data->s = s;
	data->prs = iks_sax_extend (s, data, (iksTagHook *)xmpp_tagHook, (iksCDataHook *)xmpp_cdataHook, (iksDeleteHook *)xmpp_deleteHook);
	data->user_data = user_data;
	if (xmppHook) data->xmppHook = xmppHook;
	if (logHook) data->logHook = logHook;
	return data->prs;	
}

iksid *
xmpp_set_jid (iksparser *prs, char *jid, char *passwd)
{
	iksid *id;
	struct stream_data *data = iks_user_data(prs);
	
	if (!jid) return NULL;
	if (!passwd) return NULL;
	
	id = iks_id_new(iks_parser_stack(data->prs), jid);
	if (!id) return NULL;
	
	data->jid = id;
	data->pass = passwd;
	return id;
}

int
xmpp_connect (iksparser *prs, const char *server, int port, ikstransport *trans)
{
	struct stream_data *data = iks_user_data (prs);	
	
	if (!trans->connect) return IKS_NET_NOTSUPP;
	data->trans = trans;
	data->trans->connect (data->user_data, server, port);
	return IKS_OK;
}

void
xmpp_disconnect (iksparser *prs)
{
	iks_parser_reset (prs);
}

int
xmpp_send_xml (iksparser *prs, const char *xmlstr)
{
	struct stream_data *data = iks_user_data (prs);	
	
	if (!data->trans) return IKS_NET_NOCONN;
	if (!data->trans->send) return IKS_NET_NOTSUPP;
	data->trans->send (data->user_data, xmlstr, strlen (xmlstr));
	if (data->logHook) data->logHook (data->user_data, xmlstr, strlen (xmlstr), IKS_LOG_SEND);
	return IKS_OK;
}

int
xmpp_send (iksparser *prs, iks *x)
{
	return xmpp_send_xml (prs, iks_string (iks_stack (x), x));
}

int
xmpp_send_header (iksparser *prs, const char *to)
{
	struct stream_data *data = iks_user_data (prs);
	char *msg;
	int len, err;

	len = 91 + strlen (IKS_NS_CLIENT) + 6 + strlen (to) + 16 + 1;
	msg = iks_malloc (len);
	if (!msg) return IKS_NOMEM;
	sprintf (msg, "<?xml version='1.0'?>"
		"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='"
		"%s' to='%s' version='1.0'>", IKS_NS_CLIENT, to);
	err = xmpp_send_xml (prs, msg);
	iks_free (msg);
	if (err) return err;
	data->server = to;
	return IKS_OK;
}

int
xmpp_proses_data (iksparser *prs, const char *buf, size_t len)
{
	struct stream_data *data = iks_user_data (prs);
	int ret;
	
	if (data->logHook) data->logHook (data->user_data, buf, len, IKS_LOG_RECV);
	ret = iks_parse (prs, buf, len, 0);
	if (ret != IKS_OK) return ret;
	if (!data->trans) {
		/* stream hook called xmpp_disconnect */
		return IKS_NET_NOCONN;
	}
	return IKS_OK;
}

int
xmpp_is_secure(iksparser *prs)
{	
	struct stream_data *data = iks_user_data (prs);
	
	return data->flags & SF_SECURE;
	
}

int
xmpp_tls_done (iksparser *prs)
{
	int ret;
	struct stream_data *data = iks_user_data (prs);

	if (!data->trans) return IKS_NET_NOCONN;
	if (!data->trans->send) return IKS_NET_NOTSUPP;
	if (!data->trans->handshake) return IKS_NET_NOTSUPP;
		
	data->flags &= (~SF_TRY_SECURE);
	data->flags |= SF_SECURE;
	
	ret = xmpp_send_header(data->prs, data->server);
	if (ret) return ret;	
	return IKS_OK;
}



void
xmpp_set_basic_hook(iksparser *prs, iksFilterHook *iqHook, iksFilterHook *presHook, iksFilterHook *msgHook, iksFilterHook *s10nHook)
{
	struct stream_data *data = iks_user_data(prs);
		
	if (data->filter) iks_filter_delete(data->filter);
	data->filter = iks_filter_new();
	
	if (iqHook)
	iks_filter_add_rule(data->filter, iqHook, data->user_data,
		IKS_RULE_TYPE, IKS_PAK_IQ, IKS_RULE_DONE);
		
	if (presHook)
	iks_filter_add_rule(data->filter, presHook, data->user_data,
		IKS_RULE_TYPE, IKS_PAK_PRESENCE, IKS_RULE_DONE);
		
	if (msgHook)
	iks_filter_add_rule(data->filter, msgHook, data->user_data,
		IKS_RULE_TYPE, IKS_PAK_MESSAGE, IKS_RULE_DONE);
		
	if (s10nHook)
	iks_filter_add_rule(data->filter, s10nHook, data->user_data,
		IKS_RULE_TYPE, IKS_PAK_S10N, IKS_RULE_DONE);
}

iks *
iks_find_with_ns_attrib (iks *x, const char *childname, const char *childnamespace)
{
    iks *p, *a;
    for (p = iks_first_tag (x); p; p = iks_next_tag(p))
    {
        for (a = iks_attrib (p); a; a  = iks_next (a))
        {
            if (iks_type (a) != IKS_ATTRIBUTE)
                continue;
            if (strncmp (iks_name (a), "xmlns", 5))
                continue;
            if (strcmp (iks_cdata  (a), childnamespace))
                continue;
            if (!iks_name (a)[5] || iks_name (a)[5] == ':')
                return p;
        }
    }
    return NULL;
}
