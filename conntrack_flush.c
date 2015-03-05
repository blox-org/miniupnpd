#include "conntrack_flush.h"

int conntrack_flush()
{
	int family = AF_INET;
	struct nfct_handle *cth ;
	cth = nfct_open(CONNTRACK, 0);
	if (!cth) {
		perror("conntrack_flush: Can't open handler");
		return -1;
	}
	int res = nfct_query(cth, NFCT_Q_FLUSH, &family);
	nfct_close(cth);
	return res ;
}
