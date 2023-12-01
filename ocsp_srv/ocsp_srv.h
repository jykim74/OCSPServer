#ifndef OCSP_SRV_H
#define OCSP_SRV_H

#include "js_bin.h"
#include "sqlite3.h"

#define     JS_OCSP_SRV_VERSION          "0.9.2"
#define     JS_OCSP_MSG_REQ             0
#define     JS_OCSP_MSG_RSP             1

int msgDump( int nType, const BIN *pMsg );
int procVerify( sqlite3 *db, const BIN *pReq, BIN *pRsp );

#endif // OCSP_SRV_H
