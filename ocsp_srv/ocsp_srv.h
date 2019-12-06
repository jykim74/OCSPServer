#ifndef OCSP_SRV_H
#define OCSP_SRV_H

#include "js_bin.h"
#include "sqlite3.h"

int procVerify( sqlite3 *db, const BIN *pReq, int nType, const char *pPath, BIN *pRsp );

#endif // OCSP_SRV_H
