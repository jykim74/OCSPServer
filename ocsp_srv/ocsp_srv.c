#include <stdio.h>

#include "js_process.h"
#include "js_http.h"
#include "js_db.h"
#include "ocsp_srv.h"

BIN     g_binOcspCert = {0,0};
BIN     g_binOcspPri = {0,0};

const char* g_dbPath = "/Users/jykim/work/CAMan/ca.db";

int OCSP_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    char            *pBody = NULL;
    char            *pMethInfo = NULL;
    BIN             binReq = {0,0};
    BIN             binRsp = {0,0};
    const char      *pMethod = "POST";
    int             nType = -1;
    char            *pPath = NULL;

    printf( "Service start\n" );

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    if( pMethInfo ) printf( "MethInfo : %s\n", pMethInfo );
    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING") == 0 )
    {

    }
    else if( strcasecmp( pPath, "OCSP") == 0 )
    {
        ret = procVerify( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "procVerify fail(%d)\n", ret );
            goto end;
        }
    }

    JS_UTIL_createNameValList2("accept", "application/ocsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/ocsp-response");

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }

end :
    if( pBody ) JS_free( pBody );
    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    if( pMethInfo ) JS_free( pMethInfo );
    if( pPath ) JS_free( pPath );
    if(db) JS_DB_close( db );

    return ret;
}

int OCSP_SSL_Service( JThreadInfo *pThInfo )
{
    printf( "Service SSL start\n" );

    return 0;
}

int initServer()
{
    const char *pOCSPCertPath = "/Users/jykim/work/PKITester/data/tsp_server_cert.der";
    const char *pOCSPPriPath = "/Users/jykim/work/PKITester/data/tsp_server_prikey.der";

    JS_BIN_fileRead( pOCSPCertPath, &g_binOcspCert );
    JS_BIN_fileRead( pOCSPPriPath, &g_binOcspPri );

    return 0;
}

#if 0
int main()
{
    JProcInit   sProcInit;

    memset( &sProcInit, 0x00, sizeof(sProcInit));

    sProcInit.nCreateNum = 2;
    JS_PRC_logInit( "./log", "ocsp", 3 );
    JS_PRC_initRegister( &sProcInit );

    JS_PRC_register( "JS_OCSP", NULL, 9010, 4, NULL, OCSP_Service );
    JS_PRC_register( "JS_OCSP_SSL", NULL, 9110, 4, NULL, OCSP_SSL_Service );

    JS_PRC_start();

    return 0;
}

#else
int main()
{
    initServer();

    JS_THD_logInit( "./log", "ocsp", 2 );
    JS_THD_registerService( "JS_OCSP", NULL, 9010, 4, NULL, OCSP_Service );
    JS_THD_registerService( "JS_OCSP_SSL", NULL, 9110, 4, NULL, OCSP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
#endif
