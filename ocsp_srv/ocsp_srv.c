#include <stdio.h>

#include "js_process.h"
#include "js_http.h"

#include "ocsp_srv.h"

int OCSP_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    JSNameValList   *pHeaderList = NULL;
    JSNameValList   *pRspHeaderList = NULL;
    char            *pBody = NULL;
    int             nStatus = -1;
    BIN             binReq = {0,0};
    BIN             binRsp = {0,0};
    const char      *pMethod = "POST";

    printf( "Service start\n" );

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &nStatus, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        goto end;
    }

    if( nStatus == 200 )
    {
        ret = procVerify( &binReq, &binRsp );
    }

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pMethod, pRspHeaderList, &binRsp );

end :
    if( pBody ) JS_free( pBody );
    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    return ret;
}

int OCSP_SSL_Service( JThreadInfo *pThInfo )
{
    printf( "Service SSL start\n" );

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
    JS_THD_logInit( "./log", "ocsp", 2 );
    JS_THD_registerService( "JS_OCSP", NULL, 9010, 4, NULL, OCSP_Service );
    JS_THD_registerService( "JS_OCSP_SSL", NULL, 9110, 4, NULL, OCSP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
#endif
