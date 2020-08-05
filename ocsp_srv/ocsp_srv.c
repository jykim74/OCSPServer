#include <stdio.h>
#include <getopt.h>

#include "js_process.h"
#include "js_http.h"
#include "js_db.h"
#include "js_cfg.h"
#include "ocsp_srv.h"

BIN     g_binOcspCert = {0,0};
BIN     g_binOcspPri = {0,0};

const char* g_dbPath = NULL;
static char g_sConfigPath[1024];
int g_nVerbose = 0;
JEnvList    *g_pEnvList = NULL;

static char g_sBuildInfo[1024];

const char *getBuildInfo()
{
    sprintf( g_sBuildInfo, "Version: %s Build Date : %s %s",
             JS_OCSP_SRV_VERSION, __DATE__, __TIME__ );

    return g_sBuildInfo;
}

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
    const char      *pMethod = NULL;
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
    else if( strcasecmp( pPath, "/OCSP") == 0 )
    {
        JS_BIN_fileWrite( &binReq, "D:/work/ber/ocsp_req.der" );
        ret = procVerify( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "procVerify fail(%d)\n", ret );
            goto end;
        }

        JS_BIN_fileWrite( &binRsp, "D:/work/ber/ocsp_rsp.der" );
    }

    JS_UTIL_createNameValList2("accept", "application/ocsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/ocsp-response");

    pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
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
    int ret = 0;
    const char *value = NULL;

    ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_SRV_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileRead( value, &g_binOcspCert );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read ocsp srv cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_SRV_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileRead( value, &g_binOcspPri );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read ocsp private key(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'DB_PATH'\n" );
        exit(0);
    }

    g_dbPath = JS_strdup( value );

    printf( "OCSP Server Init OK\n" );

    return 0;
}

void printUsage()
{
    printf( "JS OCSP Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config : set config file(%s)\n", g_sConfigPath );
    printf( "-h         : Print this message\n" );
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
int main( int argc, char *argv[] )
{
    int nOpt = 0;

    sprintf( g_sConfigPath, "%s", "../ocsp_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:vh")) != -1 )
    {
        switch( nOpt ) {
        case 'h':
            printUsage();
            return 0;

        case 'v':
            g_nVerbose = 1;
            break;

        case 'c':
            sprintf( g_sConfigPath, "%s", optarg );
            break;
        }
    }

    initServer();

    JS_THD_logInit( "./log", "ocsp", 2 );
    JS_THD_registerService( "JS_OCSP", NULL, 9010, 4, NULL, OCSP_Service );
    JS_THD_registerService( "JS_OCSP_SSL", NULL, 9110, 4, NULL, OCSP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
#endif
