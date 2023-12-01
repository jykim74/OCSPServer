#include <stdio.h>
#include <getopt.h>

#include "js_gen.h"
#include "js_process.h"
#include "js_http.h"
#include "js_db.h"
#include "js_cfg.h"
#include "ocsp_srv.h"
#include "js_util.h"
#include "js_log.h"
#include "js_pki.h"
#include "js_pkcs11.h"

BIN     g_binOcspCert = {0,0};
BIN     g_binOcspPri = {0,0};
JP11_CTX        *g_pP11CTX = NULL;

int     g_nConfigDB = 0;
int     g_nNeedSign = 0;
int     g_nMsgDump = 0;

int     g_nPort = 9010;
int     g_nSSLPort = 9110;
int     g_nLogLevel = JS_LOG_LEVEL_ERROR;

const char* g_dbPath = NULL;
static char g_sConfigPath[1024];

int g_nVerbose = 0;
JEnvList    *g_pEnvList = NULL;
SSL_CTX     *g_pSSLCTX = NULL;

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

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "RecvBin Len: %d", binReq.nLen );

    if( pMethInfo ) printf( "MethInfo : %s\n", pMethInfo );
    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING") == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/OCSP") == 0 )
    {
        ret = procVerify( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "procVerify fail(%d)\n", ret );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "procVerify fail(%d)", ret );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }

    JS_UTIL_createNameValList2("accept", "application/ocsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/ocsp-response");


    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to send message(%d)", ret );
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
    SSL             *pSSL = NULL;

    printf( "SSL Service start\n" );

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to accept SSL(%d)\n", ret );
        goto end;
    }

    ret = JS_HTTPS_recvBin( pSSL, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    if( pMethInfo ) printf( "MethInfo : %s\n", pMethInfo );
    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING") == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/OCSP") == 0 )
    {
        ret = procVerify( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "procVerify fail(%d)\n", ret );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }

    JS_UTIL_createNameValList2("accept", "application/ocsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/ocsp-response");


    ret = JS_HTTPS_sendBin( pSSL, pMethod, pRspHeaderList, &binRsp );
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
    if( pSSL ) JS_SSL_clear( pSSL );
    if(db) JS_DB_close( db );

    return ret;
}

int loginHSM_DB()
{
    return 0;
}

int loginHSM()
{
    int ret = 0;
    int nFlags = 0;


    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    int nSlotID = -1;
    const char *pLibPath = NULL;
    const char *pPIN = NULL;
    int nPINLen = 0;
    const char *value = NULL;

    pLibPath = JS_CFG_getValue( g_pEnvList, "OCSP_HSM_LIB_PATH" );
    if( pLibPath == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_HSM_LIB_PATH'\n" );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_HSM_SLOT_ID" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_HSM_SLOT_ID'\n" );
        exit(0);
    }

    nSlotID = atoi( value );

    pPIN = JS_CFG_getValue( g_pEnvList, "OCSP_HSM_PIN" );
    if( pPIN == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_HSM_PIN'\n" );
        exit(0);
    }

    nPINLen = atoi( pPIN );

    value = JS_CFG_getValue( g_pEnvList, "OCSP_HSM_KEY_ID" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_HSM_KEY_ID'\n" );
        exit( 0);
    }

    JS_BIN_decodeHex( value, &g_binOcspPri );

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, pLibPath );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to load library(%s:%d)\n", value, ret );
        exit(0);
    }

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run initialize(%d)\n", ret );
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, pPIN, nPINLen );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    printf( "HSM login ok\n" );

    return 0;
}

int readPriKeyDB( sqlite3 *db )
{
    int ret = 0;
    const char *value = NULL;
    JDB_KeyPair sKeyPair;

    memset( &sKeyPair, 0x00, sizeof(sKeyPair));

    value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_NUM" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'OCSP_SRV_PRIKEY_NUM'" );
        exit(0);
    }

    ret = JS_DB_getKeyPair(db, atoi(value), &sKeyPair );
    if( ret != 1 )
    {
        fprintf( stderr, "There is no key pair: %d\r\n", atoi(value));
        exit(0);
    }

    // 암호화 경우 복호화 필요함
    value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_ENC" );

    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        JS_BIN_decodeHex( sKeyPair.pPrivate, &g_binOcspPri );

        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }
    }
    else
    {
        BIN binEnc = {0,0};
        const char *pPasswd = NULL;

        pPasswd = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_PASSWD" );
        if( pPasswd == NULL )
        {
            fprintf( stderr, "You have to set 'OCSP_SRV_PRIKEY_PASSWD'\n" );
            exit(0);
        }

        JS_BIN_decodeHex( sKeyPair.pPrivate, &binEnc );

        ret = JS_PKI_decryptPrivateKey( pPasswd, &binEnc, NULL, &g_binOcspPri );
        if( ret != 0 )
        {
            fprintf( stderr, "invalid password (%d)\n", ret );
            exit(0);
        }

        JS_BIN_reset( &binEnc );
    }

    JS_DB_resetKeyPair( &sKeyPair );

    return 0;
}

int readPriKey()
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_ENC" );
    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'OCSP_SRV_PRIKEY_PATH'" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &g_binOcspPri );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }
    }
    else
    {
        BIN binEnc = {0,0};
        const char *pPasswd = NULL;

        pPasswd = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_PASSWD" );
        if( pPasswd == NULL )
        {
            fprintf( stderr, "You have to set 'OCSP_SRV_PRIKEY_PASSWD'\n" );
            exit(0);
        }

        value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_PRIKEY_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'OCSP_SRV_PRIKEY_PATH'" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &binEnc );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }

        ret = JS_PKI_decryptPrivateKey( pPasswd, &binEnc, NULL, &g_binOcspPri );
        if( ret != 0 )
        {
            fprintf( stderr, "invalid password (%d)\n", ret );
            exit(0);
        }
    }
    return 0;
}


int initServer( sqlite3 *db )
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) g_nLogLevel = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        ret = JS_LOG_open( value, "OCSP", JS_LOG_TYPE_DAILY );
    else
        ret = JS_LOG_open( "log", "OCSP", JS_LOG_TYPE_DAILY );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to open logfile:%d\n", ret );
        exit(0);
    }

    if( g_nConfigDB == 1 )
    {
        JDB_Cert sCert;
        memset( &sCert, 0x00, sizeof(sCert));

        value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_CERT_NUM" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'OCSP_SRV_CERT_NUM'\n" );
            exit(0);
        }

        JS_DB_getCert( db, atoi(value), &sCert );
        ret = JS_BIN_decodeHex( sCert.pCert, &g_binOcspCert );

        JS_DB_resetCert( &sCert );
    }
    else
    {
        value = JS_CFG_getValue( g_pEnvList, "OCSP_SRV_CERT_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'OCSP_SRV_CERT_PATH'\n" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &g_binOcspCert );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read ocsp srv cert(%s)\n", value );
            exit(0);
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_HSM_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        ret = loginHSM();
        if( ret != 0 )
        {
            fprintf( stderr, "fail to login HSM:%d\n", ret );
            exit(0);
        }
    }
    else
    {
        if( g_nConfigDB == 1 )
        {
            ret = readPriKeyDB( db );
        }
        else
        {
            ret = readPriKey();
        }

        if( ret != 0 )
        {
            fprintf( stderr, "fail to read private key:%d\n", ret );
            exit( 0 );
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_NEED_SIGN" );
    if( value )
    {
        if( strcasecmp( value, "yes" ) == 0 )
            g_nNeedSign = 1;
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_MSG_DUMP" );
    if( value )
    {
        if( strcasecmp( value, "yes" ) == 0 )
            g_nMsgDump = 1;
    }

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCA );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl ca cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLPri );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl private key(%s)\n", value );
        exit(0);
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &binSSLPri, &binSSLCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &binSSLCA );

    JS_BIN_reset( &binSSLCA );
    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );

    value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'DB_PATH'\n" );
        exit(0);
    }

    g_dbPath = JS_strdup( value );
    if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
    {
        fprintf( stderr, "The data file is no exist[%s]\n", g_dbPath );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "OCSP_PORT" );
    if( value ) g_nPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "OCSP_SSL_PORT" );
    if( value ) g_nSSLPort = atoi( value );

    printf( "OCSP Server Init OK [Port:%d SSL:%d]\n", g_nPort, g_nSSLPort );
    JS_LOG_write( JS_LOG_LEVEL_INFO, "OCSP Server Init OK [Port:%d SSL:%d]", g_nPort, g_nSSLPort );


    if( g_nNeedSign ) JS_LOG_write( JS_LOG_LEVEL_INFO, "Client have to sign for Request" );

    return 0;
}

void printUsage()
{
    printf( "JS OCSP Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config  : Set config file(%s)\n", g_sConfigPath );
    printf( "-d dbfile  : Use DB config(%s)\n", g_dbPath ? g_dbPath : "" );
    printf( "-h         : Print this message\n" );
}

int main( int argc, char *argv[] )
{
    int ret = 0;
    int nOpt = 0;
    sqlite3* db = NULL;

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

        case 'd' :
            g_dbPath = JS_strdup( optarg );
            g_nConfigDB = 1;
            break;
        }
    }

    if( g_nConfigDB == 1 )
    {
        JDB_ConfigList *pConfigList = NULL;

        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            fprintf( stderr, "The data file is no exist[%s]\n", g_dbPath );
            exit(0);
        }

        db = JS_DB_open( g_dbPath );
        if( db == NULL )
        {
            fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
            exit(0);
        }

        ret = JS_DB_getConfigListByKind( db, JS_GEN_KIND_OCSP_SRV, &pConfigList );

        ret = JS_CFG_readConfigFromDB( pConfigList, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }


        if( pConfigList ) JS_DB_resetConfigList( &pConfigList );
    }
    else
    {
        ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }
    }

    initServer( db );

    if( g_nConfigDB == 1 )
    {
        if( db ) JS_DB_close( db );
    }


    JS_THD_logInit( "./log", "ocsp", 2 );
    JS_THD_registerService( "JS_OCSP", NULL, g_nPort, 4, NULL, OCSP_Service );
    JS_THD_registerService( "JS_OCSP_SSL", NULL, g_nSSLPort, 4, NULL, OCSP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}

