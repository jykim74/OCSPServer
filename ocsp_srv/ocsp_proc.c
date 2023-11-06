#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "js_gen.h"
#include "ocsp_srv.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"
#include "js_log.h"
#include "sqlite3.h"
#include "js_pkcs11.h"

#include "js_db.h"

extern BIN  g_binOcspCert;
extern BIN  g_binOcspPri;
extern int g_nNeedSign;
extern int g_nMsgDump;
extern  JP11_CTX        *g_pP11CTX;

int msgDump( int nType, const BIN *pMsg )
{
    char        sSavePath[1024];

    if( pMsg == NULL || pMsg->nLen <= 0 ) return -1;

    if( JS_UTIL_isFolderExist( "dump" ) == 0 )
    {
#ifdef WIN32
        mkdir( "dump" );
#else
        mkdir( "dump", 0755 );
#endif
    }

    if( nType == JS_OCSP_MSG_REQ )
    {
        sprintf( sSavePath, "dump/ocsp_req_%d_%d.bin", time(NULL), getpid() );
    }
    else
    {
        sprintf( sSavePath, "dump/ocsp_rsp_%d_%d.bin", time(NULL), getpid());
    }


    return JS_BIN_fileWrite( pMsg, sSavePath );
}


int getCertStatus( sqlite3 *db, JCertIDInfo *pIDInfo, JCertStatusInfo *pStatusInfo )
{
    int     ret = 0;
    JDB_Cert        sIssuer;
    JDB_Cert        sCert;
    JDB_Signer      sSigner;
    JDB_Revoked     sRevoked;

    int             nStatus = JS_OCSP_STATUS_GOOD;
    int             nReason = 0;
    int             nRevokedTime = 0;

    memset( &sIssuer, 0x00, sizeof(sIssuer));
    memset( &sCert, 0x00, sizeof(sCert));
    memset( &sSigner, 0x00, sizeof(sSigner));
    memset( &sRevoked, 0x00, sizeof(sRevoked));

    ret = JS_DB_getCertByKeyHash( db, pIDInfo->pKeyHash, &sIssuer );
    if( ret != 1 )
    {
        fprintf( stderr, "fail to get Issuer by KeyHash(%s)\n", pIDInfo->pKeyHash );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to get Issuer by KeyHash(%s)", pIDInfo->pKeyHash );
        nStatus = JS_OCSP_STATUS_UNKNOWN;
        goto end;
    }

    ret = JS_DB_getCertBySerial( db, pIDInfo->pSerial, &sCert );
    if( ret != 1 )
    {
        fprintf( stderr, "fail to get cert by serial(%s)\n", pIDInfo->pSerial );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to get cert by serial(%s)", pIDInfo->pSerial );
        nStatus = JS_OCSP_STATUS_UNKNOWN;
        goto end;
    }

    ret = JS_DB_getRevokedByCertNum( db, sCert.nNum, &sRevoked );

    if( ret == 1 )
    {
        fprintf( stderr, "Cert is revoked(Num:%d)\n", sCert.nNum );
        JS_LOG_write( JS_LOG_LEVEL_INFO, "Cert is revoked(Num:%d)", sCert.nNum );
        nStatus = JS_OCSP_STATUS_REVOKED;
        nReason = sRevoked.nReason;
        nRevokedTime = sRevoked.nRevokedDate;

        JS_LOG_write( JS_LOG_LEVEL_INFO,
                     "The cert is revoked[Num:%d Reason:%d RevokedTime:%d]",
                sCert.nNum,
                nReason,
                nRevokedTime );
    }
    else
    {
        printf( "The cert is good[Num:%d]\n", sCert.nNum );
        JS_LOG_write( JS_LOG_LEVEL_INFO, "The cert is good[Num:%d]", sCert.nNum );
    }

    JS_addAudit( db, JS_GEN_KIND_OCSP_SRV, JS_GEN_OP_CHECK_OCSP, NULL );

end :
    JS_OCSP_setCertStatusInfo( pStatusInfo, nStatus, nReason, nRevokedTime, NULL );

    JS_DB_resetCert( &sIssuer );
    JS_DB_resetCert( &sCert );
    JS_DB_resetSigner( &sSigner );
    JS_DB_resetRevoked( &sRevoked );

    return 0;
}

int procVerify( sqlite3 *db, const BIN *pReq, BIN *pRsp )
{
    int     ret = 0;

    JCertIDInfo    sIDInfo;
    JCertStatusInfo sStatusInfo;

    char *pSignerName = NULL;
    char *pDNHash = NULL;
    JDB_Signer  sDBSigner;
    BIN binSigner = {0,0};

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));   
    memset( &sDBSigner, 0x00, sizeof(sDBSigner));

    if( g_nNeedSign )
    {
        ret = JS_OCSP_getReqSignerName( pReq, &pSignerName, &pDNHash );
        if( ret != 0 )
        {
            fprintf( stderr, "Request need to sign(%d)\n", ret );
            ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_SIGREQUIRED, pRsp );
            goto end;
        }

        printf( "Request is Signed( SignerName : %s)\n", pSignerName );
        ret = JS_DB_getSignerByDNHash( db, JS_DB_SIGNER_TYPE_OCSP, pDNHash, &sDBSigner );
        if( ret != 1 )
        {
            fprintf( stderr, "There is no signer cert[%s]\n", pSignerName );
            ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_UNAUTHORIZED, pRsp );
            goto end;
        }

        if( sDBSigner.nStatus != 1 )
        {
            fprintf( stderr, "The signer is not valid[%d]\n", sDBSigner.nStatus );
            ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_UNAUTHORIZED, pRsp );
            goto end;
        }

        JS_BIN_decodeHex( sDBSigner.pCert, &binSigner );
    }

    if( g_nMsgDump ) msgDump( JS_OCSP_MSG_REQ, pReq );

    ret = JS_OCSP_decodeRequest( pReq, &binSigner, &sIDInfo );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode request(%d)\n", ret );
        ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, pRsp );
        goto end;
    }

    ret = getCertStatus( db, &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to get cert status(%d)\n", ret );
        ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_INTERNALERROR, pRsp );
        goto end;
    }

    if( g_pP11CTX )
        ret = JS_OCSP_encodeResponseByP11( pReq, &g_binOcspCert, &g_binOcspPri, g_pP11CTX, "SHA1", &sIDInfo, &sStatusInfo, pRsp );
    else
        ret = JS_OCSP_encodeResponse( pReq, &g_binOcspCert, &g_binOcspPri, "SHA1", &sIDInfo, &sStatusInfo, pRsp );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode OCSP response message(%d)\n", ret );
        ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_INTERNALERROR, pRsp );
        goto end;
    }

    if( g_nMsgDump ) msgDump( JS_OCSP_MSG_RSP, pRsp );
end :

    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
    if( pSignerName ) JS_free( pSignerName );
    if( pDNHash ) JS_free( pDNHash );
    JS_BIN_reset( &binSigner );
    JS_DB_resetSigner( &sDBSigner );

    return ret;
}
