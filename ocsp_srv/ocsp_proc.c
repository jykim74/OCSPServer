#include "ocsp_srv.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"

#include "sqlite3.h"

#include "js_db.h"

extern BIN  g_binOcspCert;
extern BIN  g_binOcspPri;

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
    if( ret != 0 )
    {
        nStatus = JS_OCSP_STATUS_UNKNOWN;
        goto end;
    }

    ret = JS_DB_getCertBySerial( db, pIDInfo->pSerial, &sCert );
    if( ret != 0 )
    {
        nStatus = JS_OCSP_STATUS_UNKNOWN;
        goto end;
    }

    ret = JS_DB_getRevokedByCertNum( db, sCert.nNum, &sRevoked );

    if( ret == 0 )
    {
        nStatus = JS_OCSP_STATUS_REVOKED;
        nReason = sRevoked.nReason;
        nRevokedTime = sRevoked.nRevokedDate;
    }

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


//    ret = JS_OCSP_decodeRequest( pReq, &g_binOcspCert, &sIDInfo );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode OCSP request message(%d)\n", ret );
        goto end;
    }

    ret = JS_OCSP_getReqSignerName( pReq, &pSignerName, &pDNHash );
    if( ret == 0 )
    {
        JS_DB_getSignerByDNHash( db, pDNHash, &sDBSigner );
        JS_BIN_decodeHex( sDBSigner.pCert, &binSigner );
    }

    ret = JS_OCSP_decodeRequest( pReq, &binSigner, &sIDInfo );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode request(%d)\n", ret );
        goto end;
    }

    ret = getCertStatus( db, &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to get cert status(%d)\n", ret );
        goto end;
    }

    ret = JS_OCSP_encodeResponse( pReq, &g_binOcspCert, &g_binOcspPri, "SHA1", &sIDInfo, &sStatusInfo, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode OCSP response message(%d)\n", ret );
        goto end;
    }

end :
    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
    if( pSignerName ) JS_free( pSignerName );
    if( pDNHash ) JS_free( pDNHash );
    JS_BIN_reset( &binSigner );
    JS_DB_resetSigner( &sDBSigner );

    return ret;
}
