#include "ocsp_srv.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"

extern BIN  g_binOcspCert;
extern BIN  g_binOcspPri;

int procVerify( const BIN *pReq, BIN *pRsp )
{
    int     ret = 0;
    JSCertIDInfo    sIDInfo;

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));

    ret = JS_OCSP_decodeRequest( pReq, &g_binOcspCert, &sIDInfo );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode OCSP request message(%d)\n", ret );
        goto end;
    }

    sIDInfo.nStatus = JS_OCSP_STATUS_REVOKED;
    sIDInfo.nReason = 1;
    sIDInfo.nRevokedTime = time(NULL);

    ret = JS_OCSP_encodeResponse( pReq, &g_binOcspCert, &g_binOcspPri, "SHA1", &sIDInfo, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode OCSP response message(%d)\n", ret );
        goto end;
    }

end :
    JS_OCSP_resetCertIDInfo( &sIDInfo );

    return ret;
}
