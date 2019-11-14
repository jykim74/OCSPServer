#include <stdio.h>

#include "js_process.h"
#include "ocsp_srv.h"

int OCSPService( JThreadInfo *pThInfo )
{
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

    JS_PRC_register( "JS_OCSP", NULL, 9010, 4, NULL, OCSPService );

    JS_PRC_start();

    return 0;
}

#else
int main()
{
    return 0;
}
#endif
