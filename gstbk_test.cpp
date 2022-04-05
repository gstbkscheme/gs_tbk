#include"gs_tbk.h"
#include "pairing_3.h"
#include <ctime>
#include <time.h>
#define TEST_TIME 10

int correct_test()
{
    PFC pfc(AES_SECURITY);

    GS_TBK gs_tbk(&pfc);
    int ret =0;
    //1 SetUP
    GS_GPK gpk;
    GS_GSK gsk;
    ret = gs_tbk.GKeyGen(gpk,gsk);
    if(ret != 0)
    {
        printf("gs_tbk.GKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.GKeyGen pass\n");
    GS_SIGNING_KEY sign_key;
    GS_JOIN_REQ join_req;
    //2
    ret = gs_tbk.Join_REQ(gpk, sign_key, join_req);//core
    if(ret != 0)
    {
        printf("gs_tbk.Join_REQ Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.Join_REQ pass\n");
    //3
    GS_JOIN_RET join_ret;
    ret = gs_tbk.Issue(gpk,gsk,join_req,join_ret);
    if(ret != 0)
    {
        printf("gs_tbk.Issue Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.Issue pass\n");
    //4
    ret = gs_tbk.Join_REC(gpk, sign_key, join_ret);//helper
    if(ret != 0)
    {
        printf("gs_tbk.Join_REC Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.Join_REC pass\n");

    //5
    int tau=1;
    GS_GROUP_SIG gsign;
    ret = gs_tbk.Sign(gpk, sign_key, tau, gsign);
    if(ret != 0)
    {
        printf("gs_tbk.Sign Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.Sign pass\n");

    //6
    Big id=sign_key.id;
    GS_USER_REV R_tau;
#if 0
    ret = gs_tbk.Revoke(gpk,gsk,id,tau, R_tau);
    if(ret != 0)
    {
        printf("gs_tbk.Revoke Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.Revoke pass\n");
#endif
    //7
    ret = gs_tbk.Verify(gpk,gsign);
    if(ret != 0)
    {
        printf("gs_tbk.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.Verify pass\n");

    //8
    Big tid;
    ret = gs_tbk.trace(gsign, tid);
    if(ret != 0)
    {
        printf("gs_tbk.trace Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("gs_tbk.trace pass\n");
    if(tid != id)
        printf("gs_tbk.trace fail\n");

    return ret;
}
int speed_test()
{
    int k;
    clock_t start,finish;
    double sum;
    PFC pfc(AES_SECURITY);
    GS_TBK gs_tbk(&pfc);
    int ret =0;

    //1. basic
    //G1
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        G1 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G1 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_1 ret : %d time =%f sec\n",ret,sum);

    //G2
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        G2 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G2 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_2 ret : %d time =%f sec\n",ret,sum);

    //e
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        G1 G;
        G2 H;
        pfc.random(G);
        pfc.random(H);
        GT T=pfc.pairing(H,G);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_p ret : %d time =%f sec\n",ret,sum);


    //1 SetUP
    GS_GPK gpk;
    GS_GSK gsk;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = gs_tbk.GKeyGen(gpk,gsk);
        if(ret != 0)
        {
            printf("gs_tbk.GKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("gs_tbk.GKeyGen ret : %d time =%f sec\n",ret,sum);
    GS_SIGNING_KEY sign_key;
    GS_JOIN_REQ join_req;
    //2
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = gs_tbk.Join_REQ(gpk, sign_key, join_req);//core
        if(ret != 0)
        {
            printf("gs_tbk.Join_REQ Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("gs_tbk.Join_REQ ret : %d time =%f sec\n",ret,sum);
    //3
    GS_JOIN_RET join_ret;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = gs_tbk.Issue(gpk,gsk,join_req,join_ret);
        if(ret != 0)
        {
            printf("gs_tbk.Issue Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("gs_tbk.Issue ret : %d time =%f sec\n",ret,sum);
    //4
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = gs_tbk.Join_REC(gpk, sign_key, join_ret);//helper
        if(ret != 0)
        {
            printf("gs_tbk.Join_REC Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("gs_tbk.Join_REC ret : %d time =%f sec\n",ret,sum);

    //5
    int tau=1;
    GS_GROUP_SIG gsign;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = gs_tbk.Sign(gpk, sign_key, tau, gsign);
        if(ret != 0)
        {
            printf("gs_tbk.Sign Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("gs_tbk.Sign ret : %d time =%f sec\n",ret,sum);


    //7
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = gs_tbk.Verify(gpk,gsign);
        if(ret != 0)
        {
            printf("gs_tbk.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("gs_tbk.Verify ret : %d time =%f sec\n",ret,sum);
    return ret;
}

int main()
{

    int ret=0;

    ret =correct_test();
    if(ret ==0)
    {
        printf("gs_tbk is correct!\n");
    }

    ret =speed_test();
    if(ret ==0)
    {
        printf("speed test of gs_tbk is completed!\n");
    }

    return ret;
}
