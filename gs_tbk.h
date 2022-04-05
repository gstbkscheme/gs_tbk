#ifndef GS_TBK_H
#define GS_TBK_H
#include"pairing_3.h"
#include "zzn.h"
#include <stdlib.h>
#include <stdio.h>
#include <list>
typedef unsigned char u8;
typedef unsigned int u32;

#define AES_SECURITY 128 //lamda
#define TIME_PERIODS_NUM 80 //n

struct GS_GPK
{
    G2 A_,B_,C_;
    G2 X_[TIME_PERIODS_NUM],Y_[TIME_PERIODS_NUM];
};
struct GS_GSK
{
    Big a,b,c;
    Big x[TIME_PERIODS_NUM],y[TIME_PERIODS_NUM];
};
struct GS_UPK
{
    G1 T1,T2,T3;
};
struct GS_SIGNING_KEY
{
    Big id;
    Big usk;
    GS_UPK upk;
    G2 utk;
    G1 sigma_t[TIME_PERIODS_NUM];
};
struct GS_Pi_1
{
    Big c,s;
};
struct GS_JOIN_REQ
{
    Big id;
    GS_UPK upk;
    G2 utk;
    GS_Pi_1 pi_1;
};
struct GS_JOIN_RET
{
   Big id;
   GS_UPK upk;
   G2 utk;
   G1 sigma_t[TIME_PERIODS_NUM];
};
struct GS_GROUP_SIG
{
    int tau;
    GS_UPK upk;
    G1 sigma;
    Big c,s;
    Big nounce;
};

struct GS_USER_REV
{
    G2 R_tau;
};
typedef list<GS_JOIN_RET> LIST_REG;
typedef list<GS_USER_REV> LIST_REV;

class GS_TBK
{
private:
    PFC *pfc;
    G1 g;
    G2 g_;
    GT gt;
    LIST_REG list_reg;
    LIST_REV list_rev;
    int Count;
public:

    GS_TBK(PFC *p);
    ~GS_TBK();
    int GKeyGen(GS_GPK &gpk,GS_GSK &gsk);
    int Join_REQ(GS_GPK &gpk, GS_SIGNING_KEY &sign_key, GS_JOIN_REQ &join_req);//core
    int Issue(GS_GPK &gpk,GS_GSK &gsk,GS_JOIN_REQ &join_req,GS_JOIN_RET &join_ret);
    int Join_REC(GS_GPK &gpk, GS_SIGNING_KEY &sign_key, GS_JOIN_RET &join_ret);//helper
    int Sign(GS_GPK &gpk, GS_SIGNING_KEY &sign_key, int &tau, GS_GROUP_SIG &gsign);
    int Revoke(GS_GPK &gpk,GS_GSK &gsk,Big &id,int &tau, GS_USER_REV &R_tau);
    int Verify(GS_GPK &gpk,GS_GROUP_SIG &gsign);
    int trace(GS_GROUP_SIG &gsign, Big &tid);
};

#endif // GS_TBK_H
