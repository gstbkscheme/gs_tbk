#include "gs_tbk.h"

GS_TBK::GS_TBK(PFC *p)
{
    pfc=p;
    pfc->random(g);
    pfc->random(g_);
    gt=pfc->pairing(g_,g);

}
GS_TBK::~GS_TBK()
{

}
int GS_TBK::GKeyGen(GS_GPK &gpk,GS_GSK &gsk)
{
    int ret = 0;
    //choose gsk and compute gpk
    pfc->random(gsk.a);
    gpk.A_=pfc->mult(g_,gsk.a);
    pfc->random(gsk.b);
    gpk.B_=pfc->mult(g_,gsk.b);
    pfc->random(gsk.c);
    gpk.C_=pfc->mult(g_,gsk.c);

    for(int i=0;i<TIME_PERIODS_NUM;i++)
    {
        pfc->random(gsk.x[i]);
        gpk.X_[i]=pfc->mult(g_,gsk.x[i]);
        pfc->random(gsk.y[i]);
        gpk.Y_[i]=pfc->mult(g_,gsk.y[i]);
    }
    Count=0;
    return ret;
}
int GS_TBK::Join_REQ(GS_GPK &gpk, GS_SIGNING_KEY &sign_key, GS_JOIN_REQ &join_req)
{
    int ret = 0;
    //choose id
    join_req.id=sign_key.id=Count++;
    //choose usk
    pfc->random(sign_key.usk);
    //compute T1
    pfc->start_hash();
    pfc->add_to_hash(sign_key.id);
    Big t=pfc->finish_hash_to_group();
    join_req.upk.T1 = sign_key.upk.T1=pfc->mult(g,t);
    //compute T2,T3
    join_req.upk.T2 = sign_key.upk.T2=pfc->mult(sign_key.upk.T1,sign_key.usk);
    join_req.upk.T3 = sign_key.upk.T3=pfc->mult(sign_key.upk.T2,sign_key.usk);
    //compute utk
    join_req.utk = sign_key.utk=pfc->mult(g_,sign_key.usk);
    //compute Pi1
    G1 R1,R2;
    G2 R3;
    Big r;
    pfc->random(r);
    R1=pfc->mult(sign_key.upk.T1,r);
    R2=pfc->mult(sign_key.upk.T2,r);
    R3=pfc->mult(g_,r);
    pfc->start_hash();
    pfc->add_to_hash(sign_key.upk.T1);
    pfc->add_to_hash(sign_key.upk.T2);
    pfc->add_to_hash(sign_key.upk.T3);
    pfc->add_to_hash(sign_key.utk);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    join_req.pi_1.c=pfc->finish_hash_to_aes_key();
    t=pfc->Zpmulti(sign_key.usk,join_req.pi_1.c);
    join_req.pi_1.s=pfc->Zpsub(r,t);
    return ret;
}
int GS_TBK::Issue(GS_GPK &gpk,GS_GSK &gsk,GS_JOIN_REQ &join_req,GS_JOIN_RET &join_ret)
{
    int ret = 0;
    //verify pi1
    G1 R1,R2;
    G2 R3;
    R1=pfc->mult(join_req.upk.T1,join_req.pi_1.s)+pfc->mult(join_req.upk.T2,join_req.pi_1.c);
    R2=pfc->mult(join_req.upk.T2,join_req.pi_1.s)+pfc->mult(join_req.upk.T3,join_req.pi_1.c);
    R3=pfc->mult(g_,join_req.pi_1.s)+pfc->mult(join_req.utk,join_req.pi_1.c);
    pfc->start_hash();
    pfc->add_to_hash(join_req.upk.T1);
    pfc->add_to_hash(join_req.upk.T2);
    pfc->add_to_hash(join_req.upk.T3);
    pfc->add_to_hash(join_req.utk);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    Big c=pfc->finish_hash_to_aes_key();
    if(c!=join_req.pi_1.c) return -1;
    //compute tag-based sig

    for(int i=0;i<TIME_PERIODS_NUM;i++)
    {
        Big a=pfc->Zpadd(gsk.a,gsk.x[i]);
        Big b=pfc->Zpadd(gsk.b,gsk.y[i]);
        join_ret.sigma_t[i]=pfc->mult(join_req.upk.T1,a)+pfc->mult(join_req.upk.T2,b)+pfc->mult(join_req.upk.T3,gsk.c);
    }
    //store user reg info
    join_ret.id=join_req.id;
    join_ret.utk=join_req.utk;
    join_ret.upk.T1=join_req.upk.T1;
    join_ret.upk.T2=join_req.upk.T2;
    join_ret.upk.T3=join_req.upk.T3;
    list_reg.push_front(join_ret);
    return ret;
}
int GS_TBK::Join_REC(GS_GPK &gpk,GS_SIGNING_KEY &sign_key, GS_JOIN_RET &join_ret)
{
    int ret = 0;
    for(int i=0;i<TIME_PERIODS_NUM;i++)
    {
        GT E1,E2,E3,E4;
        E1=pfc->pairing(g_,join_ret.sigma_t[i]);
        E2=pfc->pairing(gpk.A_+gpk.X_[i],sign_key.upk.T1);
        E3=pfc->pairing(gpk.B_+gpk.Y_[i],sign_key.upk.T2);
        E4=pfc->pairing(gpk.C_,sign_key.upk.T3);
        E2=E2*E3*E4;
        if(E1!=E2) return -(i+1);
        sign_key.sigma_t[i]=join_ret.sigma_t[i];
    }
    return ret;
}
int GS_TBK::Sign(GS_GPK &gpk, GS_SIGNING_KEY &sign_key, int &tau, GS_GROUP_SIG &gsign)
{
    int ret = 0;
    if(tau>=TIME_PERIODS_NUM) return -1;
    gsign.tau=tau;
    //choose nonce
    pfc->random(gsign.nounce);
    //helper device
    Big r;
    pfc->random(r);
    gsign.upk.T1=pfc->mult(sign_key.upk.T1,r);
    gsign.upk.T2=pfc->mult(sign_key.upk.T2,r);
    gsign.upk.T3=pfc->mult(sign_key.upk.T3,r);
    gsign.sigma=pfc->mult(sign_key.sigma_t[tau],r);

    //core device
    Big k;
    pfc->random(k);
    G1 R1,R2;
    R1=pfc->mult(gsign.upk.T1,k);
    R2=pfc->mult(gsign.upk.T2,k);
    pfc->start_hash();
    pfc->add_to_hash(gsign.upk.T1);
    pfc->add_to_hash(gsign.upk.T2);
    pfc->add_to_hash(gsign.upk.T3);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(gsign.nounce);
    gsign.c=pfc->finish_hash_to_aes_key();
    r=pfc->Zpmulti(sign_key.usk,gsign.c);
    gsign.s=pfc->Zpsub(k,r);
    return ret;
}
int GS_TBK::Revoke(GS_GPK &gpk, GS_GSK &gsk, Big &id, int &tau, GS_USER_REV &R_tau)
{
    int ret = 0;
    if(tau>=TIME_PERIODS_NUM) return -1;
    list <GS_JOIN_RET>::iterator it;
    for(it = list_reg.begin();it!=list_reg.end();it++)
    {
        if(it->id==id)
        {
            R_tau.R_tau=pfc->mult(g_,gsk.x[tau])+pfc->mult(it->utk,gsk.y[tau]);
            list_rev.push_front(R_tau);
        }
    }
    return ret;
}
int GS_TBK::Verify(GS_GPK &gpk,GS_GROUP_SIG &gsign)
{
    int ret = 0;
    if(gsign.tau>=TIME_PERIODS_NUM) return -1;
    //signature verify
    G1 R1,R2;
    R1=pfc->mult(gsign.upk.T1,gsign.s)+pfc->mult(gsign.upk.T2,gsign.c);
    R2=pfc->mult(gsign.upk.T2,gsign.s)+pfc->mult(gsign.upk.T3,gsign.c);
    pfc->start_hash();
    pfc->add_to_hash(gsign.upk.T1);
    pfc->add_to_hash(gsign.upk.T2);
    pfc->add_to_hash(gsign.upk.T3);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(gsign.nounce);
    Big c=pfc->finish_hash_to_aes_key();
    if(c!=gsign.c) return -2;
    GT E1,E2,E3,E4;

    E1=pfc->pairing(g_,gsign.sigma);
    E2=pfc->pairing(gpk.A_+gpk.X_[gsign.tau],gsign.upk.T1);
    E3=pfc->pairing(gpk.B_+gpk.Y_[gsign.tau],gsign.upk.T2);
    E4=pfc->pairing(gpk.C_,gsign.upk.T3);
    E2=E2*E3*E4;
    if(E1!=E2) return -3;
    //revocation verify
    list <GS_USER_REV>::iterator it;
    for(it = list_rev.begin();it!=list_rev.end();it++)
    {
        E1=pfc->pairing(gpk.X_[gsign.tau],gsign.upk.T1);
        E2=pfc->pairing(gpk.Y_[gsign.tau],gsign.upk.T2);
        E3=pfc->pairing(it->R_tau,gsign.upk.T1);
        if(E3==E1*E2) return -3;
    }

    return ret;
}
int GS_TBK::trace(GS_GROUP_SIG &gsign,Big &tid)
{
    list <GS_JOIN_RET>::iterator it;
    for(it = list_reg.begin();it!=list_reg.end();it++)
    {
        GT E1,E2;
        E1 = pfc->pairing(it->utk,gsign.upk.T1);
        E2 = pfc->pairing(g_,gsign.upk.T2);
        if(E1 != E2) continue;
        E1 = pfc->pairing(it->utk,gsign.upk.T2);
        E2 = pfc->pairing(g_,gsign.upk.T3);
        if(E1 == E2)
        {
            tid=it->id;
            return 0;
        }

    }
    return -1;
}
