#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <cbmpc/api/curve.h>
#include <cbmpc/api/ecdsa_2p.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>
using coinbase::buf_t;using coinbase::error_t;using coinbase::mem_t;using coinbase::api::curve_id;using coinbase::api::data_transport_i;using coinbase::api::party_2p_t;using coinbase::api::party_idx_t;
namespace{
struct ch_t{std::mutex m;std::condition_variable cv;std::deque<buf_t>q;};
struct net_t{ch_t ch[2][2];std::mutex sm;bool cancelled=false,mutate=false;int dir=-1,target=-1,kind=-1;int counts[2]={0,0};void cancel(){{std::lock_guard<std::mutex>l(sm);cancelled=true;}for(int i=0;i<2;i++)for(int j=0;j<2;j++)ch[i][j].cv.notify_all();}bool stopped(){std::lock_guard<std::mutex>l(sm);return cancelled;}};
buf_t mutate_payload(mem_t msg,int kind){buf_t o(msg);if(o.empty())return o;switch(kind){case 0:o.resize(std::max(1,o.size()-1));break;case 1:o.resize(std::max(1,o.size()/2));break;case 2:o[0]^=0xff;break;case 3:o[0]=0xff;break;case 4:{int old=o.size();o.resize(old+64);for(int i=old;i<o.size();i++)o[i]=(uint8_t)(0x5a^i);break;}case 5:o.bzero();break;case 6:o.resize(1);o[0]=0xff;break;case 7:{int lim=std::min(o.size(),24);for(int i=0;i<lim;i++)o[i]^=(uint8_t)(0x80u>>(i%8));break;}case 8:{int st=std::max(0,o.size()-32);for(int i=st;i<o.size();i++)o[i]^=0xff;break;}}return o;}
class tr_t final:public data_transport_i{int s_;std::shared_ptr<net_t>n_;public:tr_t(int s,std::shared_ptr<net_t>n):s_(s),n_(std::move(n)){}error_t send(party_idx_t r,mem_t m)override{if(r<0||r>1||r==s_)return E_BADARG;if(n_->stopped())return E_NET_GENERAL;int d=(s_==0&&r==1)?0:1;int ord;{std::lock_guard<std::mutex>l(n_->sm);ord=++n_->counts[d];}buf_t p(m);if(n_->mutate&&d==n_->dir&&ord==n_->target){p=mutate_payload(m,n_->kind);std::cout<<"V56_MUTATED dir="<<d<<" ordinal="<<ord<<" kind="<<n_->kind<<" original="<<m.size<<" mutated="<<p.size()<<std::endl;}auto&c=n_->ch[s_][r];{std::lock_guard<std::mutex>l(c.m);c.q.emplace_back(std::move(p));}c.cv.notify_one();return SUCCESS;}error_t receive(party_idx_t s,buf_t&m)override{if(s<0||s>1||s==s_)return E_BADARG;auto&c=n_->ch[s][s_];std::unique_lock<std::mutex>l(c.m);bool ok=c.cv.wait_for(l,std::chrono::seconds(20),[&]{return!c.q.empty()||n_->stopped();});if(!ok||c.q.empty())return E_NET_GENERAL;m=std::move(c.q.front());c.q.pop_front();return SUCCESS;}error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}};
struct res_t{error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;int c01=0,c10=0;buf_t k0,k1,p0,p1;};
res_t once(bool mutate,int dir,int target,int kind){auto n=std::make_shared<net_t>();n->mutate=mutate;n->dir=dir;n->target=target;n->kind=kind;auto t0=std::make_shared<tr_t>(0,n),t1=std::make_shared<tr_t>(1,n);res_t r;std::thread a([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};r.a=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,r.k0);if(r.a)n->cancel();}),b([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};r.b=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,r.k1);if(r.b)n->cancel();});a.join();b.join();r.c01=n->counts[0];r.c10=n->counts[1];if(r.a==SUCCESS)coinbase::api::ecdsa_2p::get_public_key_compressed(r.k0,r.p0);if(r.b==SUCCESS)coinbase::api::ecdsa_2p::get_public_key_compressed(r.k1,r.p1);return r;}
}
int main(){auto ctl=once(false,-1,-1,-1);bool ok=ctl.a==SUCCESS&&ctl.b==SUCCESS&&!ctl.k0.empty()&&!ctl.k1.empty()&&ctl.p0==ctl.p1;std::cout<<"V56_CONTROL ok="<<ok<<" p1p2="<<ctl.c01<<" p2p1="<<ctl.c10<<std::endl;if(!ok)return 2;int cases=0,rejected=0,both_success=0,invariant_breaks=0;for(int dir=0;dir<2;dir++){int sends=dir==0?ctl.c01:ctl.c10;for(int ord=1;ord<=sends;ord++)for(int kind=0;kind<=8;kind++){cases++;auto r=once(true,dir,ord,kind);bool both=r.a==SUCCESS&&r.b==SUCCESS;if(!both)rejected++;else{both_success++;if(r.p0.empty()||r.p1.empty()||r.p0!=r.p1)invariant_breaks++;}std::cout<<"V56_CASE dir="<<dir<<" ord="<<ord<<" kind="<<kind<<" a="<<r.a<<" b="<<r.b<<" both="<<both<<" pub_match="<<(both&&r.p0==r.p1)<<std::endl;}}
std::cout<<"V56_DKG_SUMMARY cases="<<cases<<" rejected="<<rejected<<" both_success="<<both_success<<" invariant_breaks="<<invariant_breaks<<std::endl;std::cout<<"V56_DKG_INTEGRITY_CANDIDATE="<<(invariant_breaks?1:0)<<std::endl;std::cout<<"V56_SANITIZER_COMPLETED_WITHOUT_MEMORY_ERROR=1"<<std::endl;return invariant_breaks?1:0;}
