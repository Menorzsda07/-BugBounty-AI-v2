#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <cbmpc/api/curve.h>
#include <cbmpc/api/ecdsa_mp.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>

using coinbase::buf_t; using coinbase::error_t; using coinbase::mem_t;
using coinbase::api::curve_id; using coinbase::api::data_transport_i;
using coinbase::api::job_mp_t; using coinbase::api::party_idx_t;

namespace {
struct ch_t{std::mutex m;std::condition_variable cv;std::deque<buf_t> q;};
struct net_t{ch_t ch[2][2];std::mutex sm;bool stop=false,mut=false;int target=-1,kind=-1,m2h=0;
 void cancel(){{std::lock_guard<std::mutex>l(sm);stop=true;}for(int i=0;i<2;i++)for(int j=0;j<2;j++)ch[i][j].cv.notify_all();}
 bool stopped(){std::lock_guard<std::mutex>l(sm);return stop;}};
buf_t mutate(mem_t m,int k){buf_t o(m);if(o.empty())return o;switch(k){case 0:o.resize(std::max(1,o.size()-1));break;case 1:{int x=o.size();o.resize(x+32);for(int i=x;i<o.size();i++)o[i]=uint8_t(0xa7^i);break;}case 2:o.bzero();break;case 3:o[0]^=0xff;break;case 4:{int s=std::max(0,o.size()-32);for(int i=s;i<o.size();i++)o[i]^=0xff;break;}}return o;}
class tr_t final:public data_transport_i{int self_;std::shared_ptr<net_t>n_;public:tr_t(int s,std::shared_ptr<net_t>n):self_(s),n_(std::move(n)){}
 error_t send(party_idx_t r,mem_t m)override{if(r<0||r>1||r==self_)return E_BADARG;if(n_->stopped())return E_NET_GENERAL;buf_t p(m);if(self_==1&&r==0){int ord;{std::lock_guard<std::mutex>l(n_->sm);ord=++n_->m2h;}if(n_->mut&&ord==n_->target){p=mutate(m,n_->kind);std::cout<<"V50_MUTATED send="<<ord<<" kind="<<n_->kind<<" original="<<m.size<<" mutated="<<p.size()<<std::endl;}}auto&c=n_->ch[self_][r];{std::lock_guard<std::mutex>l(c.m);c.q.emplace_back(std::move(p));}c.cv.notify_one();return SUCCESS;}
 error_t receive(party_idx_t s,buf_t&m)override{if(s<0||s>1||s==self_)return E_BADARG;auto&c=n_->ch[s][self_];std::unique_lock<std::mutex>l(c.m);bool ok=c.cv.wait_for(l,std::chrono::seconds(30),[&]{return!c.q.empty()||n_->stopped();});if(!ok||c.q.empty())return E_NET_GENERAL;m=std::move(c.q.front());c.q.pop_front();return SUCCESS;}
 error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.clear();ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}};
const std::vector<std::string> owned={"honest-p0","malicious-p1"};std::vector<std::string_view> names(){return{owned[0],owned[1]};}
bool dkg(std::array<buf_t,2>&k){auto n=std::make_shared<net_t>();auto t0=std::make_shared<tr_t>(0,n),t1=std::make_shared<tr_t>(1,n);auto ns=names();error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;buf_t s0,s1;std::thread x([&]{job_mp_t j{0,ns,*t0};a=coinbase::api::ecdsa_mp::dkg_additive(j,curve_id::secp256k1,k[0],s0);if(a)n->cancel();}),y([&]{job_mp_t j{1,ns,*t1};b=coinbase::api::ecdsa_mp::dkg_additive(j,curve_id::secp256k1,k[1],s1);if(b)n->cancel();});x.join();y.join();return a==SUCCESS&&b==SUCCESS;}
struct rr{error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;int sends=0;buf_t k0,k1;};
rr refresh(const std::array<buf_t,2>&k,bool mut,int target,int kind){auto n=std::make_shared<net_t>();n->mut=mut;n->target=target;n->kind=kind;auto t0=std::make_shared<tr_t>(0,n),t1=std::make_shared<tr_t>(1,n);auto ns=names();rr r;const uint8_t sidb[]={'v','5','0','-','r','e','f','r','e','s','h'};buf_t s0(sidb,sizeof sidb),s1(sidb,sizeof sidb);std::thread x([&]{job_mp_t j{0,ns,*t0};r.a=coinbase::api::ecdsa_mp::refresh_additive(j,s0,k[0],r.k0);if(r.a)n->cancel();}),y([&]{job_mp_t j{1,ns,*t1};r.b=coinbase::api::ecdsa_mp::refresh_additive(j,s1,k[1],r.k1);if(r.b)n->cancel();});x.join();y.join();r.sends=n->m2h;return r;}
bool pub(mem_t k,buf_t&o){return coinbase::api::ecdsa_mp::get_public_key_compressed(k,o)==SUCCESS;}
bool signok(const buf_t&k0,const buf_t&k1){auto n=std::make_shared<net_t>();auto t0=std::make_shared<tr_t>(0,n),t1=std::make_shared<tr_t>(1,n);auto ns=names();std::array<uint8_t,32>h{};for(size_t i=0;i<h.size();i++)h[i]=uint8_t(0x31+i);buf_t q0,q1;error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;std::thread x([&]{job_mp_t j{0,ns,*t0};a=coinbase::api::ecdsa_mp::sign_additive(j,k0,mem_t(h.data(),32),0,q0);if(a)n->cancel();}),y([&]{job_mp_t j{1,ns,*t1};b=coinbase::api::ecdsa_mp::sign_additive(j,k1,mem_t(h.data(),32),0,q1);if(b)n->cancel();});x.join();y.join();return a==SUCCESS&&b==SUCCESS&&!q0.empty();}
}
int main(){std::array<buf_t,2>k;if(!dkg(k)){std::cout<<"V50_DKG_FAILED=1\n";return 2;}buf_t p0,p1;if(!pub(k[0],p0)||!pub(k[1],p1)||p0!=p1)return 3;auto c=refresh(k,false,-1,-1);bool cs=c.a==SUCCESS&&c.b==SUCCESS;buf_t cp0,cp1;bool ci=cs&&pub(c.k0,cp0)&&pub(c.k1,cp1)&&cp0==p0&&cp1==p0&&signok(c.k0,c.k1);std::cout<<"V50_CONTROL success="<<cs<<" sends="<<c.sends<<" invariants="<<ci<<std::endl;if(!ci)return 4;int cases=0,rej=0,succ=0,br=0;for(int ord=1;ord<=c.sends;ord++)for(int kind=0;kind<=4;kind++){cases++;auto r=refresh(k,true,ord,kind);bool ok=r.a==SUCCESS&&r.b==SUCCESS;if(!ok){rej++;std::cout<<"V50_CASE send="<<ord<<" kind="<<kind<<" success=0 a="<<r.a<<" b="<<r.b<<std::endl;continue;}succ++;buf_t a,b;bool same=pub(r.k0,a)&&pub(r.k1,b)&&a==p0&&b==p0;bool sg=same&&signok(r.k0,r.k1);if(!(same&&sg))br++;std::cout<<"V50_CASE send="<<ord<<" kind="<<kind<<" success=1 same_pub="<<same<<" can_sign="<<sg<<std::endl;}std::cout<<"V50_REFRESH_SUMMARY cases="<<cases<<" rejected="<<rej<<" mutated_successes="<<succ<<" invariant_breaks="<<br<<std::endl;std::cout<<"V50_REFRESH_KEY_INTEGRITY_CANDIDATE="<<(br?1:0)<<std::endl;std::cout<<"V50_SANITIZER_COMPLETED_WITHOUT_MEMORY_ERROR=1\n";return 0;}
