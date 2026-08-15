#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
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

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::mem_t;
using coinbase::api::curve_id;
using coinbase::api::data_transport_i;
using coinbase::api::party_2p_t;
using coinbase::api::party_idx_t;

namespace {
struct channel_t { std::mutex m; std::condition_variable cv; std::deque<buf_t> q; };
struct net_t {
  channel_t ch[2][2]; std::mutex sm; bool cancelled=false, mutate=false; int target=-1,kind=-1,p2p1=0;
  void cancel(){ {std::lock_guard<std::mutex> l(sm);cancelled=true;} for(int i=0;i<2;i++)for(int j=0;j<2;j++)ch[i][j].cv.notify_all(); }
  bool stopped(){std::lock_guard<std::mutex> l(sm);return cancelled;}
};

buf_t mutate_payload(mem_t msg,int kind){buf_t out(msg);if(out.empty())return out;switch(kind){
  case 0:out.resize(std::max(1,out.size()-1));break;
  case 1:{int old=out.size();out.resize(old+32);for(int i=old;i<out.size();++i)out[i]=static_cast<uint8_t>(0x73^i);break;}
  case 2:out.bzero();break;
  case 3:out[0]^=0xff;break;
  case 4:{int start=std::max(0,out.size()-32);for(int i=start;i<out.size();++i)out[i]^=0xff;break;}
}return out;}

class transport_t final:public data_transport_i{
 public:transport_t(int s,std::shared_ptr<net_t> n):s_(s),n_(std::move(n)){}
 error_t send(party_idx_t r,mem_t msg)override{if(r<0||r>1||r==s_)return E_BADARG;if(n_->stopped())return E_NET_GENERAL;buf_t p(msg);
   if(s_==1&&r==0){int ord;{std::lock_guard<std::mutex> l(n_->sm);ord=++n_->p2p1;}if(n_->mutate&&ord==n_->target){p=mutate_payload(msg,n_->kind);std::cout<<"V48_MUTATED send="<<ord<<" kind="<<n_->kind<<" original="<<msg.size<<" mutated="<<p.size()<<std::endl;}}
   auto& c=n_->ch[s_][r];{std::lock_guard<std::mutex> l(c.m);c.q.emplace_back(std::move(p));}c.cv.notify_one();return SUCCESS;}
 error_t receive(party_idx_t s,buf_t& msg)override{if(s<0||s>1||s==s_)return E_BADARG;auto& c=n_->ch[s][s_];std::unique_lock<std::mutex> l(c.m);bool ok=c.cv.wait_for(l,std::chrono::seconds(30),[&]{return !c.q.empty()||n_->stopped();});if(!ok||c.q.empty())return E_NET_GENERAL;msg=std::move(c.q.front());c.q.pop_front();return SUCCESS;}
 error_t receive_all(const std::vector<party_idx_t>& ss,std::vector<buf_t>& ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();++i){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}
 private:int s_;std::shared_ptr<net_t> n_;
};

bool dkg(std::array<buf_t,2>& keys){auto n=std::make_shared<net_t>();auto t0=std::make_shared<transport_t>(0,n);auto t1=std::make_shared<transport_t>(1,n);error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;
 std::thread p0([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};a=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,keys[0]);if(a)n->cancel();});
 std::thread p1([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};b=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,keys[1]);if(b)n->cancel();});p0.join();p1.join();return a==SUCCESS&&b==SUCCESS;}

struct rr_t{error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;int sends=0;buf_t k0,k1;};
rr_t refresh_once(const std::array<buf_t,2>& keys,bool mut,int target,int kind){auto n=std::make_shared<net_t>();n->mutate=mut;n->target=target;n->kind=kind;auto t0=std::make_shared<transport_t>(0,n);auto t1=std::make_shared<transport_t>(1,n);rr_t r;
 std::thread p0([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};r.a=coinbase::api::ecdsa_2p::refresh(j,keys[0],r.k0);if(r.a)n->cancel();});
 std::thread p1([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};r.b=coinbase::api::ecdsa_2p::refresh(j,keys[1],r.k1);if(r.b)n->cancel();});p0.join();p1.join();r.sends=n->p2p1;return r;}

bool pub(mem_t key,buf_t& out){return coinbase::api::ecdsa_2p::get_public_key_compressed(key,out)==SUCCESS;}
bool sign_ok(const buf_t& k0,const buf_t& k1){auto n=std::make_shared<net_t>();auto t0=std::make_shared<transport_t>(0,n);auto t1=std::make_shared<transport_t>(1,n);std::array<uint8_t,32> h{};for(size_t i=0;i<h.size();++i)h[i]=static_cast<uint8_t>(0x55+i);mem_t msg(h.data(),32);buf_t sid0,sid1,s0,s1;error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;
 std::thread p0([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};a=coinbase::api::ecdsa_2p::sign(j,k0,msg,sid0,s0);if(a)n->cancel();});std::thread p1([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};b=coinbase::api::ecdsa_2p::sign(j,k1,msg,sid1,s1);if(b)n->cancel();});p0.join();p1.join();return a==SUCCESS&&b==SUCCESS&&!s0.empty();}
}

int main(){std::array<buf_t,2> keys;if(!dkg(keys)){std::cout<<"V48_DKG_FAILED=1"<<std::endl;return 2;}buf_t original_pub0,original_pub1;if(!pub(keys[0],original_pub0)||!pub(keys[1],original_pub1)||original_pub0!=original_pub1)return 3;
 auto ctl=refresh_once(keys,false,-1,-1);bool ctl_success=ctl.a==SUCCESS&&ctl.b==SUCCESS;buf_t cp0,cp1;bool ctl_inv=ctl_success&&pub(ctl.k0,cp0)&&pub(ctl.k1,cp1)&&cp0==original_pub0&&cp1==original_pub0&&sign_ok(ctl.k0,ctl.k1);
 std::cout<<"V48_CONTROL success="<<ctl_success<<" sends="<<ctl.sends<<" invariants="<<ctl_inv<<std::endl;if(!ctl_inv)return 4;
 int cases=0,rejected=0,successes=0,invariant_breaks=0;
 for(int ord=1;ord<=ctl.sends;++ord)for(int kind=0;kind<=4;++kind){++cases;auto r=refresh_once(keys,true,ord,kind);bool ok=r.a==SUCCESS&&r.b==SUCCESS;if(!ok){++rejected;std::cout<<"V48_CASE send="<<ord<<" kind="<<kind<<" success=0 a="<<r.a<<" b="<<r.b<<std::endl;continue;}++successes;buf_t p0,p1;bool same=pub(r.k0,p0)&&pub(r.k1,p1)&&p0==original_pub0&&p1==original_pub0;bool can_sign=same&&sign_ok(r.k0,r.k1);bool inv=same&&can_sign;if(!inv)++invariant_breaks;std::cout<<"V48_CASE send="<<ord<<" kind="<<kind<<" success=1 same_pub="<<same<<" can_sign="<<can_sign<<" invariant="<<inv<<std::endl;}
 std::cout<<"V48_REFRESH_SUMMARY cases="<<cases<<" rejected="<<rejected<<" mutated_successes="<<successes<<" invariant_breaks="<<invariant_breaks<<std::endl;
 std::cout<<"V48_REFRESH_KEY_INTEGRITY_CANDIDATE="<<(invariant_breaks?1:0)<<std::endl;std::cout<<"V48_SANITIZER_COMPLETED_WITHOUT_MEMORY_ERROR=1"<<std::endl;return 0;}
