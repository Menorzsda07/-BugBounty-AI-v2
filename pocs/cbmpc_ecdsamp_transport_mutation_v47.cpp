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

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::mem_t;
using coinbase::api::curve_id;
using coinbase::api::data_transport_i;
using coinbase::api::job_mp_t;
using coinbase::api::party_idx_t;

namespace {
struct channel_t { std::mutex m; std::condition_variable cv; std::deque<buf_t> q; };
struct net_t {
  channel_t ch[2][2];
  std::mutex sm;
  bool cancelled=false, mutate=false;
  int target=-1, kind=-1, m_to_h_count=0;
  void cancel(){ {std::lock_guard<std::mutex> l(sm);cancelled=true;} for(int i=0;i<2;i++)for(int j=0;j<2;j++)ch[i][j].cv.notify_all(); }
  bool stopped(){std::lock_guard<std::mutex> l(sm);return cancelled;}
};

buf_t mutate_payload(mem_t msg,int kind){
  buf_t out(msg); if(out.empty()) return out;
  switch(kind){
    case 0: out.resize(std::max(1,out.size()-1)); break;
    case 1:{int old=out.size();out.resize(old+32);for(int i=old;i<out.size();++i)out[i]=static_cast<uint8_t>(0x91^i);break;}
    case 2: out.bzero(); break;
    case 3:{int start=std::max(0,out.size()-32);for(int i=start;i<out.size();++i)out[i]^=0xff;break;}
    case 4: out[0]^=0xff; break;
  }
  return out;
}

class transport_t final: public data_transport_i{
 public:
  transport_t(int self,std::shared_ptr<net_t> n):self_(self),n_(std::move(n)){}
  error_t send(party_idx_t receiver,mem_t msg) override{
    if(receiver<0||receiver>1||receiver==self_) return E_BADARG;
    if(n_->stopped()) return E_NET_GENERAL;
    buf_t payload(msg);
    if(self_==1&&receiver==0){
      int ord; {std::lock_guard<std::mutex> l(n_->sm);ord=++n_->m_to_h_count;}
      if(n_->mutate&&ord==n_->target){payload=mutate_payload(msg,n_->kind);std::cout<<"V47_MUTATED send="<<ord<<" kind="<<n_->kind<<" original="<<msg.size<<" mutated="<<payload.size()<<std::endl;}
    }
    auto& c=n_->ch[self_][receiver];{std::lock_guard<std::mutex> l(c.m);c.q.emplace_back(std::move(payload));}c.cv.notify_one();return SUCCESS;
  }
  error_t receive(party_idx_t sender,buf_t& msg) override{
    if(sender<0||sender>1||sender==self_) return E_BADARG;
    auto& c=n_->ch[sender][self_];std::unique_lock<std::mutex> l(c.m);
    bool ready=c.cv.wait_for(l,std::chrono::seconds(30),[&]{return !c.q.empty()||n_->stopped();});
    if(!ready||c.q.empty()) return E_NET_GENERAL;msg=std::move(c.q.front());c.q.pop_front();return SUCCESS;
  }
  error_t receive_all(const std::vector<party_idx_t>& senders,std::vector<buf_t>& msgs) override{
    msgs.clear();msgs.resize(senders.size());for(size_t i=0;i<senders.size();++i){auto rv=receive(senders[i],msgs[i]);if(rv)return rv;}return SUCCESS;
  }
 private:int self_;std::shared_ptr<net_t> n_;
};

const std::vector<std::string> names_owned={"honest-p0","malicious-p1"};
std::vector<std::string_view> names(){return {names_owned[0],names_owned[1]};}

bool dkg(std::array<buf_t,2>& keys){
  auto n=std::make_shared<net_t>();auto t0=std::make_shared<transport_t>(0,n);auto t1=std::make_shared<transport_t>(1,n);auto ns=names();
  error_t r0=UNINITIALIZED_ERROR,r1=UNINITIALIZED_ERROR;buf_t sid0,sid1;
  std::thread a([&]{job_mp_t j{0,ns,*t0};r0=coinbase::api::ecdsa_mp::dkg_additive(j,curve_id::secp256k1,keys[0],sid0);if(r0)n->cancel();});
  std::thread b([&]{job_mp_t j{1,ns,*t1};r1=coinbase::api::ecdsa_mp::dkg_additive(j,curve_id::secp256k1,keys[1],sid1);if(r1)n->cancel();});
  a.join();b.join();std::cout<<"V47_DKG r0="<<r0<<" r1="<<r1<<std::endl;return r0==SUCCESS&&r1==SUCCESS;
}

struct result_t{error_t h=UNINITIALIZED_ERROR,m=UNINITIALIZED_ERROR;int sig=0,sends=0;};
result_t sign_once(const std::array<buf_t,2>& keys,bool mutate,int target,int kind){
  auto n=std::make_shared<net_t>();n->mutate=mutate;n->target=target;n->kind=kind;auto t0=std::make_shared<transport_t>(0,n);auto t1=std::make_shared<transport_t>(1,n);auto ns=names();
  std::array<uint8_t,32> h{};for(size_t i=0;i<h.size();++i)h[i]=static_cast<uint8_t>(0x23+i);mem_t msg(h.data(),32);
  buf_t s0,s1;result_t r;
  std::thread a([&]{job_mp_t j{0,ns,*t0};r.h=coinbase::api::ecdsa_mp::sign_additive(j,keys[0],msg,0,s0);if(r.h)n->cancel();});
  std::thread b([&]{job_mp_t j{1,ns,*t1};r.m=coinbase::api::ecdsa_mp::sign_additive(j,keys[1],msg,0,s1);if(r.m)n->cancel();});
  a.join();b.join();r.sig=s0.size();r.sends=n->m_to_h_count;return r;
}
}

int main(){
  std::array<buf_t,2> keys;if(!dkg(keys)){std::cout<<"V47_DKG_FAILED=1"<<std::endl;return 2;}
  auto ctl=sign_once(keys,false,-1,-1);bool ok=ctl.h==SUCCESS&&ctl.m==SUCCESS&&ctl.sig>0;
  std::cout<<"V47_CONTROL h="<<ctl.h<<" m="<<ctl.m<<" sig="<<ctl.sig<<" malicious_to_honest_sends="<<ctl.sends<<" ok="<<ok<<std::endl;if(!ok)return 3;
  int cases=0,rejected=0,unexpected=0;int max_sends=std::min(ctl.sends,8);
  for(int ord=1;ord<=max_sends;++ord)for(int kind=0;kind<=4;++kind){++cases;auto r=sign_once(keys,true,ord,kind);bool both=r.h==SUCCESS&&r.m==SUCCESS;if(both)++unexpected;else++rejected;std::cout<<"V47_CASE send="<<ord<<" kind="<<kind<<" h="<<r.h<<" m="<<r.m<<" sig="<<r.sig<<" both_success="<<both<<std::endl;}
  std::cout<<"V47_ECDSAMP_MALFORMED_TRANSPORT_SUMMARY cases="<<cases<<" rejected="<<rejected<<" unexpected_success="<<unexpected<<" observed_sends="<<ctl.sends<<std::endl;
  std::cout<<"V47_SANITIZER_COMPLETED_WITHOUT_MEMORY_ERROR=1"<<std::endl;return 0;
}
