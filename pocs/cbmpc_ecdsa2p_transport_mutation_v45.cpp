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
struct network_t {
  channel_t ch[2][2];
  std::mutex sm;
  bool cancelled = false;
  bool mutate = false;
  int target = -1;
  int kind = -1;
  int p2p1_count = 0;
  void cancel() {
    { std::lock_guard<std::mutex> l(sm); cancelled = true; }
    for (int i=0;i<2;i++) for (int j=0;j<2;j++) ch[i][j].cv.notify_all();
  }
  bool stopped() { std::lock_guard<std::mutex> l(sm); return cancelled; }
};

buf_t mutate_payload(mem_t msg, int kind) {
  buf_t out(msg);
  if (out.empty()) return out;
  switch (kind) {
    case 0: out.resize(std::max(1, out.size()-1)); break;
    case 1: out.resize(std::max(1, out.size()/2)); break;
    case 2: out[0] ^= 0xff; break;
    case 3: out[0] = 0xff; break;
    case 4: {
      int old=out.size(); out.resize(old+64);
      for (int i=old;i<out.size();i++) out[i]=static_cast<uint8_t>(0x5a ^ i);
      break;
    }
    case 5: out.bzero(); break;
    case 6: out.resize(1); out[0]=0xff; break;
    case 7: {
      int lim=std::min(out.size(),24);
      for (int i=0;i<lim;i++) out[i] ^= static_cast<uint8_t>(0x80u >> (i%8));
      break;
    }
    case 8: { // corrupt tail where scalar/ciphertext encodings often land
      int start=std::max(0,out.size()-32);
      for (int i=start;i<out.size();i++) out[i]^=0xff;
      break;
    }
  }
  return out;
}

class transport_t final : public data_transport_i {
 public:
  transport_t(int self,std::shared_ptr<network_t> n):self_(self),n_(std::move(n)){}
  error_t send(party_idx_t receiver, mem_t msg) override {
    if(receiver<0||receiver>1||receiver==self_) return E_BADARG;
    if(n_->stopped()) return E_NET_GENERAL;
    buf_t payload(msg);
    if(self_==1&&receiver==0&&n_->mutate){
      int ord;
      {std::lock_guard<std::mutex> l(n_->sm); ord=++n_->p2p1_count;}
      if(ord==n_->target){
        payload=mutate_payload(msg,n_->kind);
        std::cout<<"V45_MUTATED p2_to_p1_send="<<ord<<" kind="<<n_->kind
                 <<" original_size="<<msg.size<<" mutated_size="<<payload.size()<<std::endl;
      }
    }
    auto& c=n_->ch[self_][receiver];
    {std::lock_guard<std::mutex> l(c.m); c.q.emplace_back(std::move(payload));}
    c.cv.notify_one(); return SUCCESS;
  }
  error_t receive(party_idx_t sender, buf_t& msg) override {
    if(sender<0||sender>1||sender==self_) return E_BADARG;
    auto& c=n_->ch[sender][self_];
    std::unique_lock<std::mutex> l(c.m);
    bool ready=c.cv.wait_for(l,std::chrono::seconds(30),[&]{return !c.q.empty()||n_->stopped();});
    if(!ready||c.q.empty()) return E_NET_GENERAL;
    msg=std::move(c.q.front()); c.q.pop_front(); return SUCCESS;
  }
  error_t receive_all(const std::vector<party_idx_t>& senders,std::vector<buf_t>& msgs) override {
    msgs.resize(senders.size());
    for(size_t i=0;i<senders.size();i++){auto rv=receive(senders[i],msgs[i]);if(rv)return rv;}
    return SUCCESS;
  }
 private:int self_;std::shared_ptr<network_t> n_;
};

std::array<error_t,2> dkg(std::array<buf_t,2>& keys){
  auto n=std::make_shared<network_t>(); auto t0=std::make_shared<transport_t>(0,n); auto t1=std::make_shared<transport_t>(1,n);
  std::array<error_t,2> rv={UNINITIALIZED_ERROR,UNINITIALIZED_ERROR};
  std::thread a([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};rv[0]=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,keys[0]);if(rv[0])n->cancel();});
  std::thread b([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};rv[1]=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,keys[1]);if(rv[1])n->cancel();});
  a.join();b.join();return rv;
}

struct sign_result_t{error_t p1=UNINITIALIZED_ERROR,p2=UNINITIALIZED_ERROR;int sig=0,sends=0;};
sign_result_t sign_once(const std::array<buf_t,2>& keys,bool mutate,int target,int kind){
  auto n=std::make_shared<network_t>();n->mutate=mutate;n->target=target;n->kind=kind;
  auto t0=std::make_shared<transport_t>(0,n);auto t1=std::make_shared<transport_t>(1,n);
  std::array<uint8_t,32> h{};for(size_t i=0;i<h.size();i++)h[i]=static_cast<uint8_t>(0x21+i);
  mem_t msg(h.data(),32);buf_t sid0,sid1,sig0,sig1;sign_result_t r;
  std::thread a([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};r.p1=coinbase::api::ecdsa_2p::sign(j,keys[0],msg,sid0,sig0);if(r.p1)n->cancel();});
  std::thread b([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};r.p2=coinbase::api::ecdsa_2p::sign(j,keys[1],msg,sid1,sig1);if(r.p2)n->cancel();});
  a.join();b.join();r.sig=sig0.size();r.sends=n->p2p1_count;return r;
}
}

int main(){
  std::array<buf_t,2> keys;auto kr=dkg(keys);
  if(kr[0]!=SUCCESS||kr[1]!=SUCCESS){std::cout<<"V45_DKG_FAILED rv0="<<kr[0]<<" rv1="<<kr[1]<<std::endl;return 2;}
  auto ctl=sign_once(keys,false,-1,-1);bool ok=ctl.p1==SUCCESS&&ctl.p2==SUCCESS&&ctl.sig>0;
  std::cout<<"V45_CONTROL p1="<<ctl.p1<<" p2="<<ctl.p2<<" sig_size="<<ctl.sig<<" p2_to_p1_sends="<<ctl.sends<<" ok="<<ok<<std::endl;
  if(!ok)return 3;
  int cases=0,rejected=0,unexpected=0;
  for(int ord=1;ord<=ctl.sends;ord++)for(int kind=0;kind<=8;kind++){
    ++cases;auto r=sign_once(keys,true,ord,kind);bool both=r.p1==SUCCESS&&r.p2==SUCCESS;
    if(both)++unexpected;else++rejected;
    std::cout<<"V45_CASE ordinal="<<ord<<" kind="<<kind<<" p1="<<r.p1<<" p2="<<r.p2<<" sig_size="<<r.sig<<" both_success="<<both<<std::endl;
  }
  std::cout<<"V45_ECDSA2P_MALFORMED_TRANSPORT_SUMMARY cases="<<cases<<" rejected="<<rejected<<" unexpected_success="<<unexpected<<std::endl;
  std::cout<<"V45_SANITIZER_COMPLETED_WITHOUT_MEMORY_ERROR=1"<<std::endl;
  return 0;
}
