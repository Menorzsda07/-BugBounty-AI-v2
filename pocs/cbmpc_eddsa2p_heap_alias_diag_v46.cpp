#include <array>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <cbmpc/api/curve.h>
#include <cbmpc/api/eddsa_2p.h>
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
struct net_t { channel_t ch[2][2]; };

class transport_t final : public data_transport_i {
 public:
  transport_t(int self, std::shared_ptr<net_t> n) : self_(self), n_(std::move(n)) {}
  error_t send(party_idx_t receiver, mem_t msg) override {
    if (receiver < 0 || receiver > 1 || receiver == self_) return E_BADARG;
    auto& c = n_->ch[self_][receiver];
    { std::lock_guard<std::mutex> l(c.m); c.q.emplace_back(msg); }
    c.cv.notify_one();
    return SUCCESS;
  }
  error_t receive(party_idx_t sender, buf_t& msg) override {
    if (sender < 0 || sender > 1 || sender == self_) return E_BADARG;
    auto& c = n_->ch[sender][self_];
    std::unique_lock<std::mutex> l(c.m);
    c.cv.wait(l, [&]{ return !c.q.empty(); });
    msg = std::move(c.q.front()); c.q.pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<party_idx_t>& senders, std::vector<buf_t>& msgs) override {
    msgs.resize(senders.size());
    for (size_t i=0;i<senders.size();++i) { auto rv=receive(senders[i],msgs[i]); if(rv) return rv; }
    return SUCCESS;
  }
 private:
  int self_; std::shared_ptr<net_t> n_;
};

bool dkg(std::array<buf_t,2>& keys) {
  auto n=std::make_shared<net_t>(); auto t0=std::make_shared<transport_t>(0,n); auto t1=std::make_shared<transport_t>(1,n);
  error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;
  std::thread p1([&]{ coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0}; a=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,keys[0]); });
  std::thread p2([&]{ coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1}; b=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,keys[1]); });
  p1.join();p2.join(); return a==SUCCESS && b==SUCCESS;
}
}

int main() {
  std::array<buf_t,2> keys;
  if(!dkg(keys)){ std::cout<<"V46_DKG_FAILED"<<std::endl; return 2; }

  for(int iter=0; iter<12; ++iter) {
    auto n=std::make_shared<net_t>(); auto t0=std::make_shared<transport_t>(0,n); auto t1=std::make_shared<transport_t>(1,n);
    buf_t honest(64); for(int i=0;i<64;i++) honest[i]=static_cast<uint8_t>(0x41 + ((i+iter)%23));
    buf_t attacker(64); attacker.bzero();
    error_t r0=UNINITIALIZED_ERROR,r1=UNINITIALIZED_ERROR; buf_t sig1;
    std::thread p1([&]{ coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0}; r0=coinbase::api::eddsa_2p::sign(j,keys[0],honest,honest); });
    std::thread p2([&]{ coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1}; r1=coinbase::api::eddsa_2p::sign(j,keys[1],attacker,sig1); });
    p1.join();p2.join();
    std::cout<<"V46_ITER iter="<<iter<<" p1="<<r0<<" p2="<<r1<<" p1_out="<<honest.size()<<" p2_out="<<sig1.size()<<std::endl;
  }
  std::cout<<"V46_DIAGNOSTIC_DONE=1"<<std::endl;
  return 0;
}
