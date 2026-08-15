#include <array>
#include <condition_variable>
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

using coinbase::buf_t; using coinbase::error_t; using coinbase::mem_t;
using coinbase::api::curve_id; using coinbase::api::data_transport_i;
using coinbase::api::party_2p_t; using coinbase::api::party_idx_t;

namespace {
struct ch_t { std::mutex m; std::condition_variable cv; std::deque<buf_t> q; };
struct net_t { ch_t ch[2][2]; std::mutex cm; bool capture=false; std::vector<buf_t> p1p2, p2p1; };
class normal_t final : public data_transport_i { int self_; std::shared_ptr<net_t> n_; public: normal_t(int s,std::shared_ptr<net_t> n):self_(s),n_(std::move(n)){} error_t send(party_idx_t r,mem_t m)override{if(r<0||r>1||r==self_)return E_BADARG;buf_t p(m);if(n_->capture){std::lock_guard<std::mutex>l(n_->cm);if(self_==0&&r==1)n_->p1p2.emplace_back(p);if(self_==1&&r==0)n_->p2p1.emplace_back(p);}auto&c=n_->ch[self_][r];{std::lock_guard<std::mutex>l(c.m);c.q.emplace_back(std::move(p));}c.cv.notify_one();return SUCCESS;} error_t receive(party_idx_t s,buf_t&m)override{if(s<0||s>1||s==self_)return E_BADARG;auto&c=n_->ch[s][self_];std::unique_lock<std::mutex>l(c.m);c.cv.wait(l,[&]{return!c.q.empty();});m=std::move(c.q.front());c.q.pop_front();return SUCCESS;} error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}};
class replay_t final : public data_transport_i { int self_,peer_; std::vector<buf_t> msgs_; size_t pos_=0; public: replay_t(int self,std::vector<buf_t>msgs):self_(self),peer_(1-self),msgs_(std::move(msgs)){} error_t send(party_idx_t r,mem_t)override{return r==peer_?SUCCESS:E_BADARG;} error_t receive(party_idx_t s,buf_t&m)override{if(s!=peer_)return E_BADARG;if(pos_>=msgs_.size())return E_NET_GENERAL;m=msgs_[pos_++];std::cout<<"V54_REPLAY self="<<self_<<" index="<<pos_<<" size="<<m.size()<<std::endl;return SUCCESS;} error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;} size_t consumed()const{return pos_;}};
struct cap_t{error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;std::array<buf_t,2>keys;std::vector<buf_t>p1p2,p2p1;};
cap_t capture_dkg(){cap_t r;auto n=std::make_shared<net_t>();n->capture=true;auto t0=std::make_shared<normal_t>(0,n),t1=std::make_shared<normal_t>(1,n);std::thread x([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};r.a=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,r.keys[0]);}),y([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};r.b=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,r.keys[1]);});x.join();y.join();r.p1p2=n->p1p2;r.p2p1=n->p2p1;return r;}
struct rr_t{error_t rv=UNINITIALIZED_ERROR;int key_size=0;size_t used=0;};rr_t replay_as(int self,const std::vector<buf_t>&msgs){replay_t t(self,msgs);buf_t key;error_t rv;if(self==0){coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",t};rv=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,key);}else{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",t};rv=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,key);}return{rv,key.size(),t.consumed()};}
}
int main(){auto cap=capture_dkg();bool ctl=cap.a==SUCCESS&&cap.b==SUCCESS&&!cap.keys[0].empty()&&!cap.keys[1].empty()&&!cap.p1p2.empty()&&!cap.p2p1.empty();std::cout<<"V54_CONTROL success="<<ctl<<" p1p2="<<cap.p1p2.size()<<" p2p1="<<cap.p2p1.size()<<std::endl;if(!ctl)return 2;auto p1=replay_as(0,cap.p2p1);auto p2=replay_as(1,cap.p1p2);bool bypass=(p1.rv==SUCCESS&&p1.key_size>0)||(p2.rv==SUCCESS&&p2.key_size>0);std::cout<<"V54_FRESH_P1_OLD_P2 rv="<<p1.rv<<" key="<<p1.key_size<<" used="<<p1.used<<std::endl;std::cout<<"V54_FRESH_P2_OLD_P1 rv="<<p2.rv<<" key="<<p2.key_size<<" used="<<p2.used<<std::endl;std::cout<<"V54_DKG_REPLAY_CANDIDATE="<<(bypass?1:0)<<std::endl;return bypass?1:0;}
