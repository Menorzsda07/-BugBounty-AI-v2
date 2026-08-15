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
#include <cbmpc/api/ecdsa_2p.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>

using coinbase::buf_t; using coinbase::error_t; using coinbase::mem_t;
using coinbase::api::curve_id; using coinbase::api::data_transport_i;
using coinbase::api::party_2p_t; using coinbase::api::party_idx_t;

namespace {
struct ch_t{std::mutex m;std::condition_variable cv;std::deque<buf_t>q;};
struct net_t{ch_t ch[2][2];std::mutex cm;bool capture=false;std::vector<buf_t> p2_to_p1;};
class normal_t final:public data_transport_i{int self_;std::shared_ptr<net_t>n_;public:normal_t(int s,std::shared_ptr<net_t>n):self_(s),n_(std::move(n)){}
 error_t send(party_idx_t r,mem_t m)override{if(r<0||r>1||r==self_)return E_BADARG;buf_t p(m);if(self_==1&&r==0&&n_->capture){std::lock_guard<std::mutex>l(n_->cm);n_->p2_to_p1.emplace_back(p);}auto&c=n_->ch[self_][r];{std::lock_guard<std::mutex>l(c.m);c.q.emplace_back(std::move(p));}c.cv.notify_one();return SUCCESS;}
 error_t receive(party_idx_t s,buf_t&m)override{if(s<0||s>1||s==self_)return E_BADARG;auto&c=n_->ch[s][self_];std::unique_lock<std::mutex>l(c.m);c.cv.wait(l,[&]{return!c.q.empty();});m=std::move(c.q.front());c.q.pop_front();return SUCCESS;}
 error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}};
class replay_t final:public data_transport_i{std::vector<buf_t> msgs_;size_t pos_=0;public:explicit replay_t(const std::vector<buf_t>&m):msgs_(m){}
 error_t send(party_idx_t r,mem_t)override{return r==1?SUCCESS:E_BADARG;}
 error_t receive(party_idx_t s,buf_t&m)override{if(s!=1)return E_BADARG;if(pos_>=msgs_.size())return E_NET_GENERAL;m=msgs_[pos_++];std::cout<<"V51_REPLAY_DELIVER index="<<pos_<<" size="<<m.size()<<std::endl;return SUCCESS;}
 error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}
 size_t consumed()const{return pos_;}};
bool dkg(std::array<buf_t,2>&k){auto n=std::make_shared<net_t>();auto t0=std::make_shared<normal_t>(0,n),t1=std::make_shared<normal_t>(1,n);error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;std::thread x([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};a=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,k[0]);}),y([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};b=coinbase::api::ecdsa_2p::dkg(j,curve_id::secp256k1,k[1]);});x.join();y.join();return a==SUCCESS&&b==SUCCESS;}
struct captured_t{error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;buf_t sig;std::vector<buf_t> msgs;};
captured_t capture_sign(const std::array<buf_t,2>&k,mem_t msg){auto n=std::make_shared<net_t>();n->capture=true;auto t0=std::make_shared<normal_t>(0,n),t1=std::make_shared<normal_t>(1,n);captured_t r;buf_t sid0,sid1,sig1;std::thread x([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};r.a=coinbase::api::ecdsa_2p::sign(j,k[0],msg,sid0,r.sig);}),y([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};r.b=coinbase::api::ecdsa_2p::sign(j,k[1],msg,sid1,sig1);});x.join();y.join();r.msgs=n->p2_to_p1;return r;}
struct replay_result{error_t rv=UNINITIALIZED_ERROR;int sig=0;size_t used=0;};
replay_result replay_once(const buf_t&k,const std::vector<buf_t>&msgs,mem_t msg){replay_t t(msgs);coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",t};buf_t sid,sig;replay_result r;r.rv=coinbase::api::ecdsa_2p::sign(j,k,msg,sid,sig);r.sig=sig.size();r.used=t.consumed();return r;}
}
int main(){std::array<buf_t,2>k;if(!dkg(k)){std::cout<<"V51_DKG_FAILED=1\n";return 2;}std::array<uint8_t,32>m1{},m2{};for(size_t i=0;i<32;i++){m1[i]=uint8_t(0x20+i);m2[i]=uint8_t(0xa0-i);}auto cap=capture_sign(k,mem_t(m1.data(),32));bool ctl=cap.a==SUCCESS&&cap.b==SUCCESS&&!cap.sig.empty()&&!cap.msgs.empty();std::cout<<"V51_CONTROL success="<<ctl<<" captured_p2_to_p1="<<cap.msgs.size()<<" sig="<<cap.sig.size()<<std::endl;if(!ctl)return 3;auto same=replay_once(k[0],cap.msgs,mem_t(m1.data(),32));auto diff=replay_once(k[0],cap.msgs,mem_t(m2.data(),32));bool bypass=(same.rv==SUCCESS&&same.sig>0)||(diff.rv==SUCCESS&&diff.sig>0);std::cout<<"V51_REPLAY_SAME rv="<<same.rv<<" sig="<<same.sig<<" consumed="<<same.used<<std::endl;std::cout<<"V51_REPLAY_DIFFERENT rv="<<diff.rv<<" sig="<<diff.sig<<" consumed="<<diff.used<<std::endl;std::cout<<"V51_CROSS_SESSION_REPLAY_CANDIDATE="<<(bypass?1:0)<<std::endl;return bypass?1:0;}
