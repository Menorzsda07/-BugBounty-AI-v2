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

using coinbase::buf_t;using coinbase::error_t;using coinbase::mem_t;
using coinbase::api::curve_id;using coinbase::api::data_transport_i;
using coinbase::api::party_2p_t;using coinbase::api::party_idx_t;
namespace{
struct ch_t{std::mutex m;std::condition_variable cv;std::deque<buf_t>q;};
struct net_t{ch_t ch[2][2];std::mutex cm;bool capture=false;std::vector<buf_t> p2p1;};
class normal_t final:public data_transport_i{int self_;std::shared_ptr<net_t>n_;public:normal_t(int s,std::shared_ptr<net_t>n):self_(s),n_(std::move(n)){}
 error_t send(party_idx_t r,mem_t m)override{if(r<0||r>1||r==self_)return E_BADARG;buf_t p(m);if(self_==1&&r==0&&n_->capture){std::lock_guard<std::mutex>l(n_->cm);n_->p2p1.emplace_back(p);}auto&c=n_->ch[self_][r];{std::lock_guard<std::mutex>l(c.m);c.q.emplace_back(std::move(p));}c.cv.notify_one();return SUCCESS;}
 error_t receive(party_idx_t s,buf_t&m)override{if(s<0||s>1||s==self_)return E_BADARG;auto&c=n_->ch[s][self_];std::unique_lock<std::mutex>l(c.m);c.cv.wait(l,[&]{return!c.q.empty();});m=std::move(c.q.front());c.q.pop_front();return SUCCESS;}
 error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}};
class replay_t final:public data_transport_i{std::vector<buf_t>m_;size_t p_=0;public:explicit replay_t(const std::vector<buf_t>&m):m_(m){}
 error_t send(party_idx_t r,mem_t)override{return r==1?SUCCESS:E_BADARG;}
 error_t receive(party_idx_t s,buf_t&m)override{if(s!=1)return E_BADARG;if(p_>=m_.size())return E_NET_GENERAL;m=m_[p_++];std::cout<<"V52_REPLAY_DELIVER index="<<p_<<" size="<<m.size()<<std::endl;return SUCCESS;}
 error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}size_t used()const{return p_;}};
bool dkg(std::array<buf_t,2>&k){auto n=std::make_shared<net_t>();auto t0=std::make_shared<normal_t>(0,n),t1=std::make_shared<normal_t>(1,n);error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;std::thread x([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};a=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,k[0]);}),y([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};b=coinbase::api::eddsa_2p::dkg(j,curve_id::ed25519,k[1]);});x.join();y.join();return a==SUCCESS&&b==SUCCESS;}
struct cap_t{error_t a=UNINITIALIZED_ERROR,b=UNINITIALIZED_ERROR;buf_t sig;std::vector<buf_t>msgs;};
cap_t capture(const std::array<buf_t,2>&k,mem_t msg){auto n=std::make_shared<net_t>();n->capture=true;auto t0=std::make_shared<normal_t>(0,n),t1=std::make_shared<normal_t>(1,n);cap_t r;buf_t s1;std::thread x([&]{coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",*t0};r.a=coinbase::api::eddsa_2p::sign(j,k[0],msg,r.sig);}),y([&]{coinbase::api::job_2p_t j{party_2p_t::p2,"p1","p2",*t1};r.b=coinbase::api::eddsa_2p::sign(j,k[1],msg,s1);});x.join();y.join();r.msgs=n->p2p1;return r;}
struct rr{error_t rv=UNINITIALIZED_ERROR;int sig=0;size_t used=0;};rr replay(const buf_t&k,const std::vector<buf_t>&msgs,mem_t msg){replay_t t(msgs);coinbase::api::job_2p_t j{party_2p_t::p1,"p1","p2",t};buf_t s;rr r;r.rv=coinbase::api::eddsa_2p::sign(j,k,msg,s);r.sig=s.size();r.used=t.used();return r;}
}
int main(){std::array<buf_t,2>k;if(!dkg(k)){std::cout<<"V52_DKG_FAILED=1\n";return 2;}std::array<uint8_t,64>a{},b{};for(size_t i=0;i<a.size();i++){a[i]=uint8_t(0x11+i);b[i]=uint8_t(0xe0-i);}auto c=capture(k,mem_t(a.data(),64));bool ok=c.a==SUCCESS&&c.b==SUCCESS&&!c.sig.empty()&&!c.msgs.empty();std::cout<<"V52_CONTROL success="<<ok<<" captured_p2_to_p1="<<c.msgs.size()<<" sig="<<c.sig.size()<<std::endl;if(!ok)return 3;auto same=replay(k[0],c.msgs,mem_t(a.data(),64));auto diff=replay(k[0],c.msgs,mem_t(b.data(),64));bool bypass=(same.rv==SUCCESS&&same.sig>0)||(diff.rv==SUCCESS&&diff.sig>0);std::cout<<"V52_REPLAY_SAME rv="<<same.rv<<" sig="<<same.sig<<" consumed="<<same.used<<std::endl;std::cout<<"V52_REPLAY_DIFFERENT rv="<<diff.rv<<" sig="<<diff.sig<<" consumed="<<diff.used<<std::endl;std::cout<<"V52_CROSS_SESSION_REPLAY_CANDIDATE="<<(bypass?1:0)<<std::endl;return bypass?1:0;}
