#include <condition_variable>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <openssl/evp.h>
#include <cbmpc/api/curve.h>
#include <cbmpc/api/eddsa_mp.h>
#include <cbmpc/core/access_structure.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>
using coinbase::buf_t; using coinbase::error_t; using coinbase::mem_t;
using coinbase::api::access_structure_t; using coinbase::api::curve_id; using coinbase::api::data_transport_i; using coinbase::api::job_mp_t; using coinbase::api::party_idx_t;
namespace{
struct ch_t{std::mutex m;std::condition_variable cv;std::deque<buf_t>q;};
struct net_t{explicit net_t(int n):n(n),ch(n,std::vector<std::shared_ptr<ch_t>>(n)){for(int i=0;i<n;i++)for(int j=0;j<n;j++)if(i!=j)ch[i][j]=std::make_shared<ch_t>();}int n;std::vector<std::vector<std::shared_ptr<ch_t>>>ch;};
class tr_t final:public data_transport_i{int s_;std::shared_ptr<net_t>n_;public:tr_t(int s,std::shared_ptr<net_t>n):s_(s),n_(std::move(n)){}error_t send(party_idx_t r,mem_t m)override{if(r<0||r>=n_->n||r==s_)return E_BADARG;auto c=n_->ch[s_][r];{std::lock_guard<std::mutex>l(c->m);c->q.emplace_back(m);}c->cv.notify_one();return SUCCESS;}error_t receive(party_idx_t s,buf_t&m)override{if(s<0||s>=n_->n||s==s_)return E_BADARG;auto c=n_->ch[s][s_];std::unique_lock<std::mutex>l(c->m);c->cv.wait(l,[&]{return!c->q.empty();});m=std::move(c->q.front());c->q.pop_front();return SUCCESS;}error_t receive_all(const std::vector<party_idx_t>&ss,std::vector<buf_t>&ms)override{ms.resize(ss.size());for(size_t i=0;i<ss.size();i++){auto rv=receive(ss[i],ms[i]);if(rv)return rv;}return SUCCESS;}};
bool allok(const std::vector<error_t>&v){for(auto x:v)if(x!=SUCCESS)return false;return true;}
bool verify(mem_t pub,mem_t msg,mem_t sig){if(pub.size!=32||sig.size!=64)return false;EVP_PKEY*p=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,pub.data,(size_t)pub.size);if(!p)return false;EVP_MD_CTX*c=EVP_MD_CTX_new();bool ok=false;if(c&&EVP_DigestVerifyInit(c,nullptr,nullptr,nullptr,p)==1)ok=EVP_DigestVerify(c,sig.data,(size_t)sig.size,msg.data,(size_t)msg.size)==1;if(c)EVP_MD_CTX_free(c);EVP_PKEY_free(p);return ok;}
}
int main(){std::vector<std::string>names={"honest-p0","mal-p1","mal-p2"};std::vector<std::string_view>all={names[0],names[1],names[2]};auto ac3=access_structure_t::Threshold(3,{access_structure_t::leaf(names[0]),access_structure_t::leaf(names[1]),access_structure_t::leaf(names[2])});auto ac2=access_structure_t::Threshold(2,{access_structure_t::leaf(names[0]),access_structure_t::leaf(names[1]),access_structure_t::leaf(names[2])});auto dn=std::make_shared<net_t>(3);std::vector<std::shared_ptr<tr_t>>dt;for(int i=0;i<3;i++)dt.push_back(std::make_shared<tr_t>(i,dn));std::vector<buf_t>keys(3),sids(3);std::vector<error_t>dr(3,UNINITIALIZED_ERROR);std::vector<std::thread>ths;for(int i=0;i<3;i++)ths.emplace_back([&,i]{job_mp_t j{(party_idx_t)i,all,*dt[i]};dr[i]=coinbase::api::eddsa_mp::dkg_ac(j,curve_id::ed25519,sids[i],ac3,all,keys[i]);});for(auto&t:ths)t.join();if(!allok(dr)){std::cout<<"V55_DKG_FAILED=1\n";return 2;}buf_t pub;if(coinbase::api::eddsa_mp::get_public_key_compressed(keys[0],pub)!=SUCCESS||pub.size()!=32)return 3;std::vector<std::string_view>online={names[1],names[2]};auto sn=std::make_shared<net_t>(2);auto t1=std::make_shared<tr_t>(0,sn),t2=std::make_shared<tr_t>(1,sn);buf_t msg(32);for(int i=0;i<32;i++)msg[i]=(uint8_t)(0x41+i);buf_t s1,s2;error_t r1=UNINITIALIZED_ERROR,r2=UNINITIALIZED_ERROR;std::thread a([&]{job_mp_t j{0,online,*t1};r1=coinbase::api::eddsa_mp::sign_ac(j,keys[1],ac2,msg,1,s1);}),b([&]{job_mp_t j{1,online,*t2};r2=coinbase::api::eddsa_mp::sign_ac(j,keys[2],ac2,msg,1,s2);});a.join();b.join();bool forged=r1==SUCCESS&&r2==SUCCESS&&s2.size()==64&&verify(pub,msg,s2);std::cout<<"V55_POLICY_SUBSTITUTION original_threshold=3 supplied_threshold=2 honest_offline=1 r1="<<r1<<" r2="<<r2<<" sig="<<s2.size()<<" verifies="<<(forged?1:0)<<std::endl;std::cout<<"V55_THRESHOLD_BYPASS_CANDIDATE="<<(forged?1:0)<<std::endl;return forged?1:0;}
