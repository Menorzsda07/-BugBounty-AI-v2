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

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::mem_t;
using coinbase::api::access_structure_t;
using coinbase::api::curve_id;
using coinbase::api::data_transport_i;
using coinbase::api::job_mp_t;
using coinbase::api::party_idx_t;

namespace {

struct channel_t {
  std::mutex m;
  std::condition_variable cv;
  std::deque<buf_t> q;
};

struct network_t {
  explicit network_t(int n) : n(n), ch(n, std::vector<std::shared_ptr<channel_t>>(n)) {
    for (int from = 0; from < n; ++from)
      for (int to = 0; to < n; ++to)
        if (from != to) ch[from][to] = std::make_shared<channel_t>();
  }
  int n;
  std::vector<std::vector<std::shared_ptr<channel_t>>> ch;
};

class transport_t final : public data_transport_i {
 public:
  transport_t(int self, std::shared_ptr<network_t> net) : self_(self), net_(std::move(net)) {}

  error_t send(party_idx_t receiver, mem_t msg) override {
    if (receiver < 0 || receiver >= net_->n || receiver == self_) return E_BADARG;
    auto c = net_->ch[self_][receiver];
    {
      std::lock_guard<std::mutex> lock(c->m);
      c->q.emplace_back(msg);
    }
    c->cv.notify_one();
    return SUCCESS;
  }

  error_t receive(party_idx_t sender, buf_t& msg) override {
    if (sender < 0 || sender >= net_->n || sender == self_) return E_BADARG;
    auto c = net_->ch[sender][self_];
    std::unique_lock<std::mutex> lock(c->m);
    c->cv.wait(lock, [&] { return !c->q.empty(); });
    msg = std::move(c->q.front());
    c->q.pop_front();
    return SUCCESS;
  }

  error_t receive_all(const std::vector<party_idx_t>& senders, std::vector<buf_t>& msgs) override {
    msgs.clear();
    msgs.resize(senders.size());
    for (size_t i = 0; i < senders.size(); ++i) {
      error_t rv = receive(senders[i], msgs[i]);
      if (rv) return rv;
    }
    return SUCCESS;
  }

 private:
  int self_;
  std::shared_ptr<network_t> net_;
};

template <typename Fn>
std::vector<error_t> run_parties(int n, Fn fn) {
  std::vector<error_t> rvs(static_cast<size_t>(n), UNINITIALIZED_ERROR);
  std::vector<std::thread> threads;
  for (int i = 0; i < n; ++i) threads.emplace_back([&, i] { rvs[static_cast<size_t>(i)] = fn(i); });
  for (auto& t : threads) t.join();
  return rvs;
}

bool ed25519_verify(mem_t pub, mem_t msg, mem_t sig) {
  if (pub.size != 32 || sig.size != 64) return false;
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data, static_cast<size_t>(pub.size));
  if (!pkey) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }
  bool ok = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
    ok = EVP_DigestVerify(ctx, sig.data, static_cast<size_t>(sig.size), msg.data,
                          static_cast<size_t>(msg.size)) == 1;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

bool all_success(const std::vector<error_t>& rvs) {
  for (auto rv : rvs)
    if (rv != SUCCESS) return false;
  return true;
}

}  // namespace

int main() {
  const int n = 3;
  std::vector<std::string> names = {"honest-p0", "malicious-p1", "offline-p2"};
  std::vector<std::string_view> all_names = {names[0], names[1], names[2]};
  const access_structure_t ac = access_structure_t::Threshold(
      2, {access_structure_t::leaf(names[0]), access_structure_t::leaf(names[1]), access_structure_t::leaf(names[2])});

  auto dkg_net = std::make_shared<network_t>(3);
  std::vector<std::shared_ptr<transport_t>> dkg_transport;
  for (int i = 0; i < 3; ++i) dkg_transport.push_back(std::make_shared<transport_t>(i, dkg_net));

  std::vector<buf_t> key_blobs(3), sids(3);
  const std::vector<std::string_view> all_contributors = all_names;
  auto dkg_rvs = run_parties(3, [&](int i) {
    job_mp_t job{static_cast<party_idx_t>(i), all_names, *dkg_transport[static_cast<size_t>(i)]};
    return coinbase::api::eddsa_mp::dkg_ac(job, curve_id::ed25519, sids[static_cast<size_t>(i)], ac,
                                           all_contributors, key_blobs[static_cast<size_t>(i)]);
  });
  if (!all_success(dkg_rvs)) {
    std::cerr << "POC_DKG_FAILED" << std::endl;
    return 3;
  }

  buf_t public_key;
  if (coinbase::api::eddsa_mp::get_public_key_compressed(key_blobs[0], public_key) != SUCCESS ||
      public_key.size() != 32) {
    std::cerr << "POC_PUBLIC_KEY_FAILED" << std::endl;
    return 4;
  }

  const std::vector<std::string_view> online_names = {names[0], names[1]};
  auto sign_net = std::make_shared<network_t>(2);
  auto t0 = std::make_shared<transport_t>(0, sign_net);
  auto t1 = std::make_shared<transport_t>(1, sign_net);

  buf_t honest_message(32);
  for (int i = 0; i < 32; ++i) honest_message[i] = static_cast<uint8_t>(0x71 + (i % 8));
  const buf_t approved_message = honest_message;

  buf_t malicious_message(32);
  malicious_message.bzero();
  const buf_t attacker_message = malicious_message;
  buf_t attacker_signature;

  std::vector<error_t> exploit_rvs(2, UNINITIALIZED_ERROR);
  std::thread honest([&] {
    job_mp_t job{0, online_names, *t0};
    exploit_rvs[0] = coinbase::api::eddsa_mp::sign_ac(job, key_blobs[0], ac, honest_message,
                                                       /*sig_receiver=*/1, honest_message);
  });
  std::thread malicious([&] {
    job_mp_t job{1, online_names, *t1};
    exploit_rvs[1] = coinbase::api::eddsa_mp::sign_ac(job, key_blobs[1], ac, malicious_message,
                                                       /*sig_receiver=*/1, attacker_signature);
  });
  honest.join();
  malicious.join();

  const bool exploit_success = all_success(exploit_rvs) && attacker_signature.size() == 64;
  const bool verifies_attacker = exploit_success && ed25519_verify(public_key, attacker_message, attacker_signature);
  const bool verifies_approved = exploit_success && ed25519_verify(public_key, approved_message, attacker_signature);

  auto control_net = std::make_shared<network_t>(2);
  auto c0 = std::make_shared<transport_t>(0, control_net);
  auto c1 = std::make_shared<transport_t>(1, control_net);
  buf_t control_honest_message = approved_message;
  buf_t control_malicious_message = attacker_message;
  buf_t honest_output, control_attacker_signature;
  std::vector<error_t> control_rvs(2, UNINITIALIZED_ERROR);
  std::thread control_honest([&] {
    job_mp_t job{0, online_names, *c0};
    control_rvs[0] = coinbase::api::eddsa_mp::sign_ac(job, key_blobs[0], ac, control_honest_message,
                                                       /*sig_receiver=*/1, honest_output);
  });
  std::thread control_malicious([&] {
    job_mp_t job{1, online_names, *c1};
    control_rvs[1] = coinbase::api::eddsa_mp::sign_ac(job, key_blobs[1], ac, control_malicious_message,
                                                       /*sig_receiver=*/1, control_attacker_signature);
  });
  control_honest.join();
  control_malicious.join();

  const bool control_rejected = !all_success(control_rvs) && control_attacker_signature.empty() &&
                                control_honest_message == approved_message;

  std::cout << "PUBLIC_ONLY_EDDSA_2OF3_ALIAS_POC"
            << " dkg_contributors=3 threshold=2of3 signing_online=2 offline=1"
            << " exploit_success=" << (exploit_success ? 1 : 0)
            << " attacker_received=" << (attacker_signature.size() == 64 ? 1 : 0)
            << " verifies_attacker_zero=" << (verifies_attacker ? 1 : 0)
            << " verifies_honest_approved=" << (verifies_approved ? 1 : 0)
            << " control_rejected=" << (control_rejected ? 1 : 0)
            << std::endl;

  if (exploit_success && verifies_attacker && !verifies_approved && control_rejected) {
    std::cout << "PUBLIC_ONLY_EDDSA_2OF3_UNAUTHORIZED_SIGNATURE_CONFIRMED=1" << std::endl;
    return 0;
  }
  std::cout << "PUBLIC_ONLY_EDDSA_2OF3_UNAUTHORIZED_SIGNATURE_CONFIRMED=0" << std::endl;
  return 1;
}
