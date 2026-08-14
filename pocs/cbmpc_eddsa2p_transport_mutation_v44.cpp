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

struct channel_t {
  std::mutex m;
  std::condition_variable cv;
  std::deque<buf_t> q;
};

struct network_t {
  channel_t ch[2][2];
  std::mutex state_m;
  bool cancelled = false;
  bool mutate = false;
  int target_p2_to_p1_send = -1;
  int mutation_kind = -1;
  int p2_to_p1_count = 0;

  void cancel() {
    {
      std::lock_guard<std::mutex> lock(state_m);
      cancelled = true;
    }
    for (int i = 0; i < 2; ++i)
      for (int j = 0; j < 2; ++j) ch[i][j].cv.notify_all();
  }

  bool is_cancelled() {
    std::lock_guard<std::mutex> lock(state_m);
    return cancelled;
  }
};

static buf_t mutate_payload(mem_t msg, int kind) {
  buf_t out(msg);
  if (out.empty()) return out;
  switch (kind) {
    case 0:  // truncate one byte
      out.resize(std::max(1, out.size() - 1));
      break;
    case 1:  // truncate to half
      out.resize(std::max(1, out.size() / 2));
      break;
    case 2:  // flip the first byte
      out[0] ^= 0xff;
      break;
    case 3:  // force a large-looking leading length/marker byte
      out[0] = 0xff;
      break;
    case 4: {  // append junk; strict deserializers should reject trailing bytes
      const int old = out.size();
      out.resize(old + 32);
      for (int i = old; i < out.size(); ++i) out[i] = static_cast<uint8_t>(0xa5 ^ i);
      break;
    }
    case 5:  // all zero
      out.bzero();
      break;
    case 6:  // one-byte packet
      out.resize(1);
      out[0] = 0xff;
      break;
    case 7: {  // perturb bytes around common short length prefixes
      const int lim = std::min(out.size(), 16);
      for (int i = 0; i < lim; ++i) out[i] ^= static_cast<uint8_t>(0x80u >> (i % 8));
      break;
    }
    default:
      break;
  }
  return out;
}

class transport_t final : public data_transport_i {
 public:
  transport_t(int self, std::shared_ptr<network_t> net) : self_(self), net_(std::move(net)) {}

  error_t send(party_idx_t receiver, mem_t msg) override {
    if (receiver < 0 || receiver > 1 || receiver == self_) return E_BADARG;
    if (net_->is_cancelled()) return E_NET_GENERAL;

    buf_t payload(msg);
    if (self_ == 1 && receiver == 0 && net_->mutate) {
      int ordinal;
      {
        std::lock_guard<std::mutex> lock(net_->state_m);
        ordinal = ++net_->p2_to_p1_count;
      }
      if (ordinal == net_->target_p2_to_p1_send) {
        payload = mutate_payload(msg, net_->mutation_kind);
        std::cout << "V44_MUTATED p2_to_p1_send=" << ordinal
                  << " kind=" << net_->mutation_kind
                  << " original_size=" << msg.size
                  << " mutated_size=" << payload.size() << std::endl;
      }
    }

    auto& c = net_->ch[self_][receiver];
    {
      std::lock_guard<std::mutex> lock(c.m);
      c.q.emplace_back(std::move(payload));
    }
    c.cv.notify_one();
    return SUCCESS;
  }

  error_t receive(party_idx_t sender, buf_t& msg) override {
    if (sender < 0 || sender > 1 || sender == self_) return E_BADARG;
    auto& c = net_->ch[sender][self_];
    std::unique_lock<std::mutex> lock(c.m);
    const bool ready = c.cv.wait_for(lock, std::chrono::seconds(8), [&] {
      return !c.q.empty() || net_->is_cancelled();
    });
    if (!ready || c.q.empty()) return E_NET_GENERAL;
    msg = std::move(c.q.front());
    c.q.pop_front();
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

static std::array<error_t, 2> run_dkg(std::array<buf_t, 2>& keys) {
  auto net = std::make_shared<network_t>();
  auto t0 = std::make_shared<transport_t>(0, net);
  auto t1 = std::make_shared<transport_t>(1, net);
  std::array<error_t, 2> rv = {UNINITIALIZED_ERROR, UNINITIALIZED_ERROR};

  std::thread p1([&] {
    coinbase::api::job_2p_t job{party_2p_t::p1, "p1", "p2", *t0};
    rv[0] = coinbase::api::eddsa_2p::dkg(job, curve_id::ed25519, keys[0]);
    if (rv[0] != SUCCESS) net->cancel();
  });
  std::thread p2([&] {
    coinbase::api::job_2p_t job{party_2p_t::p2, "p1", "p2", *t1};
    rv[1] = coinbase::api::eddsa_2p::dkg(job, curve_id::ed25519, keys[1]);
    if (rv[1] != SUCCESS) net->cancel();
  });
  p1.join();
  p2.join();
  return rv;
}

struct sign_result_t {
  error_t p1 = UNINITIALIZED_ERROR;
  error_t p2 = UNINITIALIZED_ERROR;
  int sig_size = 0;
  int observed_p2_to_p1_sends = 0;
};

static sign_result_t run_sign(const std::array<buf_t, 2>& keys, bool mutate, int send_ordinal, int kind) {
  auto net = std::make_shared<network_t>();
  net->mutate = mutate;
  net->target_p2_to_p1_send = send_ordinal;
  net->mutation_kind = kind;

  auto t0 = std::make_shared<transport_t>(0, net);
  auto t1 = std::make_shared<transport_t>(1, net);
  std::array<uint8_t, 64> msg_bytes{};
  for (size_t i = 0; i < msg_bytes.size(); ++i) msg_bytes[i] = static_cast<uint8_t>(0x40 + (i % 31));
  mem_t msg(msg_bytes.data(), static_cast<int>(msg_bytes.size()));

  buf_t sig0, sig1;
  sign_result_t result;
  std::thread p1([&] {
    coinbase::api::job_2p_t job{party_2p_t::p1, "p1", "p2", *t0};
    result.p1 = coinbase::api::eddsa_2p::sign(job, keys[0], msg, sig0);
    if (result.p1 != SUCCESS) net->cancel();
  });
  std::thread p2([&] {
    coinbase::api::job_2p_t job{party_2p_t::p2, "p1", "p2", *t1};
    result.p2 = coinbase::api::eddsa_2p::sign(job, keys[1], msg, sig1);
    if (result.p2 != SUCCESS) net->cancel();
  });
  p1.join();
  p2.join();
  result.sig_size = sig0.size();
  result.observed_p2_to_p1_sends = net->p2_to_p1_count;
  return result;
}

}  // namespace

int main() {
  std::array<buf_t, 2> keys;
  auto dkg = run_dkg(keys);
  if (dkg[0] != SUCCESS || dkg[1] != SUCCESS) {
    std::cout << "V44_DKG_FAILED rv0=" << dkg[0] << " rv1=" << dkg[1] << std::endl;
    return 2;
  }

  const auto control = run_sign(keys, false, -1, -1);
  const bool control_ok = control.p1 == SUCCESS && control.p2 == SUCCESS && control.sig_size == 64;
  std::cout << "V44_CONTROL p1=" << control.p1 << " p2=" << control.p2
            << " sig_size=" << control.sig_size
            << " p2_to_p1_sends=" << control.observed_p2_to_p1_sends
            << " ok=" << control_ok << std::endl;
  if (!control_ok) return 3;

  int cases = 0;
  int rejected = 0;
  int unexpected_success = 0;
  // Probe every observed P2->P1 send with several raw-wire mutations.
  for (int ordinal = 1; ordinal <= control.observed_p2_to_p1_sends; ++ordinal) {
    for (int kind = 0; kind <= 7; ++kind) {
      ++cases;
      const auto r = run_sign(keys, true, ordinal, kind);
      const bool both_success = r.p1 == SUCCESS && r.p2 == SUCCESS;
      if (both_success) ++unexpected_success;
      else ++rejected;
      std::cout << "V44_CASE ordinal=" << ordinal << " kind=" << kind
                << " p1=" << r.p1 << " p2=" << r.p2
                << " sig_size=" << r.sig_size
                << " both_success=" << both_success << std::endl;
    }
  }

  std::cout << "V44_EDDSA2P_MALFORMED_TRANSPORT_SUMMARY cases=" << cases
            << " rejected=" << rejected
            << " unexpected_success=" << unexpected_success << std::endl;
  std::cout << "V44_SANITIZER_COMPLETED_WITHOUT_MEMORY_ERROR=1" << std::endl;
  return 0;
}
