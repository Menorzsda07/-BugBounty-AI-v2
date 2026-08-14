#include <array>
#include <iostream>
#include <map>
#include <string_view>
#include <vector>

#include <cbmpc/api/pve_base_pke.h>
#include <cbmpc/api/pve_batch_ac.h>
#include <cbmpc/core/access_structure.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::mem_t;
using coinbase::api::curve_id;
using coinbase::api::access_structure_t;

namespace {

class toy_base_pke_t final : public coinbase::api::pve::base_pke_i {
 public:
  error_t encrypt(mem_t, mem_t, mem_t plain, mem_t, buf_t& out_ct) const override {
    out_ct = buf_t(plain);
    return SUCCESS;
  }
  error_t decrypt(mem_t, mem_t, mem_t ct, buf_t& out_plain) const override {
    out_plain = buf_t(ct);
    return SUCCESS;
  }
};

bool exact_one(const std::vector<buf_t>& xs, const buf_t& expected) {
  return xs.size() == 1 && xs[0] == expected;
}

struct result_t {
  error_t rv = UNINITIALIZED_ERROR;
  bool recovered = false;
};

result_t combine_case(const toy_base_pke_t& pke, curve_id curve, const access_structure_t& ac, mem_t ct,
                      int attempt, mem_t label, const coinbase::api::pve::leaf_shares_t& shares,
                      const buf_t& expected) {
  std::vector<buf_t> out;
  result_t r;
  r.rv = coinbase::api::pve::combine_ac(pke, curve, ac, ct, attempt, label, shares, out);
  r.recovered = (r.rv == SUCCESS) && exact_one(out, expected);
  return r;
}

}  // namespace

int main() {
  const toy_base_pke_t pke;
  const curve_id curve = curve_id::secp256k1;
  const buf_t label = buf_t("v43-label");
  const buf_t wrong_label = buf_t("v43-other-label");

  const access_structure_t ac = access_structure_t::Threshold(
      2, {access_structure_t::leaf("p1"), access_structure_t::leaf("p2"), access_structure_t::leaf("p3")});

  std::array<uint8_t, 32> xbytes{};
  for (size_t i = 0; i < xbytes.size(); ++i) xbytes[i] = static_cast<uint8_t>(0x31 + (i % 17));
  const buf_t expected(xbytes.data(), static_cast<int>(xbytes.size()));
  std::vector<mem_t> xs = {mem_t(xbytes.data(), static_cast<int>(xbytes.size()))};

  const buf_t dummy1 = buf_t("k1");
  const buf_t dummy2 = buf_t("k2");
  const buf_t dummy3 = buf_t("k3");
  coinbase::api::pve::leaf_keys_t pks;
  pks.emplace("p1", mem_t(dummy1));
  pks.emplace("p2", mem_t(dummy2));
  pks.emplace("p3", mem_t(dummy3));

  buf_t ct;
  error_t rv = coinbase::api::pve::encrypt_ac(pke, curve, ac, pks, label, xs, ct);
  if (rv != SUCCESS) {
    std::cout << "V43_SETUP_FAILED encrypt_rv=" << rv << std::endl;
    return 2;
  }

  buf_t s1_0, s2_0, s3_0, s2_1;
  rv = coinbase::api::pve::partial_decrypt_ac_attempt(pke, curve, ac, ct, 0, "p1", mem_t(dummy1), label, s1_0);
  if (rv != SUCCESS) return 3;
  rv = coinbase::api::pve::partial_decrypt_ac_attempt(pke, curve, ac, ct, 0, "p2", mem_t(dummy2), label, s2_0);
  if (rv != SUCCESS) return 4;
  rv = coinbase::api::pve::partial_decrypt_ac_attempt(pke, curve, ac, ct, 0, "p3", mem_t(dummy3), label, s3_0);
  if (rv != SUCCESS) return 5;
  rv = coinbase::api::pve::partial_decrypt_ac_attempt(pke, curve, ac, ct, 1, "p2", mem_t(dummy2), label, s2_1);
  if (rv != SUCCESS) return 6;

  coinbase::api::pve::leaf_shares_t normal;
  normal.emplace("p1", mem_t(s1_0));
  normal.emplace("p2", mem_t(s2_0));
  result_t normal_r = combine_case(pke, curve, ac, ct, 0, label, normal, expected);

  coinbase::api::pve::leaf_shares_t insufficient;
  insufficient.emplace("p1", mem_t(s1_0));
  result_t insufficient_r = combine_case(pke, curve, ac, ct, 0, label, insufficient, expected);

  coinbase::api::pve::leaf_shares_t dup12;
  dup12.emplace("p1", mem_t(s1_0));
  dup12.emplace("p2", mem_t(s1_0));
  result_t dup12_r = combine_case(pke, curve, ac, ct, 0, label, dup12, expected);

  coinbase::api::pve::leaf_shares_t dup13;
  dup13.emplace("p1", mem_t(s1_0));
  dup13.emplace("p3", mem_t(s1_0));
  result_t dup13_r = combine_case(pke, curve, ac, ct, 0, label, dup13, expected);

  coinbase::api::pve::leaf_shares_t relabel23;
  relabel23.emplace("p2", mem_t(s1_0));
  relabel23.emplace("p3", mem_t(s1_0));
  result_t relabel23_r = combine_case(pke, curve, ac, ct, 0, label, relabel23, expected);

  coinbase::api::pve::leaf_shares_t cross_attempt;
  cross_attempt.emplace("p1", mem_t(s1_0));
  cross_attempt.emplace("p2", mem_t(s2_1));
  result_t cross_r = combine_case(pke, curve, ac, ct, 0, label, cross_attempt, expected);

  result_t wrong_label_r = combine_case(pke, curve, ac, ct, 0, wrong_label, normal, expected);

  const bool bypass = dup12_r.recovered || dup13_r.recovered || relabel23_r.recovered ||
                      cross_r.recovered || insufficient_r.recovered || wrong_label_r.recovered;
  const bool controls_ok = normal_r.recovered && !insufficient_r.recovered && !cross_r.recovered &&
                           !wrong_label_r.recovered;

  std::cout << "V43_PVE_QUORUM_PROBE"
            << " normal=" << normal_r.recovered
            << " insufficient=" << insufficient_r.recovered
            << " dup12=" << dup12_r.recovered
            << " dup13=" << dup13_r.recovered
            << " relabel23=" << relabel23_r.recovered
            << " cross_attempt=" << cross_r.recovered
            << " wrong_label=" << wrong_label_r.recovered
            << " controls_ok=" << controls_ok
            << std::endl;

  std::cout << "V43_PVE_THRESHOLD_BYPASS_CANDIDATE=" << (bypass ? 1 : 0) << std::endl;
  return (normal_r.recovered && !bypass) ? 0 : 1;
}
