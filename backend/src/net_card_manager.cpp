#include "net_card_manager.h"
#include "netlink/attr.h"
#include "netlink/genl/ctrl.h"
#include "netlink/genl/genl.h"
#include "netlink/handlers.h"
#include "netlink/netlink.h"
#include <absl/strings/str_format.h>
#include <cstdio>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <linux/nl80211.h>
#include <memory>
#include <net/if.h>
#include <optional>
#include <sstream>
#include <stdexcept>

int temp_finish_handler(nl_msg *msg, void *arg) {
  auto ret = reinterpret_cast<int *>(arg);
  *ret = 0;
  return NL_SKIP;
}

int temp_error_handler(sockaddr_nl *nla, nlmsgerr *err, void *arg) {
  int *ret = reinterpret_cast<int *>(arg);
  *ret = err->error;
  return NL_STOP;
}

int temp_ack_handler(nl_msg *msg, void *arg) {
  int *ret = reinterpret_cast<int *>(arg);
  *ret = 0;
  return NL_STOP;
}

void NetlinkCallback::attach(nl_recvmsg_msg_cb_t func, void *arg) {
  this->result = 1;
  this->callback = nl_cb_alloc(NL_CB_DEFAULT);
  if (!this->callback)
    throw std::runtime_error("Failed to allocate netlink callback");

  nl_cb_set(this->callback, NL_CB_VALID, NL_CB_CUSTOM, func, arg);

  nl_cb_err(this->callback, NL_CB_CUSTOM, temp_error_handler, &(this->result));
  nl_cb_set(this->callback, NL_CB_FINISH, NL_CB_CUSTOM, temp_finish_handler,
            &(this->result));
  nl_cb_set(this->callback, NL_CB_ACK, NL_CB_CUSTOM, temp_ack_handler,
            &(this->result));
};

int NetlinkCallback::wait() {
  while (result > 0)
    nl_recvmsgs(sock, callback);
  return result;
}

bool NetCardManager::connect() {
  this->sock = nl_socket_alloc();
  if (!this->sock) {
    fprintf(stderr, "Failed to allocate netlink socket.\n");
    return false;
  }

  nl_socket_set_buffer_size(this->sock, 8192, 8192);

  if (genl_connect(this->sock)) {
    fprintf(stderr, "Failed to connect to netlink socket.\n");
    nl_close(this->sock);
    nl_socket_free(this->sock);
    return false;
  }

  this->sock_id = genl_ctrl_resolve(this->sock, "nl80211");
  if (this->sock_id < 0) {
    fprintf(stderr, "Nl80211 interface not found.\n");
    nl_close(this->sock);
    nl_socket_free(this->sock);
    return false;
  }

  return true;
}

void NetCardManager::disconnect() { nl_close(this->sock); }

// returns all interfaces in /proc/net/dev
std::vector<std::string> NetCardManager::iface_names() {
  std::vector<std::string> result;
  std::ifstream file("/proc/net/dev");
  std::string line;

  // Skip the first two lines (column desc)
  for (int i = 0; i < 2; i++)
    std::getline(file, line);

  // extract iface names from "   lo:  245423    1307    0    0    0     0
  // [...]"
  while (std::getline(file, line)) {
    std::string ifname = line.substr(0, line.find(':'));
    int last_space = ifname.rfind(' ');
    if (last_space != std::string::npos)
      ifname = ifname.substr(last_space + 1, ifname.length());
    result.push_back(ifname);
  }

  return result;
}

std::vector<iface *> NetCardManager::available_phys() {
  nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, this->sock_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY,
              0);
  nl_send_auto(this->sock, msg);

  std::vector<iface *> result;
  NetlinkCallback callback(this->sock);
  callback.attach(available_phys_callback, &result);
  callback.wait();
  nlmsg_free(msg);
  return result;
}

int NetCardManager::available_phys_callback(nl_msg *msg, void *arg) {
  nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
      {NLA_UNSPEC, 0, 0}, /* __NL80211_FREQUENCY_ATTR_INVALID */
      {NLA_U32, 0, 0},    /* NL80211_FREQUENCY_ATTR_FREQ */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_DISABLED */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_PASSIVE_SCAN */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_NO_IBSS */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_RADAR */
      {NLA_U32, 0, 0}     /* NL80211_FREQUENCY_ATTR_MAX_TX_POWER */
  };

  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
    return NL_SKIP;

  bool cap_monitor = false;
  int rem_mode;
  nlattr *nl_mode;
  if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
    nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES],
                        rem_mode) {
      if (nla_type(nl_mode) == NL80211_IFTYPE_MONITOR)
        cap_monitor = true;
    }
  }

  if (!cap_monitor)
    return NL_SKIP; // We skip every interface which cannot support rfmon

  auto *tralala = new iface;
  tralala->monitor = true;
  tralala->frequencies = std::vector<uint32_t>();
  tralala->channel_attrs = 1 << ChannelTypes::NO_HT;

  if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
    char *test = nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]);
    std::string formatted = absl::StrFormat("%s.mon", test);
    tralala->ifname = formatted;
  }

  nlattr *nl_band;
  int rem_band;
  nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
    nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, (nlattr *)nla_data(nl_band),
              nla_len(nl_band), NULL);

    if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
      tralala->channel_attrs |= 1 << ChannelTypes::HT20;
      if (nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]) & 0x02) {
        tralala->channel_attrs |= 1 << ChannelTypes::HT40MINUS;
        tralala->channel_attrs |= 1 << ChannelTypes::HT40PLUS;
      }
    }

    nlattr *nl_freq;
    int rem_freq;
    nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
      nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
      nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
                (nlattr *)nla_data(nl_freq), nla_len(nl_freq), freq_policy);

      uint32_t freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
      if (freq == 0 || tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
        continue;

      tralala->frequencies.push_back(freq);
    }
  }

  tralala->can_set_freq = true;
  auto ifaces = reinterpret_cast<std::vector<iface *> *>(arg);
  ifaces->push_back(tralala);
  return NL_SKIP;
}

std::optional<iface_state *> NetCardManager::details(std::string ifname) {
  nl_msg *msg = nlmsg_alloc();
  log->info("Getting logical interface details for name: {}, index: {}", ifname,
            if_nametoindex(ifname.c_str()));
  genlmsg_put(msg, 0, 0, this->sock_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname.c_str()));
  nl_send_auto(this->sock, msg);

  auto result = std::make_unique<iface_state_fetcher>();
  auto pub = std::make_unique<iface_state>();
  result->pub = pub.get();

  NetlinkCallback callback(this->sock);
  callback.attach(details_callback, result.get());
  if (callback.wait())
    return std::nullopt; // ENODEV means no device info for this, loopback
                         // doesn't really have an active channel, does it?
  nlmsg_free(msg);
  return pub.release();
}

int NetCardManager::details_callback(nl_msg *msg, void *arg) {
  auto *gnlh = reinterpret_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
  auto *iface_info = reinterpret_cast<iface_state_fetcher *>(arg);

  nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (tb_msg[NL80211_ATTR_IFTYPE])
    iface_info->type = nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);
  if (tb_msg[NL80211_ATTR_WIPHY])
    iface_info->phy_idx = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);

  if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
    iface_info->pub->freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
    iface_info->pub->chan_type = ChannelTypes::NO_HT;

    if (tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE])
      switch (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE])) {

      case NL80211_CHAN_NO_HT:
        iface_info->pub->chan_type = ChannelTypes::NO_HT;
        break;

      case NL80211_CHAN_HT20:
        iface_info->pub->chan_type = ChannelTypes::HT20;
        break;

      case NL80211_CHAN_HT40MINUS:
        iface_info->pub->chan_type = ChannelTypes::HT40MINUS;
        break;

      case NL80211_CHAN_HT40PLUS:
        iface_info->pub->chan_type = ChannelTypes::HT40PLUS;
        break;
      }
  }

  return NL_SKIP;
}

void NetCardManager::test() {
  auto ifs = available_phys();
  for (const auto haha : ifs) {
    log->info(haha->ifname);
    log->info(
        "Physical interface: {}, supports {} frequencies and monitor mode: {}",
        haha->ifname, haha->frequencies.size(), haha->monitor);
    std::stringstream ss;
    for (const auto freq : haha->frequencies)
      ss << freq << " ";
    log->info(ss.str());
  }

  auto ifnames = iface_names();
  for (const auto ifname : ifnames) {
    log->info("Logical intarface with name: {}", ifname);
    auto details = this->details(ifname);
    if (details.has_value()) {
      log->info("Its frequency currently is set to {} ", details.value()->freq);
    }
  }
};
