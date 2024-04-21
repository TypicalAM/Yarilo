#include "net_card_manager.h"
#include "netlink/attr.h"
#include "netlink/genl/ctrl.h"
#include "netlink/genl/genl.h"
#include "netlink/handlers.h"
#include "netlink/msg.h"
#include "netlink/netlink.h"
#include <absl/strings/str_format.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <optional>
#include <stdexcept>

namespace yarilo {

void NetlinkCallback::attach(nl_recvmsg_msg_cb_t func, void *arg) {
  result = 1;
  callback = nl_cb_alloc(NL_CB_DEFAULT);
  if (!callback)
    throw std::runtime_error("Failed to allocate netlink callback");

  nl_cb_set(callback, NL_CB_VALID, NL_CB_CUSTOM, func, arg);
  nl_cb_err(callback, NL_CB_CUSTOM, error, &result);
  nl_cb_set(callback, NL_CB_FINISH, NL_CB_CUSTOM, finish, &result);
  nl_cb_set(callback, NL_CB_ACK, NL_CB_CUSTOM, ack, &result);
};

int NetlinkCallback::wait() {
  while (result > 0)
    nl_recvmsgs(sock, callback);
  return result;
}

int NetlinkCallback::finish(nl_msg *msg, void *arg) {
  auto ret = reinterpret_cast<int *>(arg);
  *ret = 0;
  return NL_SKIP;
}

int NetlinkCallback::error(sockaddr_nl *nla, nlmsgerr *err, void *arg) {
  int *ret = reinterpret_cast<int *>(arg);
  *ret = err->error;
  return NL_STOP;
}

int NetlinkCallback::ack(nl_msg *msg, void *arg) {
  int *ret = reinterpret_cast<int *>(arg);
  *ret = 0;
  return NL_STOP;
}

bool NetCardManager::connect() {
  sock = nl_socket_alloc();
  if (!sock) {
    log->error("Failed to allocate netlink socket.");
    return false;
  }

  nl_socket_set_buffer_size(sock, 8192, 8192);

  if (genl_connect(sock)) {
    log->error("Failed to connect to netlink socket.");
    nl_close(sock);
    nl_socket_free(sock);
    return false;
  }

  sock_id = genl_ctrl_resolve(sock, "nl80211");
  if (sock_id < 0) {
    log->error("nl80211 interface not found.");
    nl_close(sock);
    nl_socket_free(sock);
    return false;
  }

  return true;
}

void NetCardManager::disconnect() { nl_close(sock); }

std::set<std::string> NetCardManager::net_interfaces() {
  std::set<std::string> interfaces;
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
    interfaces.emplace(ifname);
  }

  return interfaces;
}

std::set<std::string> NetCardManager::phy_interfaces() {
  nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, sock_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
  nl_send_auto(sock, msg);

  std::set<std::string> phy_ifaces;
  NetlinkCallback callback(sock);
  callback.attach(phy_interfaces_callback, &phy_ifaces);
  callback.wait();

  nlmsg_free(msg);
  return phy_ifaces;
}

std::optional<phy_iface> NetCardManager::phy_details(std::string phy_name) {
  int idx = std::atoi(phy_name.substr(3, 4).c_str());
  nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, sock_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
  nla_put_u32(msg, NL80211_ATTR_WIPHY, idx);
  nl_send_auto(sock, msg);

  phy_iface result;
  NetlinkCallback callback(sock);
  callback.attach(phy_details_callback, &result);
  if (callback.wait())
    return std::nullopt;

  nlmsg_free(msg);
  return result;
}

std::optional<iface_state>
NetCardManager::net_iface_details(std::string ifname) {
  iface_state result{};
  result.logic_idx = if_nametoindex(ifname.c_str());

  nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, sock_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, result.logic_idx);
  nl_send_auto(sock, msg);

  NetlinkCallback callback(sock);
  callback.attach(net_iface_details_callback, &result);
  if (callback.wait())
    return std::nullopt; // ENODEV means no device info for this, loopback
                         // doesn't really have an active channel, does it?
  nlmsg_free(msg);
  return result;
}

bool NetCardManager::set_phy_channel(std::string phy_name, int chan) {
  int idx = std::atoi(phy_name.substr(3, 4).c_str());
  int freq = (chan == 14) ? 2484 : (chan - 1) * 5 + 2412;
  if (freq < 2412 || freq > 2484)
    return false;

  nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, sock_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
  nla_put_u32(msg, NL80211_ATTR_WIPHY, idx);
  nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
  nl_send_auto(sock, msg);

  NetlinkCallback callback(sock);
  callback.attach(net_iface_details_callback, nullptr);
  if (callback.wait())
    return false;

  nlmsg_free(msg);
  return true;
}

int NetCardManager::phy_interfaces_callback(nl_msg *msg, void *arg) {
  genlmsghdr *hdr = reinterpret_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
  nlattr *attrs[NL80211_ATTR_MAX + 1];
  nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0),
            genlmsg_attrlen(hdr, 0), NULL);

  std::string phy_name = "";
  if (attrs[NL80211_ATTR_WIPHY_NAME])
    phy_name = nla_get_string(attrs[NL80211_ATTR_WIPHY_NAME]);

  auto iface_ids = reinterpret_cast<std::set<std::string> *>(arg);
  iface_ids->emplace(phy_name);
  return NL_SKIP;
}

int NetCardManager::phy_details_callback(nl_msg *msg, void *arg) {
  genlmsghdr *hdr = reinterpret_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
  nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
      {NLA_UNSPEC, 0, 0}, /* __NL80211_FREQUENCY_ATTR_INVALID */
      {NLA_U32, 0, 0},    /* NL80211_FREQUENCY_ATTR_FREQ */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_DISABLED */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_PASSIVE_SCAN */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_NO_IBSS */
      {NLA_FLAG, 0, 0},   /* NL80211_FREQUENCY_ATTR_RADAR */
      {NLA_U32, 0, 0}     /* NL80211_FREQUENCY_ATTR_MAX_TX_POWER */
  };

  nlattr *attrs[NL80211_ATTR_MAX + 1];
  nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0),
            genlmsg_attrlen(hdr, 0), NULL);

  bool cap_monitor = false;
  phy_iface iface{};
  iface.can_set_freq = true; // TODO: Correct this
  iface.channel_opts = 1 << ChannelModes::NO_HT;

  if (attrs[NL80211_ATTR_WIPHY_NAME])
    iface.ifname = std::string(nla_get_string(attrs[NL80211_ATTR_WIPHY_NAME]));

  int rem_mode;
  nlattr *nl_mode;
  if (attrs[NL80211_ATTR_SUPPORTED_IFTYPES]) {
    nla_for_each_nested(nl_mode, attrs[NL80211_ATTR_SUPPORTED_IFTYPES],
                        rem_mode) {
      if (nla_type(nl_mode) == NL80211_IFTYPE_MONITOR)
        iface.can_monitor = true;
    }
  }

  if (!attrs[NL80211_ATTR_WIPHY_BANDS])
    return NL_SKIP;

  int rem_band;
  nlattr *nl_band;
  nla_for_each_nested(nl_band, attrs[NL80211_ATTR_WIPHY_BANDS], rem_band) {
    nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, (nlattr *)nla_data(nl_band),
              nla_len(nl_band), NULL);

    if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
      iface.channel_opts |= 1 << ChannelModes::HT20;
      if (nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]) & 0x02) {
        iface.channel_opts |= 1 << ChannelModes::HT40MINUS;
        iface.channel_opts |= 1 << ChannelModes::HT40PLUS;
      }
    }

    int rem_freq;
    nlattr *nl_freq;
    nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
      nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
      nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
                (nlattr *)nla_data(nl_freq), nla_len(nl_freq), freq_policy);

      uint32_t freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
      if (freq == 0 || tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
        continue;

      iface.frequencies.emplace(freq);
    }
  }

  auto phy_iface = reinterpret_cast<struct phy_iface *>(arg);
  *phy_iface = iface;
  return NL_SKIP;
}

int NetCardManager::net_iface_details_callback(nl_msg *msg, void *arg) {
  auto *hdr = reinterpret_cast<genlmsghdr *>(nlmsg_data(nlmsg_hdr(msg)));
  auto *iface_info = reinterpret_cast<iface_state *>(arg);

  nlattr *attrs[NL80211_ATTR_MAX + 1];
  nla_parse(attrs, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0),
            genlmsg_attrlen(hdr, 0), NULL);

  if (attrs[NL80211_ATTR_IFTYPE])
    iface_info->type = nla_get_u32(attrs[NL80211_ATTR_IFTYPE]);
  if (attrs[NL80211_ATTR_WIPHY])
    iface_info->phy_idx = nla_get_u32(attrs[NL80211_ATTR_WIPHY]);

  if (attrs[NL80211_ATTR_WIPHY_FREQ]) {
    iface_info->freq = nla_get_u32(attrs[NL80211_ATTR_WIPHY_FREQ]);
    iface_info->chan_type = ChannelModes::NO_HT;

    if (attrs[NL80211_ATTR_WIPHY_CHANNEL_TYPE])
      switch (nla_get_u32(attrs[NL80211_ATTR_WIPHY_CHANNEL_TYPE])) {

      case NL80211_CHAN_NO_HT:
        iface_info->chan_type = ChannelModes::NO_HT;
        break;

      case NL80211_CHAN_HT20:
        iface_info->chan_type = ChannelModes::HT20;
        break;

      case NL80211_CHAN_HT40MINUS:
        iface_info->chan_type = ChannelModes::HT40MINUS;
        break;

      case NL80211_CHAN_HT40PLUS:
        iface_info->chan_type = ChannelModes::HT40PLUS;
        break;
      }
  }

  return NL_SKIP;
}

int NetCardManager::set_phy_channel_callback(nl_msg *msg, void *arg) {
  return 0;
}

} // namespace yarilo
