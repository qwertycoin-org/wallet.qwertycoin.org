#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "qms/protocol.h"

namespace
{
  qwertycoin::qms::bytes unhex(const std::string& value)
  {
    if (value.size() % 2) throw std::runtime_error("odd hex input");
    qwertycoin::qms::bytes result(value.size() / 2);
    const auto digit = [](char value) -> uint8_t {
      if (value >= '0' && value <= '9') return uint8_t(value - '0');
      value = char(std::tolower(static_cast<unsigned char>(value)));
      if (value >= 'a' && value <= 'f') return uint8_t(value - 'a' + 10);
      throw std::runtime_error("invalid hex input");
    };
    for (size_t index = 0; index != result.size(); ++index)
      result[index] = uint8_t((digit(value[index * 2]) << 4) | digit(value[index * 2 + 1]));
    return result;
  }

  template<size_t N> std::array<uint8_t, N> fixed(const std::string& value)
  {
    const auto decoded = unhex(value);
    if (decoded.size() != N) throw std::runtime_error("invalid fixed-size input");
    std::array<uint8_t, N> result{};
    std::copy(decoded.begin(), decoded.end(), result.begin());
    return result;
  }

  std::vector<std::string> lines(const std::string& path)
  {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("unable to open fixture");
    std::vector<std::string> result;
    for (std::string line; std::getline(input, line);) result.push_back(line);
    return result;
  }
}

int main(int argc, char** argv)
{
  try
  {
    if (argc != 3) throw std::runtime_error("usage: probe INPUT OUTPUT");
    const auto input = lines(argv[1]);
    if (input.size() != 10) throw std::runtime_error("invalid fixture field count");
    qwertycoin::qms::identity recipient;
    recipient.box_public = fixed<32>(input[0]);
    recipient.box_secret = fixed<32>(input[1]);
    recipient.sign_public = fixed<32>(input[2]);
    recipient.sign_secret = fixed<64>(input[3]);
    const auto sender_invitation = qwertycoin::qms::decode_invitation(unhex(input[4]));
    const auto recipient_invitation = qwertycoin::qms::decode_invitation(unhex(input[5]));
    const auto genesis = fixed<32>(input[6]);
    const auto web_message_id = fixed<16>(input[7]);
    const auto web_fragments = qwertycoin::qms::extract_carrier_fragments(unhex(input[8]));
    if (web_fragments.size() != 1 || !qwertycoin::qms::verify_fragment(recipient_invitation, genesis, web_fragments.front()))
      throw std::runtime_error("Web carrier failed Core verification");
    const auto opened = qwertycoin::qms::open_text(
      recipient, sender_invitation, recipient_invitation, genesis,
      web_message_id, qwertycoin::qms::reassemble(web_fragments));
    if (opened.text != "Web to Core QMS1") throw std::runtime_error("Core opened unexpected Web text");

    const auto reply_message_id = fixed<16>(input[9]);
    const auto reply_ciphertext = qwertycoin::qms::seal_text(
      recipient, sender_invitation, genesis, reply_message_id, "Core to Web QMS1");
    const auto reply_fragments = qwertycoin::qms::fragment_ciphertext(
      sender_invitation, genesis, reply_message_id, reply_ciphertext);
    if (reply_fragments.size() != 1) throw std::runtime_error("Core reply was not compact");
    qwertycoin::qms::bytes reply_extra;
    if (!qwertycoin::qms::append_carrier_nonces(reply_extra, reply_fragments.front()))
      throw std::runtime_error("Core failed to encode reply carrier");
    std::ofstream output(argv[2], std::ios::trunc);
    if (!output) throw std::runtime_error("unable to open result");
    output << qwertycoin::qms::hex(reply_extra) << '\n';
    return 0;
  }
  catch (const std::exception& error)
  {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
