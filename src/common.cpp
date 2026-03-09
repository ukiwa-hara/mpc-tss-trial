#include "common.h"

// 必要な変数の実体は、ここで各1回ずつ定義します
std::set<std::string> processed_ids; // ← これを1つだけに！

std::vector<std::string> GlobalPartyIDs = {"co_signer1", "co_signer2", "co_signer3"};
std::vector<Msg> msg_queue;
std::vector<Msg> msg_buffer;