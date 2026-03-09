#pragma once
#include <string>
#include <vector>
#include <set>

// 変数の「宣言」のみを行う (extern を付ける)
extern std::set<std::string> processed_ids;

// 共通構造体
struct Msg
{
    std::string id_; // UUIDや連番を追加
    std::string src_;
    std::string bc_msg_;
    std::string p2p_msg_;
    int round_;
};

// --- 関数宣言（これらを各 .cpp で実装し、main.cpp から呼ぶ） ---

// 通信用
void send_msg(const std::string &src, const std::string &dest, const std::string &bc, const std::string &p2p, int round);
std::vector<Msg> recv_msg(const std::string &party_id);

// 実行ロジック
void run_keygen_logic(const std::string &party_id);
void run_signing_logic(const std::string &party_id, const std::string &my_id, const std::string &hash, const std::vector<std::string> &participants);
void run_refresh_logic(const std::string &party_id, const std::vector<std::string> &participants);