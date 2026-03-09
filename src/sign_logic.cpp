#include "common.h"

#include <iostream>
#include <vector>
#include <string>
#include <set>
#include "httplib.h"
#include "json.hpp"
#include "multi-party-sig/multi-party-ecdsa/gg18/gg18.h"

using json = nlohmann::json;
using safeheron::bignum::BN;
using safeheron::multi_party_ecdsa::gg18::sign::Context;

// 受信済みだが、まだ使っていない「未来のメッセージ」を保管するバッファ
static std::vector<Msg> msg_buffer;

std::string load_key(const std::string &filename)
{
    std::ifstream f(filename);
    std::string content;
    if (f)
        f >> content;
    return content;
}

// 共通のラウンド実行ロジック
// void run_round_network(Context *ctx_ptr, const std::string &party_id, int round_index, int expected_count)
// {
//     // 1. そのラウンドの最初に自分のメッセージを生成・送信
//     if (round_index == 0)
//         ctx_ptr->PushMessage();

//     std::vector<std::string> out_p2p, out_des;
//     std::string out_bc;
//     ctx_ptr->PopMessages(out_p2p, out_bc, out_des);

//     for (size_t k = 0; k < out_des.size(); ++k)
//     {
//         send_msg(party_id, out_des[k], out_bc, out_p2p.empty() ? "" : out_p2p[k], round_index);
//     }

//     std::set<std::string> received_from;

//     // 2. まず「バッファ」の中に、今のラウンドで使えるメッセージがないか確認
//     auto it = msg_buffer.begin();
//     while (it != msg_buffer.end())
//     {
//         if (it->round_ == round_index)
//         {
//             ctx_ptr->PushMessage(it->p2p_msg_, it->bc_msg_, it->src_, round_index);
//             received_from.insert(it->src_);
//             it = msg_buffer.erase(it); // 使ったメッセージは消す
//         }
//         else
//         {
//             ++it;
//         }
//     }

//     // 3. 全員分揃うまで通信を監視
//     // 3. 通信を監視
//     while (received_from.size() < (size_t)expected_count - 1)
//     {
//         auto msgs = recv_msg(party_id);
//         for (auto &m : msgs)
//         {
//             if (m.src_ == party_id)
//                 continue;

//             if (m.round_ == round_index)
//             {
//                 // すでにこの人からこのラウンドのメッセージをもらっていたら無視
//                 if (received_from.find(m.src_) != received_from.end())
//                     continue;

//                 ctx_ptr->PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, round_index);
//                 received_from.insert(m.src_);
//                 std::cout << "[" << party_id << "] OK: Round " << round_index << " from " << m.src_ << " (Total: " << received_from.size() << ")" << std::endl;
//             }
//             else if (m.round_ > round_index)
//             {
//                 // 重複チェック付きでバッファへ
//                 bool already_buffered = false;
//                 for (const auto &b : msg_buffer)
//                 {
//                     if (b.src_ == m.src_ && b.round_ == m.round_)
//                     {
//                         already_buffered = true;
//                         break;
//                     }
//                 }
//                 if (!already_buffered)
//                     msg_buffer.push_back(m);
//             }
//         }

//         if (ctx_ptr->IsCurRoundFinished())
//             break;
//         std::this_thread::sleep_for(std::chrono::milliseconds(100));
//     }
// }

void run_round_network(Context *ctx_ptr, const std::string &party_id, int round_index, int expected_count)
{
    std::set<std::string> received_from;

    // 1. メッセージ送信
    if (round_index == 0)
        ctx_ptr->PushMessage();

    std::vector<std::string> out_p2p, out_des;
    std::string out_bc;
    ctx_ptr->PopMessages(out_p2p, out_bc, out_des);

    for (size_t k = 0; k < out_des.size(); ++k)
    {
        send_msg(party_id, out_des[k], out_bc, out_p2p.empty() ? "" : out_p2p[k], round_index);
    }

    // 2. バッファからの回収（バッファ内のメッセージは既にIDフィルタ済みとみなす）
    auto it = msg_buffer.begin();
    while (it != msg_buffer.end())
    {
        if (it->round_ == round_index)
        {
            if (ctx_ptr->PushMessage(it->p2p_msg_, it->bc_msg_, it->src_, it->round_))
            {
                processed_ids.insert(it->id_); // 成功時に確定
                received_from.insert(it->src_);
                it = msg_buffer.erase(it);
                continue;
            }
        }
        ++it;
    }

    // 3. 通信監視
    while (received_from.size() < (size_t)expected_count - 1)
    {
        auto msgs = recv_msg(party_id); // ここで既に重複排除済みの新鮮なデータが届く
        for (auto &m : msgs)
        {
            if (m.src_ == party_id)
                continue;

            if (m.round_ == round_index)
            {
                if (received_from.find(m.src_) == received_from.end())
                {
                    // ID確認（念のための二重チェック）
                    if (processed_ids.count(m.id_))
                        continue;

                    if (ctx_ptr->PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, m.round_))
                    {
                        processed_ids.insert(m.id_); // ★ここで処理済みIDを記録
                        received_from.insert(m.src_);
                        std::cout << "[" << party_id << "] OK: Round " << round_index
                                  << " from " << m.src_
                                  << " (Progress: " << received_from.size() << "/" << (expected_count - 1) << ")" << std::endl;
                    }
                }
            }
            else if (m.round_ > round_index)
            {
                // 未来のメッセージはバッファへ
                bool found = false;
                for (auto &b : msg_buffer)
                    if (b.src_ == m.src_ && b.round_ == m.round_)
                    {
                        found = true;
                        break;
                    }
                if (!found)
                    msg_buffer.push_back(m);
            }
        }

        // 終了判定
        if (received_from.size() >= (size_t)expected_count - 1)
        {
            if (ctx_ptr->IsCurRoundFinished())
                break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// 署名実行の本体
void run_signing_logic(const std::string &party_id,
                       const std::string &my_id,
                       const std::string &hash,
                       const std::vector<std::string> &participants)
{
    msg_buffer.clear(); // 前回の残りカスを掃除
    std::cout << "\n[SIGN START] Hash: " << hash << std::endl;

    // --- 署名ロジック ---
    std::string raw_key = load_key(my_id + ".key");
    std::string b64_trimmed;

    if (!safeheron::multi_party_ecdsa::gg18::trim_sign_key(b64_trimmed, raw_key, participants))
    {
        throw std::runtime_error("Trim failed.");
    }

    BN m(hash.c_str(), 16);
    Context ctx(participants.size());
    if (!Context::CreateContext(ctx, b64_trimmed, m))
    {
        throw std::runtime_error("CreateContext failed.");
    }

    for (int round = 0; !ctx.IsFinished(); ++round)
    {
        run_round_network(&ctx, my_id, round, participants.size());
    }

    std::string r_str, s_str;
    ctx.r_.ToHexStr(r_str);
    ctx.s_.ToHexStr(s_str);

    std::cout << "=== Signing Finished ===\nr: " << r_str << "\ns: " << s_str << std::endl;

    // Node-RED への送信処理
    httplib::Client cli("host.docker.internal", 1880);
    json result_json;
    result_json["party_id"] = party_id;
    result_json["status"] = "success";
    result_json["signature"] = {
        {"r", r_str},
        {"s", s_str}};

    auto res = cli.Post("/mpc/sign_result", result_json.dump(), "application/json");

    if (res && res->status == 200)
    {
        std::cout << "Signature sent to Node-RED successfully!" << std::endl;
    }
    else
    {
        std::cerr << "Failed to send signature to Node-RED" << std::endl;
    }
}
