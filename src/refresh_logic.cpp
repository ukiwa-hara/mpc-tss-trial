#include "common.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/gg18.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <set>

using safeheron::multi_party_ecdsa::gg18::key_refresh::Context;

// 外部グローバル変数の参照
extern std::vector<Msg> msg_buffer;
extern std::set<std::string> processed_ids;

void run_round_network(Context *ctx_ptr, const std::string &party_id, int round_index, int expected_count)
{
    std::set<std::string> received_from;

    // 1. メッセージ送信 (ラウンド0はPushMessageが必要)
    if (round_index == 0)
        ctx_ptr->PushMessage();

    std::vector<std::string> out_p2p, out_des;
    std::string out_bc;
    ctx_ptr->PopMessages(out_p2p, out_bc, out_des);

    for (size_t k = 0; k < out_des.size(); ++k)
    {
        send_msg(party_id, out_des[k], out_bc, out_p2p.empty() ? "" : out_p2p[k], round_index);
    }

    // 2. バッファからの回収（既読IDはスキップ）
    auto it = msg_buffer.begin();
    while (it != msg_buffer.end())
    {
        if (it->round_ == round_index)
        {
            if (ctx_ptr->PushMessage(it->p2p_msg_, it->bc_msg_, it->src_, it->round_))
            {
                processed_ids.insert(it->id_);
                received_from.insert(it->src_);
                it = msg_buffer.erase(it);
                continue;
            }
        }
        ++it;
    }

    // 3. 通信監視ループ (全員から届くまで待機)
    while (received_from.size() < (size_t)expected_count - 1)
    {
        auto msgs = recv_msg(party_id);
        for (auto &m : msgs)
        {
            if (m.src_ == party_id)
                continue;

            if (m.round_ == round_index)
            {
                if (processed_ids.find(m.id_) == processed_ids.end())
                {
                    if (ctx_ptr->PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, m.round_))
                    {
                        processed_ids.insert(m.id_);
                        received_from.insert(m.src_);
                        std::cout << "[" << party_id << "] OK: Round " << round_index
                                  << " from " << m.src_ << " (" << received_from.size() << "/" << (expected_count - 1) << ")" << std::endl;
                    }
                }
            }
            else if (m.round_ > round_index)
            {
                // 未来のメッセージはバッファへ保持
                bool found = false;
                for (auto &b : msg_buffer)
                    if (b.id_ == m.id_)
                    {
                        found = true;
                        break;
                    }
                if (!found)
                    msg_buffer.push_back(m);
            }
        }

        // 終了判定
        if (received_from.size() >= (size_t)expected_count - 1 && ctx_ptr->IsCurRoundFinished())
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void run_refresh_logic(const std::string &party_id, const std::vector<std::string> &participants)
{
    std::cout << "=== Start GG18 Key Refresh for " << party_id << " ===" << std::endl;

    // 鍵の読み込み
    std::ifstream f(party_id + ".key");
    std::string raw_key;
    if (f)
        f >> raw_key;

    Context ctx(participants.size());
    if (!Context::CreateContext(ctx, raw_key))
        throw std::runtime_error("Context init failed");

    // プロトコル実行
    for (int round = 0; !ctx.IsFinished(); ++round)
    {
        run_round_network(&ctx, party_id, round, participants.size());
    }

    // 1. 古い鍵をバックアップ (.key.bak) へ移動
    std::string old_filename = party_id + ".key";
    std::string bak_filename = party_id + ".key.bak";

    // rename は上書きされる可能性があるため注意が必要です
    if (std::rename(old_filename.c_str(), bak_filename.c_str()) != 0)
    {
        std::cerr << "Warning: Could not rename old key file." << std::endl;
    }

    // 2. 新しい鍵を元のファイル名 (.key) で保存
    std::string base64;
    ctx.sign_key_.ToBase64(base64);

    std::ofstream ofs(old_filename);
    if (ofs.is_open())
    {
        ofs << base64;
        ofs.close();
        std::cout << "Successfully saved new key to " << old_filename << std::endl;
    }
}