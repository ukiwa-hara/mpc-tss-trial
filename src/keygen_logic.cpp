#include "common.h"  // 追加

#include <iostream>
#include <vector>
#include <fstream>
#include <thread>
#include <chrono>
#include <set>

#include "httplib.h"
#include "json.hpp"

// curve
#include "crypto-suites/crypto-curve/curve.h"

static std::vector<Msg> global_msg_buffer; // 他のラウンドのメッセージ保管場所


// GG18
#include "multi-party-sig/multi-party-ecdsa/gg18/gg18.h"

using json = nlohmann::json;

using namespace safeheron;
using namespace safeheron::multi_party_ecdsa::gg18::key_gen;
using namespace safeheron::curve;


void run_round(Context *ctx_ptr,
               const std::string &party_id,
               int round_index)
{
    std::vector<std::string> out_p2p_message_arr;
    std::string out_bc_message;
    std::vector<std::string> out_des_arr;

    if (round_index == 0)
    {
        ctx_ptr->PushMessage();

        ctx_ptr->PopMessages(out_p2p_message_arr,
                             out_bc_message,
                             out_des_arr);

        for (size_t k = 0; k < out_des_arr.size(); ++k)
        {
            send_msg(
                party_id,
                out_des_arr[k],
                out_bc_message,
                out_p2p_message_arr.empty()
                    ? ""
                    : out_p2p_message_arr[k],
                round_index // ここに現在の round_index を渡す
            );
        }

        return;
    }

    //////////////////////////////////////////////////////////
    // Round1+
    //////////////////////////////////////////////////////////

    // このラウンドで「誰から」受け取ったかを管理
    std::set<std::string> received_from;

    // 自分以外の参加者数（今回は 3人合計なので、相手は 2人）
    const size_t expected_count = 2;

// A. まずバッファの中に「今回のラウンドに必要なメッセージ」がないかチェック
    auto it = global_msg_buffer.begin();
    while (it != global_msg_buffer.end()) {
        if (it->round_ == round_index - 1) {
            ctx_ptr->PushMessage(it->p2p_msg_, it->bc_msg_, it->src_, round_index - 1);
            received_from.insert(it->src_);
            it = global_msg_buffer.erase(it); // 消費したら削除
        } else {
            ++it;
        }
    }

    // while (true)
    // {
    //     auto msgs = recv_msg(party_id);
    //     for (auto &m : msgs)
    //     {
    //         // if (m.src_ == party_id)
    //         //     continue;
    //         // // 正しいラウンドのデータのみ受け取る
    //         // if (m.round_ != round_index - 1)
    //         //     continue;

    //         // if (received_from.count(m.src_) == 0)
    //         // {
    //         //     ctx_ptr->PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, round_index - 1);
    //         //     received_from.insert(m.src_);
    //         //     std::cout << "[" << party_id << "] Received Round " << m.round_ << " from " << m.src_ << std::endl;
    //         // }
    //         if (m.src_ == party_id) continue;

    //         // B. 「今回のラウンド用」なら Push
    //         if (m.round_ == round_index - 1) {
    //             if (received_from.count(m.src_) == 0) {
    //                 ctx_ptr->PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, round_index - 1);
    //                 received_from.insert(m.src_);
    //             }
    //         } 
    //         // C. 「未来のラウンド用」ならバッファへ退避
    //         else if (m.round_ >= round_index) {
    //             global_msg_buffer.push_back(m);
    //         }
    //     }

    //     // 【ここが重要】ライブラリの判定だけでなく、物理的に2人分揃ったか確認する
    //     if (received_from.size() >= expected_count && ctx_ptr->IsCurRoundFinished())
    //     {
    //         break;
    //     }

    //     std::this_thread::sleep_for(std::chrono::milliseconds(200));
    // }
    while (true)
    {
        auto msgs = recv_msg(party_id);
        for (auto &m : msgs)
        {
            if (m.src_ == party_id) continue;

            // 【重要】通信層でフィルタしきれなかった重複をここで弾く
            if (processed_ids.count(m.id_)) continue;

            // B. 「今回のラウンド用」なら Push
            if (m.round_ == round_index - 1) {
                if (received_from.count(m.src_) == 0) {
                    // PushMessageが成功した場合のみ、IDを確定させる
                    if (ctx_ptr->PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, round_index - 1)) {
                        processed_ids.insert(m.id_); // ★ここが確定処理
                        received_from.insert(m.src_);
                        std::cout << "[" << party_id << "] OK: Received Round " 
                                  << m.round_ << " from " << m.src_ << std::endl;
                    }
                }
            } 
            // C. 「未来のラウンド用」ならバッファへ退避（IDの重複も回避）
            else if (m.round_ >= round_index) {
                bool already_buffered = false;
                for(auto &b : global_msg_buffer) if(b.id_ == m.id_) already_buffered = true;
                if(!already_buffered) global_msg_buffer.push_back(m);
            }
        }

        // 物理的に人数が揃い、かつ計算も終了していれば抜ける
        if (received_from.size() >= expected_count && ctx_ptr->IsCurRoundFinished())
        {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    ctx_ptr->PopMessages(
        out_p2p_message_arr,
        out_bc_message,
        out_des_arr);

    for (size_t k = 0; k < out_des_arr.size(); ++k)
    {
        send_msg(
            party_id,
            out_des_arr[k],
            out_bc_message,
            out_p2p_message_arr.empty()
                ? ""
                : out_p2p_message_arr[k],
            round_index // ここに現在の round_index を渡す
        );
    }
}


////////////////////////////////////////////////////////////
// run_keygen
////////////////////////////////////////////////////////////

void run_keygen_logic(const std::string &party_id)
{
    std::string workspace_id("workspace_0");

    int threshold = 2;
    int n_parties = 3;

    std::string party_id_1 = "co_signer1";
    std::string party_id_2 = "co_signer2";
    std::string party_id_3 = "co_signer3";

    bignum::BN party_index;

    std::vector<std::string> others;

    if (party_id == party_id_1)
    {
        party_index = bignum::BN(1);
        others = {party_id_2, party_id_3};
    }
    else if (party_id == party_id_2)
    {
        party_index = bignum::BN(2);
        others = {party_id_1, party_id_3};
    }
    else
    {
        party_index = bignum::BN(3);
        others = {party_id_1, party_id_2};
    }

    Context ctx(3);

    Context::CreateContext(
        ctx,
        CurveType::SECP256K1,
        workspace_id,
        threshold,
        n_parties,
        party_id,
        party_index,
        others);

    std::cout << "Start KeyGen : "
              << party_id
              << std::endl;

    for (int round = 0; round <= 3; ++round)
    {
        std::cout << "Round "
                  << round
                  << std::endl;

        run_round(&ctx,
                  party_id,
                  round);
    }

    std::cout << "KeyGen Finished\n";

    std::cout << "PublicKey: "
              << ctx.sign_key_.X_.Inspect()
              << std::endl;

    std::string b64;

    ctx.sign_key_.ToBase64(b64);

    std::ofstream f(party_id + ".key");

    f << b64;

    f.close();

    std::cout << "Key saved\n";


    // 公開鍵の座標を取得
    std::string pub_x = ctx.sign_key_.X_.x().Inspect();
    std::string pub_y = ctx.sign_key_.X_.y().Inspect();

    // Node-RED の新しいエンドポイント /mpc/result に送信
    httplib::Client cli("host.docker.internal", 1880);
    json result_json;
    result_json["party_id"] = party_id;
    result_json["status"] = "success";
    result_json["public_key"]["x"] = pub_x;
    result_json["public_key"]["y"] = pub_y;

    auto res = cli.Post("/mpc/keygen_result", result_json.dump(), "application/json");

    if (res && res->status == 200)
    {
        std::cout << "Public key sent to Node-RED successfully!" << std::endl;
    }
}

