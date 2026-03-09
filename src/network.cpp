#include "common.h"
#include "httplib.h"
#include "json.hpp"
#include <iostream>
#include <uuid/uuid.h>


using json = nlohmann::json;

// UUIDを生成するヘルパー関数
std::string generate_uuid(const std::string &party_id)
{
    return party_id + "_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
}

// 共通の送信処理
void send_msg(const std::string &src, const std::string &dest, const std::string &bc, const std::string &p2p, int round)
{
    httplib::Client cli("host.docker.internal", 1880);
    json j = {
        {"id", generate_uuid(src)},
        {"src", src},
        {"dest", dest},
        {"bc", bc},
        {"p2p", p2p},
        {"round", round}};
    cli.Post("/mpc/send", j.dump(), "application/json");
}

// 共通の受信処理
std::vector<Msg> recv_msg(const std::string &party_id)
{
    httplib::Client cli("host.docker.internal", 1880);
    auto res = cli.Get(("/mpc/recv/" + party_id).c_str());
    std::vector<Msg> out;
    if (res && res->status == 200)
    {
        try
        {
            auto j = json::parse(res->body);
            for (auto &x : j)
            {
                std::string id = x.value("id", "");
                if (id.empty() || processed_ids.count(id)) continue;
                
                out.push_back({id,
                               x.value("src", ""),
                               x.value("bc", ""),
                               x.value("p2p", ""),
                               x.value("round", -1)});
            }
        }
        catch (...)
        {
            // パースエラー時は空で返す
        }
    }
    return out;
}