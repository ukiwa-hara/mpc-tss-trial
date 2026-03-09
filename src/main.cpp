#include "httplib.h"
#include "common.h"
#include "json.hpp" // jsonのパース用
#include <iostream> // cerr, cout 用に追加

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Error: Argument missing (e.g., co_signer1)" << std::endl;
        return 1;
    }

    std::string my_id = argv[1];
    std::cout << "Server starting for ID: " << my_id << " on port 8080..." << std::endl;

    httplib::Server svr;

    // 疎通確認用（ブラウザで http://localhost:8081/ を叩ける）
    svr.Get("/", [](const auto &, auto &res)
            { res.set_content("MPC Server is running", "text/plain"); });

    // KeyGenリクエスト
    svr.Post("/mpc/keygen", [&](const auto &req, auto &res)
             {
        std::cout << "Received KeyGen request for " << my_id << std::endl;
        std::thread([my_id]() { 
            std::cout << "Starting KeyGen logic thread..." << std::endl;
            run_keygen_logic(my_id); 
        }).detach();
        res.set_content("KeyGen Started", "text/plain"); });

    // main.cpp の署名リクエスト部分
    svr.Post("/mpc/sign", [&](const auto &req, auto &res)
             {
    auto j = nlohmann::json::parse(req.body);
    
    // JSON から取得
    std::string party_id = j.value("party_id", "default_party"); // Node-RED側から送られるキー
    std::string hash = j.value("hash", "...");
    std::vector<std::string> p;
    j.at("participants").get_to(p);
    
    // 4つの引数で呼び出す！
    std::thread([party_id, my_id, hash, p]() { 
        run_signing_logic(party_id, my_id, hash, p); 
    }).detach();
    
    res.set_content("Sign Started", "text/plain"); });

    // Key Refreshリクエスト
    svr.Post("/mpc/refresh", [&](const auto &req, auto &res)
             {
    auto j = nlohmann::json::parse(req.body);
    
    // JSON から取得
    std::vector<std::string> p;
    j.at("participants").get_to(p);
    
    // スレッド起動
    std::thread([my_id, p]() { 
        try { 
            std::cout << "Starting Refresh logic thread for " << my_id << "..." << std::endl;
            run_refresh_logic(my_id, p); 
        }
        catch(const std::exception& e) { 
            std::cerr << "Refresh Error: " << e.what() << std::endl; 
        }
    }).detach();
    
    res.set_content("Refresh Started", "text/plain"); });

    // ここで起動メッセージを出してから listen を呼ぶのが一般的です
    std::cout << "Listening on 0.0.0.0:8080..." << std::endl;

    if (!svr.listen("0.0.0.0", 8080))
    {
        std::cerr << "Failed to start server! Maybe port 8080 is already in use." << std::endl;
        return 1;
    }

    return 0;
}