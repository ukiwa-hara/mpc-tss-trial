cmake_minimum_required(VERSION 3.16)
project(minimal_mpc LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)

# 依存ライブラリの検索
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
# ※注: mpc-base 内で既にインストールされているならこの find_package は必要かもしれません
find_package(MultiPartySig REQUIRED)

# CMakeLists.txt と同じ場所にある third_party を指定
include_directories(
    .
    ./third_party/httplib
    ./third_party/json
)

add_executable(mpc_server
    main.cpp
    keygen_logic.cpp
    sign_logic.cpp
    refresh_logic.cpp
    common.cpp 
    network.cpp
)

target_link_libraries(mpc_server
    PRIVATE
        MultiPartySig
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)