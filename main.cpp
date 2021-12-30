//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP SSL client, coroutine
//
//------------------------------------------------------------------------------
#include <thread>

#include "root_certificates.hpp"

#include <boost/asio/spawn.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/program_options.hpp>

#include <atomic>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>

namespace po = boost::program_options;
namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

//------------------------------------------------------------------------------

std::atomic_uint32_t active_sessions{0};
std::atomic_uint32_t connected_sessions{0};
std::atomic_uint32_t success_sessions{0};
std::atomic_uint32_t failed_sessions{0};
std::atomic_uint32_t success_requests{0};
std::atomic_uint32_t failed_requests{0};

bool keepAlive = true;
uint32_t requests = 10;

struct SessionsCounter {
    SessionsCounter() {
        ++active_sessions;
    }
    ~SessionsCounter() {
       --active_sessions;
    }
};

struct ConnectedSessionsCounter {
    ConnectedSessionsCounter() {
        ++connected_sessions;
    }
    ~ConnectedSessionsCounter() {
        --connected_sessions;
    }
};


// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
    ++failed_sessions;
    return;
}

// Performs an HTTP GET and prints the response
void
do_ssl_session(
    const tcp::resolver::results_type &results,
    std::string const& host,
    std::string const& target,
    net::io_context& ioc,
    ssl::context& ctx,
    net::yield_context yield)
{
    beast::error_code ec;

    boost::asio::deadline_timer timer(ioc);
    timer.expires_from_now(boost::posix_time::millisec(rand() % 2000));
    timer.async_wait(yield[ec]);

    SessionsCounter conter;
    // These objects perform our I/O
    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

    // Set SNI Hostname (many hosts need this to handshake successfully)
    if (! SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
    {
        ec.assign(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
        std::cerr << ec.message() << "\n";
        return;
    }


    // Set the timeout.
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

    // Make the connection on the IP address we get from a lookup
    get_lowest_layer(stream).async_connect(results, yield[ec]);
    if (ec)
        return fail(ec, "connect");

    // Set the timeout.
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

    // Perform the SSL handshake
    stream.async_handshake(ssl::stream_base::client, yield[ec]);
    if (ec)
        return fail(ec, "handshake");

    ConnectedSessionsCounter cs;

    // Set up an HTTP GET request message
    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, host);
    if (keepAlive)
        req.set(http::field::connection, "Keep-Alive");
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    auto doRequest = [&] {
        // Set the timeout.
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

        // Send the HTTP request to the remote host
        http::async_write(stream, req, yield[ec]);
        if (ec) {
            fail(ec, "write");
            ++failed_requests;
            return false;
        }

        // This buffer is used for reading and must be persisted
        beast::flat_buffer b;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::async_read(stream, b, res, yield[ec]);
        if (ec) {
            fail(ec, "read");
            ++failed_requests;
            return false;
        }

        // Write the message to standard out
        ///        std::cout << res << std::endl;

        // Set the timeout.
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
        ++success_requests;
        return true;
    };
    for (uint32_t i = 0; i < requests; ++i) {
        if (!doRequest())
            return;

        timer.expires_from_now(boost::posix_time::millisec(100 + rand() % 3000));
        timer.async_wait(yield[ec]);
        if (ec == boost::asio::error::operation_aborted)
            return;
    }

    timer.expires_from_now(boost::posix_time::millisec(2500));
    timer.async_wait(yield[ec]);

    // Gracefully close the stream
    stream.async_shutdown(yield[ec]);
    if (ec == net::error::eof)
    {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec = {};
    }
    if (ec)
        return fail(ec, "shutdown");

    // If we get here then the connection is closed gracefully
    ++success_sessions;
}

void
do_session(
    const tcp::resolver::results_type &results,
    std::string const& host,
    std::string const& target,
    net::io_context& ioc,
    net::yield_context yield)
{
    beast::error_code ec;

    // simulate users concurrency
    boost::asio::deadline_timer timer(ioc);
    timer.expires_from_now(boost::posix_time::millisec(rand() % 2000));
    timer.async_wait(yield[ec]);

    SessionsCounter conter;
    // These objects perform our I/O
    beast::tcp_stream stream(ioc);

    // Set the timeout.
    stream.expires_after(std::chrono::seconds(30));

    // Make the connection on the IP address we get from a lookup
    stream.async_connect(results, yield[ec]);
    if (ec)
        return fail(ec, "connect");

    ConnectedSessionsCounter cs;

    // Set up an HTTP GET request message
    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, host);
    if (keepAlive)
        req.set(http::field::connection, "Keep-Alive");
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    auto doRequest = [&] {
        // Set the timeout.
        stream.expires_after(std::chrono::seconds(30));

        // Send the HTTP request to the remote host
        http::async_write(stream, req, yield[ec]);
        if (ec) {
            fail(ec, "write");
            ++failed_requests;
            return false;
        }

        // This buffer is used for reading and must be persisted
        beast::flat_buffer b;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::async_read(stream, b, res, yield[ec]);
        if (ec) {
            fail(ec, "read");
            ++failed_requests;
            return false;
        }

        // Write the message to standard out
        //    std::cout << res << std::endl;
        ++success_requests;
        return true;
    };

    for (uint32_t i = 0; i < requests; ++i) {
        if (!doRequest())
            return;

        timer.expires_from_now(boost::posix_time::millisec(100 + rand() % 3000));
        timer.async_wait(yield[ec]);
        if (ec == boost::asio::error::operation_aborted)
            return;
    }

    timer.expires_from_now(boost::posix_time::millisec(2500));
    timer.async_wait(yield[ec]);

    // Gracefully close the socket
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes
    // so don't bother reporting it.
    //
    if (ec && ec != beast::errc::not_connected)
        return fail(ec, "shutdown");

    // If we get here then the connection is closed gracefully
    ++success_sessions;
}

//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    int workers = std::thread::hardware_concurrency();
    bool ssl = false;
    int count = 25000;
    std::string host = "localhost";
    std::string port;
    std::string target = "/";

    po::options_description desc{"HTTP Bench options"};
    desc.add_options()
        ("keepAlive,k", po::bool_switch(&keepAlive), "keep alive")
        ("requests,r", po::value<uint32_t>(&requests)->implicit_value(requests), "requests per connection")
        ("workers,w", po::value<int>(&workers)->implicit_value(workers), "workers")
        ("connections,c", po::value<int>(&count)->implicit_value(count), "concurrent connection")
        ("ssl,s", po::bool_switch(&ssl), "use ssl")
        ("help,h", "print this help")
        ("url", po::value< std::string>(), "url e.g. 192.168.0.1:8080/index.html")
        ;
    po::positional_options_description p;
    p.add("url", 1);

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
        po::notify(vm);
        if (vm.count("help") || vm.count("url") != 1) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }
        port = ssl ? "443" : "80";
        auto url = vm["url"].as<std::string>();
        auto idx = url.find('/');
        if (idx != std::string::npos)
            target = url.substr(idx);
        url = url.substr(0, idx);
        idx = url.find(':');
        if (idx != std::string::npos)
            port = url.substr(idx + 1);
        host = url.substr(0, idx);
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        return EXIT_FAILURE;
    }

    // The io_context is required for all I/O
    net::io_context ioc{workers};

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12_client};

    // This holds the root certificate used for verification
    load_root_certificates(ctx);

    // Verify the remote server's certificate
    ctx.set_verify_mode(ssl::verify_none);

    beast::error_code ec;
    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, port, ec);
    if (ec) {
        std::cerr << "Can not resolve " << host << ":" << port;
        return EXIT_FAILURE;
    }

    boost::asio::spawn(ioc, [&] (net::yield_context yield) {
        beast::error_code ec;
        boost::asio::deadline_timer timer(ioc);
        do {
            timer.expires_from_now(boost::posix_time::seconds(1));
            timer.async_wait(yield[ec]);
            const auto cs = connected_sessions.load();
            std::cout << "Active sessions " << active_sessions.load()
                      << " connected sessions " << cs
                      << " success sessions " << success_sessions.load()
                      << " failed sessions " << failed_sessions.load()
                      << " success requests " << success_requests.load()
                      << " failed requests " << failed_requests.load()
                      << std::endl;

        } while (active_sessions.load());
    });

    // Launch the asynchronous operations
    if (ssl) {
        while (count--)
            boost::asio::spawn(ioc, std::bind(
                                        &do_ssl_session,
                                        results,
                                        host,
                                        target,
                                        std::ref(ioc),
                                        std::ref(ctx),
                                        std::placeholders::_1));
    } else {
        while (count--)
            boost::asio::spawn(ioc, std::bind(
                                        &do_session,
                                        results,
                                        host,
                                        target,
                                        std::ref(ioc),
                                        std::placeholders::_1));
    }
    std::cout << "Starting ..\n";
    std::vector<std::thread> v;
    v.reserve(workers - 1);
    for (auto i = workers - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run();});

    ioc.run();
    for (auto &t : v) {
        if (t.joinable())
            t.join();
    }

    std::cout << "Summary :\n"
              << "\n\tsessions success " << success_sessions.load()  << " / failed " <<  failed_sessions.load()
              << "\n\trequests success " << success_requests.load()  << " / failed " <<  failed_requests.load()
              << std::endl;
    return EXIT_SUCCESS;
}
