#include "dns_server.h"
#include <cstdint>
#include <cstring>
#include <esp_log.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

#define TAG "DnsServer"

namespace {

constexpr size_t kDnsHeaderSize = 12;
constexpr size_t kDnsAnswerSize = 16;
constexpr uint16_t kDnsTypeA = 1;
constexpr uint16_t kDnsClassIn = 1;

uint16_t ReadUint16(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

void WriteUint16(uint8_t* data, uint16_t value) {
    data[0] = static_cast<uint8_t>(value >> 8);
    data[1] = static_cast<uint8_t>(value & 0xff);
}

void WriteUint32(uint8_t* data, uint32_t value) {
    data[0] = static_cast<uint8_t>(value >> 24);
    data[1] = static_cast<uint8_t>((value >> 16) & 0xff);
    data[2] = static_cast<uint8_t>((value >> 8) & 0xff);
    data[3] = static_cast<uint8_t>(value & 0xff);
}

// Advances offset over an RFC 1035 encoded name. Compression is unusual in
// questions, but accepting it makes the parser safe for multi-question and
// desktop resolver packets.
bool SkipDnsName(const uint8_t* packet, size_t packet_len, size_t& offset) {
    while (offset < packet_len) {
        const uint8_t label_len = packet[offset++];
        if (label_len == 0) {
            return true;
        }
        if ((label_len & 0xc0) == 0xc0) {
            if (offset >= packet_len) {
                return false;
            }
            ++offset;
            return true;
        }
        if ((label_len & 0xc0) != 0 || label_len > 63 ||
            offset + label_len > packet_len) {
            return false;
        }
        offset += label_len;
    }
    return false;
}

}  // namespace

DnsServer::DnsServer() {
}

DnsServer::~DnsServer() {
    Stop();
}

void DnsServer::Start(esp_ip4_addr_t gateway) {
    // If already running, stop first
    if (running_) {
        Stop();
    }

    ESP_LOGI(TAG, "Starting DNS server");
    gateway_ = gateway;

    fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port_);

    if (bind(fd_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "failed to bind port %d", port_);
        close(fd_);
        fd_ = -1;
        return;
    }

    running_ = true;
    xTaskCreate([](void* arg) {
        DnsServer* dns_server = static_cast<DnsServer*>(arg);
        dns_server->Run();
        vTaskDelete(NULL);
    }, "DnsServerTask", 4096, this, 5, &task_handle_);
}

void DnsServer::Stop() {
    if (!running_) {
        return;
    }

    ESP_LOGI(TAG, "Stopping DNS server");
    running_ = false;

    // Close socket to unblock recvfrom
    if (fd_ >= 0) {
        shutdown(fd_, SHUT_RDWR);
        close(fd_);
        fd_ = -1;
    }

    // Wait for task to finish
    if (task_handle_ != nullptr) {
        // Give the task some time to exit gracefully
        vTaskDelay(pdMS_TO_TICKS(100));
        task_handle_ = nullptr;
    }
}

void DnsServer::Run() {
    uint8_t buffer[512];
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int len = recvfrom(fd_, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (len < 0) {
            if (!running_) {
                // Socket was closed during Stop(), exit gracefully
                break;
            }
            ESP_LOGE(TAG, "recvfrom failed, errno=%d", errno);
            continue;
        }

        if (!running_) {
            break;
        }

        const size_t request_len = static_cast<size_t>(len);
        if (request_len < kDnsHeaderSize || (buffer[2] & 0x80) != 0 ||
            (buffer[2] & 0x78) != 0) {
            ESP_LOGW(TAG, "Ignoring malformed or unsupported DNS packet");
            continue;
        }

        const uint16_t question_count = ReadUint16(&buffer[4]);
        size_t question_offset = kDnsHeaderSize;
        size_t response_len = kDnsHeaderSize;
        uint16_t answer_count = 0;

        for (uint16_t i = 0; i < question_count; ++i) {
            const size_t name_offset = question_offset;
            if (!SkipDnsName(buffer, request_len, question_offset) ||
                question_offset + 4 > request_len) {
                response_len = 0;
                break;
            }

            const uint16_t type = ReadUint16(&buffer[question_offset]);
            const uint16_t dns_class = ReadUint16(&buffer[question_offset + 2]);
            question_offset += 4;
            response_len = question_offset;

            // Return the AP address only for IPv4 questions. AAAA and other
            // desktop resolver queries receive a valid empty response instead
            // of the malformed IPv4 answer the previous implementation made.
            if (type == kDnsTypeA && dns_class == kDnsClassIn) {
                if (response_len + (answer_count + 1) * kDnsAnswerSize > sizeof(buffer) ||
                    name_offset > 0x3fff) {
                    response_len = 0;
                    break;
                }
                ++answer_count;
            }
        }

        if (response_len == 0) {
            ESP_LOGW(TAG, "Ignoring truncated DNS question");
            continue;
        }
        if (response_len + answer_count * kDnsAnswerSize > sizeof(buffer)) {
            ESP_LOGW(TAG, "DNS response would exceed packet buffer");
            continue;
        }

        // Strip authority/additional records (including EDNS OPT), then append
        // one A answer for each IPv4 question.
        buffer[2] = static_cast<uint8_t>(0x84 | (buffer[2] & 0x01));  // QR, AA, preserve RD
        buffer[3] = 0x00;
        WriteUint16(&buffer[6], answer_count);
        WriteUint16(&buffer[8], 0);
        WriteUint16(&buffer[10], 0);

        question_offset = kDnsHeaderSize;
        size_t answer_offset = response_len;
        for (uint16_t i = 0; i < question_count; ++i) {
            const size_t name_offset = question_offset;
            if (!SkipDnsName(buffer, response_len, question_offset)) {
                break;
            }
            const uint16_t type = ReadUint16(&buffer[question_offset]);
            const uint16_t dns_class = ReadUint16(&buffer[question_offset + 2]);
            question_offset += 4;
            if (type != kDnsTypeA || dns_class != kDnsClassIn) {
                continue;
            }

            WriteUint16(&buffer[answer_offset], static_cast<uint16_t>(0xc000 | name_offset));
            WriteUint16(&buffer[answer_offset + 2], kDnsTypeA);
            WriteUint16(&buffer[answer_offset + 4], kDnsClassIn);
            WriteUint32(&buffer[answer_offset + 6], 30);  // Short TTL for a temporary AP
            WriteUint16(&buffer[answer_offset + 10], 4);
            memcpy(&buffer[answer_offset + 12], &gateway_.addr, 4);
            answer_offset += kDnsAnswerSize;
        }

        ESP_LOGD(TAG, "Sending DNS response with %u answer(s)",
                 static_cast<unsigned>(answer_count));
        sendto(fd_, buffer, answer_offset, 0,
               reinterpret_cast<struct sockaddr *>(&client_addr), client_addr_len);
    }

    task_handle_ = nullptr;
    ESP_LOGI(TAG, "DNS server task exiting");
}
