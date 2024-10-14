#include "Rawsocket.h"
#include <iostream>
#include "thread"
#include "CertHandler.h"


constexpr auto PRIMARY_PORT = 17595;
constexpr auto SECONDARY_PORT = 17596;


int listenForIncomming() {
    WSADATA wsaData;
    int iResult;
    char readBuf[10] = {};
    int iRead = 0;
    CWizSyncSocket* serversocket = nullptr;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return 1;
    }
    std::cout << "Binding on port" << std::endl;
    // Create listening socket for chat
    serversocket = new CWizSyncSocket(PRIMARY_PORT, SOCK_STREAM);
    if (WSAGetLastError() != 0) {
        serversocket = new CWizSyncSocket(SECONDARY_PORT, SOCK_STREAM);
        std::cout << "Listening on port " << SECONDARY_PORT << std::endl;
    }
    if (WSAGetLastError() != 0) {
        std::cout << "Failed to bind socket to endpoint" << std::endl;
        return -1;
    }
    std::cout << "Listening on port " << PRIMARY_PORT << std::endl;
    while (true) {
        SOCKET sock = serversocket->Accept();
        if (sock == INVALID_SOCKET) {
            continue;
        }
        
        CWizReadWriteSocket* socket = new CWizReadWriteSocket(true);

        if (WSAGetLastError() != 0) {
            delete socket;
            delete serversocket;
            continue;
        }

        socket->SetSocket(sock);
        CertHandler* handler = new CertHandler(socket);
        std::thread comThread(&CertHandler::handleConnection, handler);
        comThread.detach();
    }
}

int main() {
    listenForIncomming();
	return 0;
}