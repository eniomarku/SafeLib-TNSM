#include <libvnf/core.hpp>

using namespace vnf;

struct BState {
    char *req;
    void *dsreq;
    int val;
    int aCoreId;
    int aSocketId;
};

string mmeIp;
int mmePort;
string neighbour1Ip;
int neighbour1Port;

int getKeyId(int coreId, int socketId) {
    int keyId;
    if (coreId >= 1 && coreId <= 7) {
        keyId = coreId * 100000 + socketId;
    } else {
        keyId = 800000 + socketId;
    }
    return keyId;
}

void onDatastoreReply(ConnId& aConnId, int reqObjId, void *requestObject, void *value, int valueLen, int errCode) {
    // prepare key id
    int keyId = getKeyId(aConnId.coreId, aConnId.socketId);

    BState *state = static_cast<BState *>(requestObject);
    state->dsreq = setCachedDSKeyDNE(keyId);
    unsetCachedDSKeyDNE(keyId);
    aConnId.unsetPktDNE((void *) state->req);

    // send data to A
    char *buffer = aConnId.getPktBuf();
    memcpy((void *) buffer, value, valueLen);
    aConnId.sendData(buffer, valueLen);

    // free request object bound to A's connection, delete data from datastore and close connection in a single line
    //aConnId.freeReqObj(1).delData("", keyId, LOCAL).closeConn();
    aConnId.freeReqObj(1).delData("", keyId, LOCAL);
}

void onPacketReceivedFromC(ConnId& cConnId, int reqObjId, void *requestObject, char *packet, int packetLen, int errCode, int streamNum) {
    // get values from request object [created at B when a packet is received from A]
    BState *state = static_cast<BState *>(requestObject);

    // prepare A's connection id and key id
    int keyId = getKeyId(state->aCoreId, state->aSocketId);
    ConnId aConnId = ConnId(state->aCoreId, state->aSocketId);

    // free request obj bound to C's connection and close connection in one line
    cConnId.freeReqObj(1).closeConn();

    // get key value pair stored in data store [when a packet is received from A]
    aConnId.retrieveData("", keyId, LOCAL, onDatastoreReply);
}

void onPacketReceivedFromA(ConnId& aConnId, int reqObjId, void *requestObject, char *packet, int packetLen, int errCode, int streamNum) {
    // allocate request object and bind it to A's connection
    requestObject = aConnId.allocReqObj(1);

    // connect to C as a client
//    ConnId cConnId = aConnId.createClient(mmeIp, neighbour1Ip, neighbour1Port, "tcp");

    // set values in request object
    BState *state = static_cast<BState *>(requestObject);
    int val = aConnId.socketId;
    for (int i = 1; i < 20000000; i++) {
        val = val + i;
    }
    state->val = val;
    state->req = (char *) aConnId.setPktDNE((void *) packet);
    state->aSocketId = aConnId.socketId;
    state->aCoreId = aConnId.coreId;

    // store key value pair in data store
    int keyId = getKeyId(aConnId.coreId, aConnId.socketId);
    char value[] = "Dear A, thank you for your message, I have contacted C and sending back this message. Lots of love.";
    int valueLen = strlen(value);
    aConnId.storeData("", keyId, LOCAL, (void *) value, valueLen, NULL);
     aConnId.unsetPktDNE((void *) state->req);
 char *buffer = aConnId.getPktBuf();
    memcpy((void *) buffer, value, valueLen);
    aConnId.sendData(buffer, valueLen);

    // free request object bound to A's connection, delete data from datastore and close connection in a single line
    //aConnId.freeReqObj(1).delData("", keyId, LOCAL).closeConn();
    aConnId.freeReqObj(1).delData("", keyId, LOCAL).closeConn();

   // char *buffer = cConnId.getPktBuf();
   // const string message = "This message is originated from B. It shall be echoed back to B from C";
   // memcpy((void *) buffer, (void *) message.c_str(), message.size());
    // link request object, register READ callback and send data in one line
 //   cConnId.linkReqObj(requestObject).registerCallback(READ, onPacketReceivedFromC).sendData(buffer, message.size());
}

int main(int argc, char *argv[]) {
    // init libvnf
    vector<int> dataStorePorts;
    dataStorePorts.push_back(7000);
    dataStorePorts.push_back(7001);
    dataStorePorts.push_back(7002);
    dataStorePorts.push_back(7003);
    initLibvnf(2, 128, "127.0.0.1", dataStorePorts, 131072, false);

    if (argc != 5) {
        exit(0);
    }

    // init network parameters
    mmeIp = argv[1];
    mmePort = atoi(argv[2]);
    neighbour1Ip = argv[3];
    neighbour1Port = atoi(argv[4]);

    // create server
    ConnId serverId = initServer("", mmeIp, mmePort, "tcp");
    // register callback to handle packets coming from A
    registerCallback(serverId, READ, onPacketReceivedFromA);

    // request object declaration
    int requestObjectSizes[1] = {sizeof(struct BState)};
    initReqPool(requestObjectSizes, 1);

    // start vnf
    startEventLoop();

    return 0;
}
