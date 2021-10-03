#ifndef CYBERSEC_PROJECT_CONST_H
#define CYBERSEC_PROJECT_CONST_H

const unsigned int SERVER_PORT = 20000;
const unsigned int MAX_INPUT_LEN = 20;
const unsigned int SHOW_ONLINE_USERS_OPC = 1;
const unsigned int OUTCOME_CHALLENGE_RESPONSE_POS_OPC = 2;
const unsigned int OUTCOME_CHALLENGE_RESPONSE_NEG_OPC = 3;
const unsigned int CHALLENGE_REQUEST_OPC = 4;
const unsigned int WAITING_REQ_OPC = 5;
const unsigned int NEW_CHALLENGE_REQ_OPC = 6;
const unsigned int END_OF_MATCHMAKING = 7;
const unsigned int CHALLENGE_ACCEPTED = 8;
const unsigned int CHALLENGE_REFUSED = 9;
const unsigned int DISCONNECTED = 9;
const unsigned int CONNECTED = 10;
const unsigned int READY = 11;
const unsigned int NONCE_SIZE = 16;
const unsigned int ERROR_CHALLENGE_SELF = 20;

enum client_status {
    ONLINE, OFFLINE, UNREGISTERED, MATCHMAKING, PLAYING, CERT_REQ, LOGIN
};

#endif //CYBERSEC_PROJECT_CONST_H
