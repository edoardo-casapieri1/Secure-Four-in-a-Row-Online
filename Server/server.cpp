#include <iostream>
#include <sstream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <cstdlib>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
#include "../Common/const.h"


using namespace std;

/********************************************************************/
/* Convert sockaddr to string.                                      */
/********************************************************************/
string addr_to_string(struct sockaddr_in addr) {
    ostringstream os;
    os << inet_ntoa(addr.sin_addr) << ":" << htons(addr.sin_port);
    return os.str();
}

struct client {
    string username;
    client_status status = OFFLINE;
    struct sockaddr_in client_addr;
    unsigned char nonce_client[NONCE_SIZE];
    socklen_t client_addr_len;
    uint32_t cnt = 0;
    unsigned char session_key[16];
    EVP_PKEY *client_pubkey;
    uint16_t listening_port_client;
};

static DH *get_dh2048() {
    static unsigned char dhp_2048[] = {
            0xBA, 0x43, 0x25, 0xF3, 0x87, 0xB3, 0x78, 0xAB, 0x5F, 0x54,
            0xAC, 0x04, 0x47, 0x09, 0x5D, 0x0F, 0x5C, 0xD9, 0xAD, 0xBA,
            0x53, 0x54, 0x1B, 0xB0, 0xBE, 0x54, 0x91, 0x1D, 0x87, 0xB2,
            0x41, 0x0D, 0xBC, 0x55, 0x40, 0x17, 0x15, 0xF4, 0xB6, 0x24,
            0xBA, 0x33, 0x28, 0x75, 0x72, 0xA6, 0x0F, 0x75, 0x9D, 0xFC,
            0x83, 0x6D, 0xA3, 0xE7, 0xF3, 0xA8, 0x5A, 0xA6, 0x3E, 0xEB,
            0xAB, 0x22, 0x8F, 0x4A, 0xF7, 0xB1, 0xAE, 0x8A, 0x5A, 0x3B,
            0xBA, 0xAB, 0xED, 0x94, 0xA9, 0x58, 0x51, 0x64, 0x6C, 0x8D,
            0x38, 0xDE, 0xA4, 0x4D, 0x04, 0xE3, 0x3A, 0x91, 0x80, 0x0D,
            0x78, 0x0C, 0xAA, 0x70, 0x16, 0x5E, 0x34, 0xBA, 0xB4, 0x01,
            0xF2, 0xC5, 0x85, 0x93, 0xED, 0x2D, 0x0F, 0x9A, 0x2F, 0x67,
            0xC9, 0xAD, 0x76, 0x10, 0x7E, 0x16, 0xD6, 0xB0, 0x25, 0xCE,
            0xD9, 0x3E, 0xE2, 0xAD, 0x68, 0x0A, 0x73, 0x98, 0xC7, 0x43,
            0x80, 0xFE, 0xDC, 0xBA, 0x5F, 0x3D, 0x71, 0xFE, 0x7A, 0x9B,
            0xB2, 0x74, 0x1A, 0xEA, 0x74, 0xE0, 0x84, 0xB4, 0x09, 0x74,
            0xD5, 0x3F, 0x11, 0x21, 0x13, 0x7E, 0xAF, 0x46, 0x2C, 0x5F,
            0x56, 0x59, 0x46, 0x5B, 0xFC, 0xF9, 0xED, 0xDF, 0x92, 0x64,
            0x81, 0xA3, 0x47, 0x34, 0x94, 0x4F, 0x1C, 0x90, 0x93, 0x1E,
            0x10, 0x8C, 0xCE, 0xA4, 0x33, 0x55, 0x54, 0x9D, 0x09, 0x75,
            0x7C, 0xEB, 0x14, 0x4C, 0x18, 0x1D, 0xD5, 0x54, 0xAC, 0x32,
            0x50, 0xB4, 0x8D, 0x5D, 0x8E, 0x0E, 0xE6, 0xE7, 0xFC, 0xDD,
            0xD4, 0xE6, 0xC7, 0x9C, 0x02, 0x15, 0x44, 0x55, 0xE2, 0x28,
            0x9B, 0xD9, 0x78, 0x41, 0x47, 0x16, 0x8C, 0xDE, 0xD9, 0xF8,
            0x4F, 0xAA, 0xFA, 0xB2, 0x1C, 0x4C, 0x7F, 0xF6, 0xD1, 0x2F,
            0x8D, 0x5B, 0x98, 0x17, 0x53, 0x41, 0xE3, 0x2A, 0x03, 0x68,
            0xB0, 0xCF, 0x4F, 0x14, 0x19, 0xDB
    };
    static unsigned char dhg_2048[] = {
            0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == nullptr)
        return nullptr;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), nullptr);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), nullptr);
    if (p == nullptr || g == nullptr
        || !DH_set0_pqg(dh, p, nullptr, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return nullptr;
    }
    return dh;
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                uint32_t &cnt,
                unsigned char *aad,
                unsigned char *key,
                unsigned char *ciphertext,
                unsigned char *tag) {

    RAND_poll();
    unsigned char iv[12];
    RAND_bytes(iv, 12);

    cnt++;

    memcpy(aad, iv, 12);
    memcpy(aad + 12, (unsigned char *) &cnt, sizeof(uint32_t));

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return -1;

    //Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, 12 + sizeof(uint32_t)))
        return -1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;
    //Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;
    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return -1;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                uint32_t &cnt,
                unsigned char *aad,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    cnt++;

    int aad_len = 12 + sizeof(uint32_t);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    if (!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return -1;
    //Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len))
        return -1;

    // Check the value of the counter to avoid replay attacks
    if (memcmp(aad + 12, (unsigned char *) &cnt, sizeof(uint32_t)) != 0)
        return -2;

    //Provide the message to be decrypted, and obtain the plaintext output.
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;

    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return -1;
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int main(int argc, char *argv[]) {
    int rc, on = 1, opcode;
    size_t len;
    uint16_t opcode_rcvd, opcode_snd;
    int len_msg;
    uint16_t lmsg;
    int listen_sd = -1, new_sd = -1;
    bool end_server = false, compress_array = false;
    int close_conn;
    struct sockaddr_in addr;
    int timeout;
    struct pollfd fds[200];
    vector<client> vec_client;
    size_t nfds = 1, current_size = 0, i, j;  //size_t in quanto sono indici
    int username_set = 0;
    uint16_t number_of_users_online = 0; //contatore degli utenti online da decrementare nel quando un utente si disconnette o comincia una partita
    uint16_t number_of_users_matchmaking = 0; //contatore degli utenti nello stato matchmaking da decrementare quando un utente si disconnette o comincia una partita o scade il timeout
    uint16_t number_of_users_online_snd, number_of_users_matchmaking_snd;
    //X509* server_cert;

    OpenSSL_add_all_algorithms();

    /*************************************************************/
    /* Create an AF_INET stream socket to receive incoming      */
    /* connections on                                            */
    /*************************************************************/
    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sd < 0) {
        cerr << "socket() failed" << endl;
        exit(EXIT_FAILURE);
    }

    /*************************************************************/
    /* Allow socket descriptor to be reuseable                   */
    /*************************************************************/
    rc = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));

    if (rc < 0) {
        cerr << "setsockopt() failed" << endl;
        close(listen_sd);
        exit(EXIT_FAILURE);
    }

    /*************************************************************/
    /* Set socket to be nonblocking. All of the sockets for      */
    /* the incoming connections will also be nonblocking since   */
    /* they will inherit that state from the listening socket.   */
    /*************************************************************/
    rc = ioctl(listen_sd, FIONBIO, (char *) &on);

    if (rc < 0) {
        cerr << "ioctl() failed" << endl;
        close(listen_sd);
        exit(EXIT_FAILURE);
    }

    /*************************************************************/
    /* Bind the socket                                           */
    /*************************************************************/
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);
    rc = bind(listen_sd, (struct sockaddr *) &addr, sizeof(addr));

    if (rc < 0) {
        cerr << "bind() failed" << endl;
        close(listen_sd);
        exit(EXIT_FAILURE);
    }

    /*************************************************************/
    /* Set the listen back log                                   */
    /*************************************************************/
    rc = listen(listen_sd, 32);

    if (rc < 0) {
        cerr << "listen() failed" << endl;
        close(listen_sd);
        exit(EXIT_FAILURE);
    }

    /*************************************************************/
    /* Initialize the pollfd structure                           */
    /*************************************************************/
    memset(fds, 0, sizeof(fds));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    fds[0].fd = listen_sd;
    fds[0].events = POLLIN;

    timeout = -1;     /* Unlimited */

    /*************************************************************/
    /* Loop waiting for incoming connects or for incoming data   */
    /* on any of the connected sockets.                          */
    /*************************************************************/
    do {
        cout << "[server] Waiting for requests..." << endl;
        rc = poll(fds, nfds, timeout);

        if (rc < 0) {
            cerr << "poll() failed" << endl;
            break;
        }

        /***********************************************************/
        /* One or more descriptors are readable.  Need to          */
        /* determine which ones they are.                          */
        /***********************************************************/
        current_size = nfds;
        for (i = 0; i < current_size; i++) {
            /*********************************************************/
            /* Loop through to find the descriptors that returned    */
            /* POLLIN and determine whether it's the listening       */
            /* or the active connection.                             */
            /*********************************************************/
            if (fds[i].revents == 0)
                continue;

            /*********************************************************/
            /* If revents is not POLLIN, it's an unexpected result,  */
            /* log and end the server.                               */
            /*********************************************************/
            if (fds[i].revents != POLLIN) {
                cout << "Error! revents = " << fds[i].revents << endl;
                end_server = true;
                break;

            }
            if (fds[i].fd == listen_sd) {
                /*******************************************************/
                /* Listening descriptor is readable.                   */
                /*******************************************************/
                cout << "[server] New request of connection." << endl;

                /*******************************************************/
                /* Accept all incoming connections that are            */
                /* queued up on the listening socket before we         */
                /* loop back and call poll again.                      */
                /*******************************************************/
                do {
                    /*****************************************************/
                    /* Accept each incoming connection. If               */
                    /* accept fails with EWOULDBLOCK, then we            */
                    /* have accepted all of them. Any other              */
                    /* failure on accept will cause us to end the        */
                    /* server.                                           */
                    /*****************************************************/
                    //struct sockaddr_in cl_addr;
                    //socklen_t cl_addr_len;
                    client tempClient;
                    tempClient.status = CERT_REQ;
                    new_sd = accept(listen_sd, (struct sockaddr *) &tempClient.client_addr,
                                    &tempClient.client_addr_len);
                    if (new_sd < 0) {
                        if (errno != EWOULDBLOCK) {
                            cerr << "accept() failed" << endl;
                            end_server = true;
                        }
                        break;
                    }

                    vec_client.push_back(tempClient);
                    cout << "[server] Client " << addr_to_string(vec_client.at(nfds - 1).client_addr) << " connected."
                         << endl;

                    /*****************************************************/
                    /* Add the new incoming connection to the            */
                    /* pollfd structure                                  */
                    /*****************************************************/
                    fds[nfds].fd = new_sd;
                    fds[nfds].events = POLLIN;
                    nfds++;

                    if (vec_client.at(nfds - 2).status == CERT_REQ) {
                        //cout << "Devo inviare lunghezza certificato" << endl;
                        FILE *server_cert_file = fopen("cert/FOC_cert.pem", "r");
                        if (!server_cert_file) {
                            exit(EXIT_FAILURE);
                        }
                        X509 *server_cert = PEM_read_X509(server_cert_file, nullptr, nullptr, nullptr);
                        fclose(server_cert_file);
                        unsigned char *cert_buf = nullptr;
                        int cert_size = i2d_X509(server_cert, &cert_buf);
                        X509_free(server_cert);
                        if (cert_size < 0) {
                            cerr << "Error in serializing the certificate!" << endl;
                            exit(EXIT_FAILURE);
                        }
                        uint64_t cert_size_snd = htons(cert_size);
                        rc = send(new_sd, (void *) &cert_size_snd, sizeof(uint64_t), 0);
                        if (rc < 0) {
                            cerr << "[server] send size of cert failed." << endl;
                            close_conn = true;
                            break;
                        }
                        rc = send(new_sd, cert_buf, cert_size, 0);
                        OPENSSL_free(cert_buf);
                        if (rc < 0) {
                            cerr << "[server] send of cert failed." << endl;
                            close_conn = true;
                            break;
                        }
                        vec_client.at(nfds - 2).status = LOGIN;
                    }

                    /*****************************************************/
                    /* Loop back up and accept another incoming          */
                    /* connection                                        */
                    /*****************************************************/
                } while (new_sd != -1);
            }

                /*********************************************************/
                /* This is not the listening socket, therefore an        */
                /* existing connection must be readable                  */
                /*********************************************************/

            else {
                // printf("  Descriptor %d is readable\n", fds[i].fd);
                close_conn = false;
                /*******************************************************/
                /* Receive all incoming data on this socket            */
                /* before we loop back and call poll again.            */
                /*******************************************************/

                do {
                    /*****************************************************/
                    /* Receive data on this connection until the         */
                    /* recv fails with EWOULDBLOCK. If any other         */
                    /* failure occurs, we will close the                 */
                    /* connection.                                       */
                    /*****************************************************/

                    if (vec_client.at(i - 1).status == LOGIN) {

                        //L'Utente non ha ancora loggato con il suo username, perciò si attende l'invio dello username da parte del utente
                        //ricezione dimensione username 
                        rc = recv(fds[i].fd, (void *) &lmsg, sizeof(uint16_t), 0);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "recv() size username failed" << endl;
                                close_conn = true;
                            }
                            break;
                        }

                        if (rc == 0) {
                            cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                 << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }


                        len_msg = ntohs(lmsg); // Rinconverto in formato host
                        //cout<<"DIMENSIONE USERNAME: "<<len_msg<<endl;

                        char tmp_msg[len_msg];

                        //ricezione username
                        rc = recv(fds[i].fd, (void *) tmp_msg, len_msg, 0);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "recv() username failed" << endl;
                                close_conn = true;
                            }
                            break;
                        }

                        /*****************************************************/
                        /* Check to see if the connection has been           */
                        /* closed by the client                              */
                        /*****************************************************/
                        if (rc == 0) {
                            cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                 << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }

                        string tmp_username = tmp_msg;

                        /* Sanitize username to avoid path-traversal */
                        tmp_username.erase(remove_if(tmp_username.begin(), tmp_username.end(), [](unsigned char c) {
                            return !isalnum(c);
                        }), tmp_username.end());

                        bool twice_logged = false;

                        for (int h = 0; h < vec_client.size(); h++) {
                            client client = vec_client[h];
                            if (client.username == tmp_username) {
                                // user is already logged in
                                cout << "[server] User " << tmp_username
                                     << " is already logged in on this server. Disconnecting..." << endl;
                                close_conn = true;
                                twice_logged = true;
                                break;
                            }
                        }

                        if (twice_logged)
                            break;

                        string client_pubkey_file_name = "pubkeys/" + tmp_username + "_pubkey.pem";
                        FILE *client_pubkey_file = fopen(client_pubkey_file_name.c_str(), "r");
                        if (!client_pubkey_file) {
                            cout << "[server] User not registered on this server! Disconnecting..." << endl;
                            close_conn = true;
                            break;
                        }
                        fclose(client_pubkey_file);

                        /*****************************************************/
                        /* Data was received                                 */
                        /*****************************************************/
                        vec_client.at(i - 1).username = tmp_username;

                        //printf("Username ricevuto dal client: %s\n", tmp);
                        cout << "[server] Client with address " << addr_to_string(vec_client.at(i - 1).client_addr)
                             << " logged with Username: "
                             << vec_client.at(i - 1).username << endl;
                        number_of_users_online++; //incremento poichè di default un utente ha stato online
                        vec_client.at(i - 1).status = ONLINE;
                        //cout << "[server] Client authenticated" << endl;

                        //INVIO NONCE AL CLIENT
                        cout << "[server] Sending nonce to " << vec_client.at(i - 1).username << endl;
                        RAND_poll();
                        unsigned char nonce_server[NONCE_SIZE];
                        RAND_bytes(nonce_server, NONCE_SIZE);

                        rc = send(fds[i].fd, (void *) nonce_server, NONCE_SIZE, 0);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "[server] send size nonce failed" << endl;
                                close_conn = true;
                            }
                            break;
                        }
                        /*printf("INVIATO N_S ");
                                for (unsigned char x : nonce_server) {
                                    printf("%x", x);
                                }
                        printf("\n");*/

                        //RICEZIONE DEL NONCE GENERATO DAL CLIENT
                        cout << "[server] Receiving nonce generated by" << vec_client.at(i - 1).username << endl;
                        rc = recv(fds[i].fd, (void *) vec_client.at(i - 1).nonce_client, NONCE_SIZE, 0);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "[server] Error encountered in receiving nonce generated by "
                                     << vec_client.at(i - 1).username << endl;
                                close_conn = true;
                            }
                            break;
                        }
                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }

                        /*printf("RICEVUTO N_C ");
                                for (unsigned char x : vec_client.at(i-1).nonce_client) {
                                    printf("%x", x);
                                }
                        printf("\n");*/

                        //Negoziazione chiave simmetrica con il client => DH

                        cout << "[server] Start: loading standard DH parameters with "
                             << addr_to_string(vec_client.at(i - 1).client_addr) << endl;
                        EVP_PKEY *params;
                        if (nullptr == (params = EVP_PKEY_new())) {
                            cerr << "[server] Error during the creation of params" << endl;
                            close_conn = true;
                            break;
                        }
                        DH *temp = get_dh2048();
                        if (1 != EVP_PKEY_set1_DH(params, temp)) {
                            cerr << "[server] Error during setting params" << endl;
                            close_conn = true;
                            break;
                        }
                        DH_free(temp);
                        /*cout << "Generating ephemeral DH KeyPair with "
                             << addr_to_string(vec_client.at(i - 1).client_addr) << endl;*/

                        /* Create context for the key generation */
                        EVP_PKEY_CTX *DHctx;
                        if (!(DHctx = EVP_PKEY_CTX_new(params, nullptr))) {
                            cerr << "[server] Error during the creation of params" << endl;
                            close_conn = true;
                            break;
                        }
                        //cout << "eseguita creazione contesto" << endl;

                        /* Generate a new key */

                        EVP_PKEY *my_dhkey = nullptr;
                        if (1 != EVP_PKEY_keygen_init(DHctx)) {
                            cerr << "[server] Error during keygen_init" << endl;
                            close_conn = true;
                            break;
                        }
                        //cout << "eseguita init key gen int " << endl;
                        if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) {
                            cerr << "[server] Error during keygen" << endl;
                            close_conn = true;
                            break;
                        }
                        //cout << "eseguita key gen" << endl;

                        //RICEZIONE CHIAVE PUBBLICA DH CLIENT

                        //Ricezione dimensione chiave pubblica DH client
                        uint64_t pubkey_DH_client_size_rcv = 0;
                        rc = recv(fds[i].fd, (void *) &pubkey_DH_client_size_rcv, sizeof(uint64_t), MSG_WAITALL);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "[server] Error encountered in reception of size of DH client's public key !"
                                     << endl;
                                close_conn = true;
                            }
                            break;
                        }
                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }

                        //cout<< "Ricevuta chiave pubblica DH client"<<endl;
                        //cout << ntohs(cert_size_rcv) << endl;

                        //Ricezione chiave pubblica DH client
                        auto *pubkey_DH_client = (unsigned char *) malloc(ntohs(pubkey_DH_client_size_rcv));
                        rc = recv(fds[i].fd, pubkey_DH_client, ntohs(pubkey_DH_client_size_rcv), MSG_WAITALL);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "[server] Error encountered in reception of  DH client's public key!" << endl;
                                close_conn = true;
                            }
                            break;
                        }
                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }
                        //cout<<"Ricevuto da: "<<vec_client.at(i - 1).username<<" La seguente chiave Pubblica DH "<<endl;
                        //BIO_dump_fp(stdout, (const char *) pubkey_DH_client, ntohs(pubkey_DH_client_size_rcv));


                        BIO *mbio_rcv = BIO_new(BIO_s_mem());
                        BIO_write(mbio_rcv, pubkey_DH_client, ntohs(pubkey_DH_client_size_rcv));
                        EVP_PKEY *client_DH_pubkey = PEM_read_bio_PUBKEY(mbio_rcv, nullptr, nullptr, nullptr);
                        //Ricezione dimensione della sign
                        uint64_t sign_client_size_rcv = 0;
                        rc = recv(fds[i].fd, (void *) &sign_client_size_rcv, sizeof(uint64_t), 0);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "[server] Error encountered in reception of digest sign size !"
                                     << endl;
                                close_conn = true;
                            }
                            break;
                        }
                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }


                        //Ricezione sign(pubkey_DH_client, nonce_client, nonce_server)
                        auto *sign_client_rcvd = (unsigned char *) malloc(
                                ntohs(sign_client_size_rcv)); //QUI DENTRO C'E' IL DIGEST => RICORDARSI DI FARE LA FREE DOPO AVER FATTO LA VERIFY
                        rc = recv(fds[i].fd, (void *) sign_client_rcvd, ntohs(sign_client_size_rcv), 0);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "[server] Error encountered in reception of digest sign!" << endl;
                                close_conn = true;
                            }
                            break;
                        }
                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }
                        //cout<<"Ricevuto da: "<<vec_client.at(i - 1).username<<" il seguente digest "<<endl;
                        //BIO_dump_fp(stdout, (const char *) sign_client_rcvd, ntohs(sign_client_size_rcv));


                        //VERIFICA DEL DIGEST INVIATO DAL CLIENT
                        //EVP_PKEY *client_pubkey;
                        string file_name = "pubkeys/" + vec_client.at(i - 1).username + "_pubkey.pem";
                        FILE *file = fopen(file_name.c_str(), "r");
                        if (!file) {
                            cout << "[server] error in opening file PEM" << endl;
                            close_conn = true;
                            break;
                        }
                        vec_client.at(i - 1).client_pubkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
                        if (!vec_client.at(i - 1).client_pubkey) {
                            cout << "[server] error in reading client public key" << endl;
                            close_conn = true;
                            break;
                        }
                        fclose(file);

                        long int to_verify_size = (NONCE_SIZE * 2) + ntohs(pubkey_DH_client_size_rcv);
                        auto *buf_to_verify = (unsigned char *) malloc(to_verify_size);

                        memcpy(buf_to_verify, pubkey_DH_client, ntohs(pubkey_DH_client_size_rcv));
                        memcpy(buf_to_verify + ntohs(pubkey_DH_client_size_rcv), vec_client.at(i - 1).nonce_client,
                               NONCE_SIZE);
                        memcpy(buf_to_verify + ntohs(pubkey_DH_client_size_rcv) + NONCE_SIZE, nonce_server, NONCE_SIZE);
                        free(pubkey_DH_client);

                        EVP_MD_CTX *md_ctx_sk = EVP_MD_CTX_new();
                        const EVP_MD *md = EVP_sha256();
                        if (!md_ctx_sk) {
                            cout << "[server] error in EVP_MD_CTX_new" << endl;
                            close_conn = true;
                            break;
                        }

                        rc = EVP_VerifyInit(md_ctx_sk, md);
                        if (rc == 0) {
                            cout << "[server] error in VerifyInit" << endl;
                            close_conn = true;
                            break;
                        }
                        rc = EVP_VerifyUpdate(md_ctx_sk, buf_to_verify, to_verify_size);
                        if (rc == 0) {
                            cout << "[server] error in VerifyUpdate" << endl;
                            close_conn = true;
                            break;
                        }
                        rc = EVP_VerifyFinal(md_ctx_sk, sign_client_rcvd, ntohs(sign_client_size_rcv),
                                             vec_client.at(i - 1).client_pubkey);
                        if (rc != 1) {
                            cout
                                    << "[server]The signature of (chiave_DH_Client + nonce_client + nonce_server) has NOT been verified correctly"
                                    << endl;
                            close_conn = true;
                            break;
                        }

                        cout
                                << "[server] The signature of (chiave_DH_Client + nonce_client + nonce_server) has been verified correctly"
                                << endl;
                        free(buf_to_verify);
                        BIO_free(mbio_rcv);
                        free(sign_client_rcvd);

                        //Preparazione del messaggio da firmare chiavePubblicaDHCLient + N_C + N_S
                        BIO *mbio_snd = BIO_new(BIO_s_mem());
                        PEM_write_bio_PUBKEY(mbio_snd, my_dhkey);
                        char *pubkey_DH_buf = nullptr;
                        long pubkey_DH_size = BIO_get_mem_data(mbio_snd, &pubkey_DH_buf);

                        //invio dimensione chiave pubblica DH del server al client
                        uint64_t pubkey_DH_size_snd = htons(pubkey_DH_size);
                        rc = send(fds[i].fd, (void *) &pubkey_DH_size_snd, sizeof(uint64_t), 0);
                        if (rc < 0) {
                            cerr << "[server] Error sending public key DH size" << endl;
                            if (rc < 0) {
                                if (errno != EWOULDBLOCK) {
                                    cerr << "[server] send size nonce failed" << endl;
                                    close_conn = true;
                                }
                                break;
                            }
                        }
                        //cout<<"Dimensione public key DH "<<pubkey_DH_size<<endl;

                        //invio chiave pubblica DH del server al client
                        rc = send(fds[i].fd, pubkey_DH_buf, pubkey_DH_size, 0);
                        if (rc < 0) {
                            cerr << "[server] Error sending public key DH" << endl;
                            if (rc < 0) {
                                if (errno != EWOULDBLOCK) {
                                    cerr << "[server] send size nonce failed" << endl;
                                    close_conn = true;
                                }
                                break;
                            }
                        }
                        //cout<<"Inviata la seguente chiave pubblica DH: "<<endl;
                        //BIO_dump_fp(stdout, (const char *) pubkey_DH_buf, pubkey_DH_size);


                        long int to_sign_size = (NONCE_SIZE * 2) + pubkey_DH_size;
                        auto *buf_to_sign = (unsigned char *) malloc(to_sign_size);

                        memcpy(buf_to_sign, pubkey_DH_buf, pubkey_DH_size);
                        memcpy(buf_to_sign + pubkey_DH_size, vec_client.at(i - 1).nonce_client, NONCE_SIZE);
                        memcpy(buf_to_sign + pubkey_DH_size + NONCE_SIZE, nonce_server, NONCE_SIZE);

                        FILE *prvkey_file = fopen("prvkey.pem", "r");
                        if (!prvkey_file) {
                            cerr << "[server] cannot open file containing the privkey" << endl;
                            close_conn = true;
                            break;
                        }
                        char password[] = "foc2020";
                        EVP_PKEY *prvkey = PEM_read_PrivateKey(prvkey_file, nullptr, nullptr, password);
                        fclose(prvkey_file);
                        if (!prvkey) {
                            cerr << "[server] read privKey failed" << endl;
                            close_conn = true;
                            break;
                        }

                        // create the signature context:
                        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
                        if (!md_ctx) {
                            cerr << "[server] EVP_MD_CTX_new returned nullptr" << endl;
                        }

                        auto *sgnt_buf = (unsigned char *) malloc(EVP_PKEY_size(prvkey));
                        if (!sgnt_buf) {
                            cerr << "[server] malloc returned nullptr" << endl;
                            close_conn = true;
                            break;
                        }

                        rc = EVP_SignInit(md_ctx, md);
                        if (rc == 0) {
                            cerr << "[server] EVP_SignInit returned " << rc << endl;
                            close_conn = true;
                            break;

                        }
                        rc = EVP_SignUpdate(md_ctx, buf_to_sign, to_sign_size);
                        if (rc == 0) {
                            cerr << "[server] EVP_SignUpdate returned " << rc << endl;
                            close_conn = true;
                            break;

                        }
                        unsigned int sgnt_size;
                        rc = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
                        if (rc == 0) {
                            cerr << "[server] EVP_SignFinal returned " << rc << endl;
                            close_conn = true;
                            break;
                        }

                        //invio dimensione sign al client

                        uint64_t hash_size_snd = htons(sgnt_size);
                        rc = send(fds[i].fd, (void *) &hash_size_snd, sizeof(uint64_t), 0);
                        if (rc < 0) {
                            cerr << "[server] Error sending digest size" << endl;
                            if (rc < 0) {
                                if (errno != EWOULDBLOCK) {
                                    cerr << "[server] send size nonce failed" << endl;
                                    close_conn = true;
                                }
                                break;
                            }
                        }
                        //cout<<"Dimensione hash da inviare: "<<sgnt_size<<endl;

                        //invio del digest al client
                        rc = send(fds[i].fd, (void *) sgnt_buf, sgnt_size, 0);
                        if (rc < 0) {
                            cerr << "[server] Error sending digest " << endl;
                            if (rc < 0) {
                                if (errno != EWOULDBLOCK) {
                                    cerr << "[server] send size nonce failed" << endl;
                                    close_conn = true;
                                }
                                break;
                            }
                        }

                        BIO_free(mbio_snd);
                        //cout<<"Inviato digest della sign: "<<endl;
                        //BIO_dump_fp(stdout, (const char *) sgnt_buf, sgnt_size);

                        //DERIVAZIONE DEL SEGRETO

                        cout << "[server] Deriving a shared secret with "
                             << addr_to_string(vec_client.at(i - 1).client_addr) << endl;
                        /*creating a context, the buffer for the shared key and an int for its length*/
                        EVP_PKEY_CTX *derive_ctx;
                        unsigned char *skey;
                        size_t skeylen;
                        derive_ctx = EVP_PKEY_CTX_new(my_dhkey, nullptr);
                        if (!derive_ctx) {
                            cerr << "[server] EVP_PKEY_CTX_new failed";
                            close_conn = true;
                            break;
                        }
                        if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
                            cerr << "[server] derive_init failed" << endl;
                            close_conn = true;
                            break;
                        }
                        /*Setting the peer with its pubkey*/
                        if (EVP_PKEY_derive_set_peer(derive_ctx, client_DH_pubkey) <= 0) {
                            cerr << "[server] derive_set_peer" << endl;
                            close_conn = true;
                            break;
                        }

                        /* Determine buffer length, by performing a derivation but writing the result nowhere */
                        EVP_PKEY_derive(derive_ctx, nullptr, &skeylen);

                        /*allocate buffer for the shared secret*/
                        skey = (unsigned char *) (malloc(int(skeylen)));
                        if (!skey) {
                            cerr << "[server] malloc failed" << endl;
                            close_conn = true;
                            break;
                        }

                        /*Perform again the derivation and store it in skey buffer*/
                        if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) {
                            cerr << "[server] EVP_PKEY_derive failed" << endl;
                            close_conn = true;
                            break;
                        }

                        cout << "[server] Here it is the shared secret: with "
                             << addr_to_string(vec_client.at(i - 1).client_addr) << endl;
                        BIO_dump_fp(stdout, (const char *) skey, skeylen);

                        EVP_PKEY_CTX_free(derive_ctx);
                        EVP_PKEY_free(client_DH_pubkey);
                        EVP_PKEY_free(my_dhkey);
                        EVP_PKEY_CTX_free(DHctx);
                        EVP_PKEY_free(params);

                        //CREAZIONE DELLA CHIAVE DI SESSIONE UTILIZZANDO IL SEGRETO CONDIVISO

                        auto *digest_ss = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()));
                        unsigned int digestlen;
                        EVP_MD_CTX *md_ctx_hash;
                        md_ctx_hash = EVP_MD_CTX_new();
                        EVP_DigestInit(md_ctx_hash, md);
                        EVP_DigestUpdate(md_ctx_hash, (unsigned char *) skey, skeylen);
                        EVP_DigestFinal(md_ctx_hash, digest_ss, &digestlen);
                        EVP_MD_CTX_free(md_ctx_hash);
                        //cout << "The dimension of the digest is:" << digestlen << endl;
                        memcpy(vec_client.at(i - 1).session_key, digest_ss, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
#pragma optimize("", off);
                        memset(digest_ss, 0, digestlen);
                        memset(skey, 0, skeylen);
#pragma optimize("", on);
                        free(digest_ss);
                        free(skey);
                        cout << "[server] The session key is: "
                             << BIO_dump_fp(stdout, (const char *) vec_client.at(i - 1).session_key,
                                            EVP_CIPHER_key_length(EVP_aes_128_gcm())) << endl;

                        EVP_MD_CTX_free(md_ctx);
                        EVP_PKEY_free(prvkey);

                        //RICEZIONE DELLA PORTA DI ASCOLTO DEL CLIENT
                        auto gcm_msg_list_port = (unsigned char *) malloc(
                                12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                        rc = recv(fds[i].fd, (void *) gcm_msg_list_port,
                                  (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                  MSG_WAITALL);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "recv() opcode failed" << endl;
                                close_conn = true;
                            }
                            break;
                        }

                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }

                        unsigned char aad_list_port[12 + sizeof(uint32_t)];
                        unsigned char iv_list_port[12];
                        unsigned char tag_buf_list_port[16];
                        auto cphr_buf_list_port = (unsigned char *) malloc(sizeof(uint16_t));
                        auto plain_buf_list_port = (unsigned char *) malloc(sizeof(uint16_t));
                        memcpy(aad_list_port, gcm_msg_list_port, 12 + sizeof(uint32_t));
                        memcpy(iv_list_port, gcm_msg_list_port, 12);
                        memcpy(cphr_buf_list_port, gcm_msg_list_port + 12 + sizeof(uint32_t), sizeof(uint16_t));
                        memcpy(tag_buf_list_port, gcm_msg_list_port + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                        int res = gcm_decrypt(cphr_buf_list_port, sizeof(uint16_t), vec_client.at(i - 1).cnt,
                                              aad_list_port, tag_buf_list_port, vec_client.at(i - 1).session_key,
                                              iv_list_port, 12, plain_buf_list_port);
                        if (res == -2) {
                            cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                 << "'s counter out of sync. Disconnecting..." << endl;
                            close_conn = true;
                            break;
                        }
                        if (res == -1) {
                            cout << "[server] Error encountered in decryption of message from client "
                                 << addr_to_string(vec_client.at(i - 1).client_addr) << "." << endl;
                            close_conn = true;
                            break;
                        }

                        uint16_t listening_port = *(uint16_t *) plain_buf_list_port;
                        vec_client.at(i - 1).listening_port_client = ntohs(listening_port);
                        cout << vec_client.at(i - 1).listening_port_client << endl;

                        // Free up memory
                        free(gcm_msg_list_port);
                        free(cphr_buf_list_port);
                        free(plain_buf_list_port);


                    } else if (vec_client.at(i - 1).status == ONLINE || vec_client.at(i - 1).status == MATCHMAKING ||
                               vec_client.at(i - 1).status == PLAYING) {
                        //Utente loggato quindi attesa della ricezione di un comando inviato da lui

                        /*** GCM message format: [AAD (IV + CNT) | OPCODE | TAG] ***/
                        auto gcm_msg = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                        rc = recv(fds[i].fd, (void *) gcm_msg, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                  MSG_WAITALL);
                        if (rc < 0) {
                            if (errno != EWOULDBLOCK) {
                                cerr << "recv() opcode failed" << endl;
                                close_conn = true;
                            }
                            break;
                        }

                        if (rc == 0) {
                            cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr) << ":"
                                 << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                 << vec_client.at(i - 1).username << " disconnected." << endl;
                            close_conn = true;
                            break;
                        }

                        unsigned char aad[12 + sizeof(uint32_t)];
                        unsigned char iv[12];
                        unsigned char tag_buf[16];
                        auto cphr_buf = (unsigned char *) malloc(sizeof(uint16_t));
                        auto plain_buf = (unsigned char *) malloc(sizeof(uint16_t));
                        memcpy(aad, gcm_msg, 12 + sizeof(uint32_t));
                        memcpy(iv, gcm_msg, 12);
                        memcpy(cphr_buf, gcm_msg + 12 + sizeof(uint32_t), sizeof(uint16_t));
                        memcpy(tag_buf, gcm_msg + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                        int res = gcm_decrypt(cphr_buf, sizeof(uint16_t), vec_client.at(i - 1).cnt, aad, tag_buf,
                                              vec_client.at(i - 1).session_key, iv, 12, plain_buf);
                        if (res == -2) {
                            cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                 << "'s counter out of sync. Disconnecting..." << endl;
                            close_conn = true;
                            break;
                        }
                        if (res == -1) {
                            cout << "[server] Error encountered in decryption of message from client "
                                 << addr_to_string(vec_client.at(i - 1).client_addr) << "." << endl;
                            close_conn = true;
                            break;
                        }

                        opcode_rcvd = *(uint16_t *) plain_buf;
                        opcode = ntohs(opcode_rcvd);

                        // Free up memory
                        free(gcm_msg);
                        free(cphr_buf);
                        free(plain_buf);

                        //cout<<"OPCODE RICEVUTO dal client: "<<opcode<<endl;

                        if (opcode == SHOW_ONLINE_USERS_OPC) {
                            cout << "[server] Request to show online users by " << vec_client.at(i - 1).username
                                 << endl;
                            //Invio lunghezza lista utenti
                            number_of_users_matchmaking_snd = htons(
                                    number_of_users_matchmaking); // L'utente che fa la richiesta non è tra quelli in matchmaking
                            unsigned char aad_num_users[12 + sizeof(uint32_t)];
                            unsigned char tag_buf_num_users[16];
                            auto cphr_buf_num_users = (unsigned char *) malloc(sizeof(uint16_t));
                            auto gcm_msg_num_users = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                            int res = gcm_encrypt((unsigned char *) &number_of_users_matchmaking_snd, sizeof(uint16_t), vec_client.at(i - 1).cnt, aad_num_users, vec_client.at(i - 1).session_key, cphr_buf_num_users, tag_buf_num_users);
                            memcpy(gcm_msg_num_users, aad_num_users, 12 + sizeof(uint32_t));
                            memcpy(gcm_msg_num_users + 12 + sizeof(uint32_t), cphr_buf_num_users, sizeof(uint16_t));
                            memcpy(gcm_msg_num_users + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_num_users, 16);
                            int ret = send(fds[i].fd, (void *) gcm_msg_num_users,
                                               (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                
                            if (ret <= 0) {
                                cerr << "[server] send() Challenge status failed" << endl;
                                close_conn = true;
                                break;
                            }
                            free(cphr_buf_num_users);
                            free(gcm_msg_num_users);

                            for (size_t k = 0; k < vec_client.size(); k++) {
                                if (vec_client.at(k).status == MATCHMAKING && k != (i - 1)) {
                                    //invio lunghezza username j-simo
                                    len = vec_client.at(k).username.size() + 1;
                                    lmsg = htons(len);

                                    unsigned char aad_users_len[12 + sizeof(uint32_t)];
                                    unsigned char tag_buf_users_len[16];
                                    auto cphr_buf_users_len = (unsigned char *) malloc(sizeof(uint16_t));
                                    auto gcm_msg_users_len = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                    int res_users_len = gcm_encrypt((unsigned char *) &lmsg, sizeof(uint16_t), vec_client.at(i - 1).cnt, aad_users_len, vec_client.at(i - 1).session_key, cphr_buf_users_len, tag_buf_users_len);
                                    memcpy(gcm_msg_users_len, aad_users_len, 12 + sizeof(uint32_t));
                                    memcpy(gcm_msg_users_len + 12 + sizeof(uint32_t), cphr_buf_users_len, sizeof(uint16_t));
                                    memcpy(gcm_msg_users_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_users_len, 16);
                                    ret = send(fds[i].fd, (void *) gcm_msg_users_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                    free(cphr_buf_users_len);
                                    free(gcm_msg_users_len);
                                    if (ret <= 0) {
                                    	cerr << "[server] send() users len failed" << endl;
                                    	close_conn = true;
                                   	break;
                                    }

                                    //invio username j-simo corrispondente ad un utente online
                                    char tmp_msg[len];
                                    /* DA CONTROLLARE */
                                    sprintf(tmp_msg, "%s", vec_client.at(k).username.c_str());
                                    
                                    unsigned char aad_users[12 + sizeof(uint32_t)];
                                    unsigned char tag_buf_users[16];
                                    auto cphr_buf_users = (unsigned char *) malloc(len);
                                    auto gcm_msg_users = (unsigned char *) malloc(12 + sizeof(uint32_t) + len + 16);
                                    int res_username_challenge = gcm_encrypt((unsigned char *) tmp_msg, len, vec_client.at(i - 1).cnt, aad_users, vec_client.at(i - 1).session_key, cphr_buf_users, tag_buf_users);
                                    memcpy(gcm_msg_users, aad_users, 12 + sizeof(uint32_t));
                                    memcpy(gcm_msg_users + 12 + sizeof(uint32_t), cphr_buf_users,len);
                                    memcpy(gcm_msg_users + 12 + sizeof(uint32_t) + len, tag_buf_users, 16);
                                    ret = send(fds[i].fd, (void *) gcm_msg_users, (12 + sizeof(uint32_t) + len + 16), 0);
                                    free(cphr_buf_users);
                                    free(gcm_msg_users);
                                    if (ret <= 0) {
                                   	cerr << "[server] send() Challenge status failed" << endl;
                                    	close_conn = true;
                                   	break;
                                    }
                                    
                                    cout << "Sent: " << vec_client.at(k).username.c_str() << " bytes" << endl;
                                }
                            }
                        } else if (opcode == WAITING_REQ_OPC) {
                            cout << "[server] Request to wait challenges by " << vec_client.at(i - 1).username << endl;
                            vec_client.at(i - 1).status = MATCHMAKING;
                            number_of_users_matchmaking++;

                        } else if (opcode == END_OF_MATCHMAKING) {
                            cout << "[server] Command of end matchmaking by " << vec_client.at(i - 1).username << endl;
                            vec_client.at(i - 1).status = ONLINE;
                            number_of_users_matchmaking--;

                        } else if (opcode == CHALLENGE_REQUEST_OPC) {

                            //Ricevuto richiesta di sfida da parte di uno user

                            cout << "[server] Request to challenge user by " << vec_client.at(i - 1).username
                                 << endl;
                            auto gcm_user_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);

                            //Ricezione lunghezza username destinatario della richiesta di sfida 

                            rc = recv(fds[i].fd, (void *) gcm_user_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                      MSG_WAITALL);
                            if (rc < 0) {
                                if (errno != EWOULDBLOCK) {
                                    cerr << "recv() opcode failed" << endl;
                                    close_conn = true;
                                }
                                break;
                            }

                            if (rc == 0) {
                                cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr)
                                     << ":"
                                     << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                     << vec_client.at(i - 1).username << " disconnected." << endl;
                                close_conn = true;
                                break;
                            }

                            unsigned char aad_user_len[12 + sizeof(uint32_t)];
                            unsigned char iv_user_len[12];
                            unsigned char tag_buf_user_len[16];
                            auto cphr_buf_user_len = (unsigned char *) malloc(sizeof(uint16_t));
                            auto plain_buf_user_len = (unsigned char *) malloc(sizeof(uint16_t));
                            memcpy(aad_user_len, gcm_user_len, 12 + sizeof(uint32_t));
                            memcpy(iv_user_len, gcm_user_len, 12);
                            memcpy(cphr_buf_user_len, gcm_user_len + 12 + sizeof(uint32_t), sizeof(uint16_t));
                            memcpy(tag_buf_user_len, gcm_user_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                            int res_user_len = gcm_decrypt(cphr_buf_user_len, sizeof(uint16_t),
                                                           vec_client.at(i - 1).cnt, aad_user_len, tag_buf_user_len,
                                                           vec_client.at(i - 1).session_key, iv_user_len, 12,
                                                           plain_buf_user_len);
                            if (res_user_len == -2) {
                                cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                     << "'s counter out of sync. Disconnecting..." << endl;
                                close_conn = true;
                                break;
                            }
                            if (res_user_len == -1) {
                                cout << "[server] Error encountered in decryption of message from client "
                                     << addr_to_string(vec_client.at(i - 1).client_addr) << "." << endl;
                                close_conn = true;
                                break;
                            }

                            uint16_t username_len = *(uint16_t *) plain_buf_user_len;
                            uint16_t username_len_real = ntohs(username_len);

                            cout << "Lunghezza username: " << username_len_real << endl;

                            // Free up memory
                            free(gcm_user_len);
                            free(cphr_buf_user_len);
                            free(plain_buf_user_len);

                            //Ricezione dello username destinatario della richiesta di sfida 
                            char username_to_challenge[username_len_real];

                            auto gcm_user_challenge = (unsigned char *) malloc(
                                    12 + sizeof(uint32_t) + username_len_real + 16);
                            rc = recv(fds[i].fd, (void *) gcm_user_challenge,
                                      (12 + sizeof(uint32_t) + username_len_real + 16),
                                      MSG_WAITALL);
                            if (rc < 0) {
                                if (errno != EWOULDBLOCK) {
                                    cerr << "[server] recv username to challenge failed" << endl;
                                    close_conn = true;
                                }
                                break;
                            }

                            if (rc == 0) {
                                cout << "[server] Client " << inet_ntoa(vec_client.at(i - 1).client_addr.sin_addr)
                                     << ":"
                                     << ntohs(vec_client[i - 1].client_addr.sin_port) << " Username: "
                                     << vec_client.at(i - 1).username << " disconnected." << endl;
                                close_conn = true;
                                break;
                            }

                            unsigned char aad_user_challenge[12 + sizeof(uint32_t)];
                            unsigned char iv_user_challenge[12];
                            unsigned char tag_buf_user_challenge[16];
                            auto cphr_buf_user_challenge = (unsigned char *) malloc(username_len_real);
                            memcpy(aad_user_challenge, gcm_user_challenge, 12 + sizeof(uint32_t));
                            memcpy(iv_user_challenge, gcm_user_challenge, 12);
                            memcpy(cphr_buf_user_challenge, gcm_user_challenge + 12 + sizeof(uint32_t),
                                   username_len_real);
                            memcpy(tag_buf_user_challenge,
                                   gcm_user_challenge + 12 + sizeof(uint32_t) + username_len_real, 16);
                            int res_user_challenge = gcm_decrypt(cphr_buf_user_challenge, username_len_real,
                                                                 vec_client.at(i - 1).cnt, aad_user_challenge,
                                                                 tag_buf_user_challenge,
                                                                 vec_client.at(i - 1).session_key, iv_user_challenge,
                                                                 12, (unsigned char *) username_to_challenge);
                            if (res == -2) {
                                cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                     << "'s counter out of sync. Disconnecting..." << endl;
                                close_conn = true;
                                break;
                            }
                            if (res == -1) {
                                cout << "[server] Error encountered in decryption of message from client "
                                     << addr_to_string(vec_client.at(i - 1).client_addr) << "." << endl;
                                close_conn = true;
                                break;
                            }

                            string user_challenge = (char *) username_to_challenge;
                            user_challenge.erase(
                                    remove_if(user_challenge.begin(), user_challenge.end(), [](unsigned char c) {
                                        return !isalnum(c);
                                    }), user_challenge.end());
                            cout << "Username: " << user_challenge << endl;

                            // Free up memory
                            free(gcm_user_challenge);
                            free(cphr_buf_user_challenge);

                            //Verifica dello stato attuale dello user destinatario della richiesta di sfida 
                            bool found = false;
                            uint16_t user_challenge_status = OFFLINE;
                            string tmp_ip_address_challenge;
                            int index_socket_user = 0;

                            for (int z = 0; z < vec_client.size(); z++) {
                                client tmp_client = vec_client[z];
                                if (tmp_client.username == user_challenge) {
                                    if (tmp_client.status == MATCHMAKING) {
                                        user_challenge_status = tmp_client.status;
                                        tmp_ip_address_challenge = addr_to_string(vec_client.at(z).client_addr);
                                    } else user_challenge_status = ONLINE;
                                    found = true;
                                    index_socket_user = z + 1;
                                    break;
                                }
                            }

                            if (vec_client.at(i - 1).username == user_challenge) {
                                user_challenge_status = ERROR_CHALLENGE_SELF;
                                found = true;
                            }

                            cout << user_challenge_status << endl;
                            if (!found) {
                                string client_pubkey_file_name = "pubkeys/" + user_challenge + "_pubkey.pem";
                                FILE *client_pubkey_file = fopen(client_pubkey_file_name.c_str(), "r");
                                if (client_pubkey_file) {
                                    cout << "[server] User is not online" << endl;
                                    fclose(client_pubkey_file);
                                } else {
                                    cout << "[server] User not registered on this server!" << endl;
                                    user_challenge_status = UNREGISTERED;
                                }
                            }

                            unsigned char aad_challenge_status[12 + sizeof(uint32_t)];
                            unsigned char tag_buf_challenge_status[16];
                            auto cphr_buf_challenge_status = (unsigned char *) malloc(sizeof(uint16_t));
                            auto gcm_msg_challenge_status = (unsigned char *) malloc(
                                    12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                            int res_challenge_status = gcm_encrypt((unsigned char *) &user_challenge_status,
                                                                   sizeof(uint16_t), vec_client.at(i - 1).cnt,
                                                                   aad_challenge_status,
                                                                   vec_client.at(i - 1).session_key,
                                                                   cphr_buf_challenge_status, tag_buf_challenge_status);
                            memcpy(gcm_msg_challenge_status, aad_challenge_status, 12 + sizeof(uint32_t));
                            memcpy(gcm_msg_challenge_status + 12 + sizeof(uint32_t), cphr_buf_challenge_status,
                                   sizeof(uint16_t));
                            memcpy(gcm_msg_challenge_status + 12 + sizeof(uint32_t) + sizeof(uint16_t),
                                   tag_buf_challenge_status, 16);

                            //invio dello stato attuale dell'utente destinatario della richiesta di sfida 

                            rc = send(fds[i].fd, (void *) gcm_msg_challenge_status,
                                      (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                            free(cphr_buf_challenge_status);
                            free(gcm_msg_challenge_status);
                            if (rc < 0) {
                                cerr << "[server] send() Challenge status failed" << endl;
                                close_conn = true;
                                break;
                            }

                            if (user_challenge_status == MATCHMAKING) {

                                vec_client.at(index_socket_user - 1).status = ONLINE;
                                number_of_users_matchmaking--;
                                opcode_snd = NEW_CHALLENGE_REQ_OPC;
                                opcode = htons(opcode_snd);
                                cout << "Invio opcode di richiesta: " << opcode_snd << endl;
                                unsigned char aad_req[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_req[16];
                                auto cphr_buf_req = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_req = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                int res = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t),
                                                      vec_client.at(index_socket_user - 1).cnt, aad_req,
                                                      vec_client.at(index_socket_user - 1).session_key, cphr_buf_req,
                                                      tag_buf_req);
                                memcpy(gcm_msg_req, aad_req, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_req + 12 + sizeof(uint32_t), cphr_buf_req, sizeof(uint16_t));
                                memcpy(gcm_msg_req + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_req, 16);
                                int ret = send(fds[index_socket_user].fd, (void *) gcm_msg_req,
                                               (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                free(cphr_buf_req);
                                free(gcm_msg_req);
                                if (ret <= 0) {
                                    cerr << "[server] send() Challenge status failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                //invio della dimensione dello username

                                unsigned int user_len_h = vec_client.at(i - 1).username.size() + 1;
                                uint16_t user_len = htons(user_len_h);

                                unsigned char aad_user_len[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_user_len[16];
                                auto cphr_buf_user_len = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_user_len = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                int res_user_len = gcm_encrypt((unsigned char *) &user_len, sizeof(uint16_t),
                                                               vec_client.at(index_socket_user - 1).cnt, aad_user_len,
                                                               vec_client.at(index_socket_user - 1).session_key,
                                                               cphr_buf_user_len, tag_buf_user_len);
                                memcpy(gcm_msg_user_len, aad_user_len, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_user_len + 12 + sizeof(uint32_t), cphr_buf_user_len, sizeof(uint16_t));
                                memcpy(gcm_msg_user_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_user_len,
                                       16);
                                ret = send(fds[index_socket_user].fd, (void *) gcm_msg_user_len,
                                           (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                free(cphr_buf_user_len);
                                free(gcm_msg_user_len);
                                if (ret <= 0) {
                                    cerr << "[server] send() Challenge status failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                char buffer_username_challenge[vec_client.at(i - 1).username.length()];
                                sprintf(buffer_username_challenge, "%s", vec_client.at(i - 1).username.c_str());

                                unsigned char aad_username_challenge[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_username_challenge[16];
                                auto cphr_buf_username_challenge = (unsigned char *) malloc(user_len_h);
                                auto gcm_msg_username_challenge = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + user_len_h + 16);
                                int res_username_challenge = gcm_encrypt((unsigned char *) buffer_username_challenge,
                                                                         user_len_h,
                                                                         vec_client.at(index_socket_user - 1).cnt,
                                                                         aad_username_challenge, vec_client.at(
                                                index_socket_user - 1).session_key, cphr_buf_username_challenge,
                                                                         tag_buf_username_challenge);
                                memcpy(gcm_msg_username_challenge, aad_username_challenge, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_username_challenge + 12 + sizeof(uint32_t), cphr_buf_username_challenge,
                                       user_len_h);
                                memcpy(gcm_msg_username_challenge + 12 + sizeof(uint32_t) + user_len_h,
                                       tag_buf_username_challenge, 16);
                                ret = send(fds[index_socket_user].fd, (void *) gcm_msg_username_challenge,
                                           (12 + sizeof(uint32_t) + user_len_h + 16), 0);
                                free(cphr_buf_username_challenge);
                                free(gcm_msg_username_challenge);
                                if (ret <= 0) {
                                    cerr << "[server] send() Challenge status failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                //Aspetto se il destinatario della sfida accetta o rifiuta
                                auto gcm_msg_resp = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);

                                struct pollfd pfd[2];
                                memset(pfd, 0, sizeof(pfd));
                                pfd[0].fd = fds[i].fd;
                                pfd[0].events = POLLIN;
                                pfd[1].fd = fds[index_socket_user].fd;
                                pfd[1].events = POLLIN;
                                //timeout = 0;
                                size_t npfd = 2;
                                auto gcm_msg_test = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                bool disconnected = false;
                                int ret_poll = poll(pfd, npfd, 10000);
                                if (ret_poll == 1) {
                                    for (size_t j = 0; j < 2; j++) {
                                        if (pfd[j].revents == 0)
                                            continue;
                                        if (pfd[j].revents != POLLIN) {
                                            cout << "Error! revents = " << pfd[j].revents << endl;
                                            close_conn = true;
                                            break;
                                        }
                                        if (pfd[j].fd == fds[i].fd) {
                                            int rc_req = recv(fds[i].fd, (void *) gcm_msg_test,
                                                              (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                                              MSG_WAITALL);
                                            if (rc_req < 0) {
                                                close_conn = true;
                                                break;
                                            }
                                            if (rc_req == 0) {
                                                cout << "[server] Client "
                                                     << addr_to_string(vec_client.at(i - 1).client_addr)
                                                     << " disconnected." << endl;
                                                int rc_req = recv(fds[index_socket_user].fd, (void *) gcm_msg_test,
                                                                  sizeof(uint16_t), MSG_WAITALL);
                                                cout << "è finito prima" << endl;
                                                //Inviare un opcode Disconnected
                                                disconnected = true;
                                                //continue; // si è disconnesso
                                            }
                                        } else {
                                            int rc_req = recv(fds[index_socket_user].fd, (void *) gcm_msg_test,
                                                              sizeof(uint16_t), MSG_WAITALL);
                                            cout << "è finito prima" << endl;
                                        }
                                    }
                                } else if (ret_poll == 0) {
                                    sleep(1);
                                    cout << "time out expired" << endl;
                                    int rc_req = recv(fds[index_socket_user].fd, (void *) gcm_msg_test,
                                                      sizeof(uint16_t), MSG_WAITALL);
                                    cout << "è finito prima" << endl;
                                }



                                /*struct timeval tv;
                                bool disconnected = false;
                                tv.tv_sec = 10; //timeout in seconds
                                tv.tv_usec = 0;
                                int res_rcv = setsockopt(fds[i].fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
                                if (res_rcv < 0) {
		                          cerr << "recv() setsockopt failed" << endl;
                                          close_conn = true;
                                          break;
                                }*/


                                //inviare un opcode Connected
                                //Sicuramente il destinatario avrà risposto perchè anche il suo tempo è scaduto (se Ricevo EXPIRED signidica che l'utente non ha fatto in tempo a rispondere e faccio continue)
                                if (disconnected)
                                    opcode_snd = DISCONNECTED;
                                else opcode_snd = CONNECTED;
                                opcode = htons(opcode_snd);
                                cout << "Invio opcode di richiesta: " << opcode_snd << endl;
                                unsigned char aad_conn[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_conn[16];
                                auto cphr_buf_conn = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_conn = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                int res_conn = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t),
                                                           vec_client.at(index_socket_user - 1).cnt, aad_conn,
                                                           vec_client.at(index_socket_user - 1).session_key,
                                                           cphr_buf_conn, tag_buf_conn);
                                memcpy(gcm_msg_conn, aad_conn, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_conn + 12 + sizeof(uint32_t), cphr_buf_conn, sizeof(uint16_t));
                                memcpy(gcm_msg_conn + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_conn, 16);
                                int ret_conn = send(fds[index_socket_user].fd, (void *) gcm_msg_conn,
                                                    (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                free(cphr_buf_conn);
                                free(gcm_msg_conn);
                                if (ret <= 0) {
                                    cerr << "[server] send() Challenge status failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                if (disconnected) {
                                    close_conn = true;
                                    continue;
                                }
                                //////////////////////////////////
                                rc = recv(fds[index_socket_user].fd, (void *) gcm_msg_resp,
                                          (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), MSG_WAITALL);
                                if (rc < 0) {
                                    if (errno != EWOULDBLOCK) {
                                        cerr << "recv() waiting response failed" << endl;
                                        close_conn = true;
                                    }
                                    break;
                                }

                                if (rc == 0) {
                                    cout << "[server] Client "
                                         << addr_to_string(vec_client.at(index_socket_user - 1).client_addr)
                                         << " disconnected." << endl;
                                    close_conn = true;
                                    continue; //è scaduto il tempo per rispondere
                                }
                                unsigned char aad_resp[12 + sizeof(uint32_t)];
                                unsigned char iv_resp[12];
                                unsigned char tag_buf_resp[16];
                                auto cphr_buf_resp = (unsigned char *) malloc(sizeof(uint16_t));
                                auto plain_buf_resp = (unsigned char *) malloc(sizeof(uint16_t));
                                memcpy(aad_resp, gcm_msg_resp, 12 + sizeof(uint32_t));
                                memcpy(iv_resp, gcm_msg_resp, 12);
                                memcpy(cphr_buf_resp, gcm_msg_resp + 12 + sizeof(uint32_t), sizeof(uint16_t));
                                memcpy(tag_buf_resp, gcm_msg_resp + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                                int res_resp = gcm_decrypt(cphr_buf_resp, sizeof(uint16_t),
                                                           vec_client.at(index_socket_user - 1).cnt, aad_resp,
                                                           tag_buf_resp,
                                                           vec_client.at(index_socket_user - 1).session_key, iv_resp,
                                                           12, plain_buf_resp);
                                if (res_resp == -2) {
                                    cout << "[server] Client " << addr_to_string(vec_client.at(i - 1).client_addr)
                                         << "'s counter out of sync. Disconnecting..." << endl;
                                    close_conn = true;
                                    break;
                                }
                                if (res_resp == -1) {
                                    cout << "[server] Error encountered in decryption of message from client "
                                         << addr_to_string(vec_client.at(i - 1).client_addr) << "." << endl;
                                    close_conn = true;
                                    break;
                                }

                                opcode_rcvd = *(uint16_t *) plain_buf_resp;
                                opcode = ntohs(opcode_rcvd);
                                free(gcm_msg_resp);
                                free(cphr_buf_resp);
                                free(plain_buf_resp);

                                cout << "Invio della risposta allo sfidante: " << opcode << endl;
                                unsigned char aad_reply[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_reply[16];
                                auto cphr_buf_reply = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_reply = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                int res_reply = gcm_encrypt((unsigned char *) &opcode_rcvd, sizeof(uint16_t),
                                                            vec_client.at(i - 1).cnt, aad_reply,
                                                            vec_client.at(i - 1).session_key, cphr_buf_reply,
                                                            tag_buf_reply);
                                memcpy(gcm_msg_reply, aad_reply, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_reply + 12 + sizeof(uint32_t), cphr_buf_reply, sizeof(uint16_t));
                                memcpy(gcm_msg_reply + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_reply, 16);

                                int ret_reply = send(fds[i].fd, (void *) gcm_msg_reply,
                                                     (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                free(cphr_buf_reply);
                                free(gcm_msg_reply);
                                cout << "ret_reply send: " << ret_reply << endl;
                                if (ret_reply <= 0) {
                                    cerr << "[server] send() Challenge status failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                if (opcode == CHALLENGE_ACCEPTED) {
                                    cout << "Challenge has been accepted by: "
                                         << vec_client.at(index_socket_user - 1).username << endl;
                                } else {
                                    cout << "Challenge has been refused by: "
                                         << vec_client.at(index_socket_user - 1).username << endl;
                                    continue;
                                }

                                //Invio l'indirizzo IP dello sfidante all'utente destinatario della richiesta di sfida

                                unsigned int IP_len_challenge =
                                        addr_to_string(vec_client.at(i - 1).client_addr).size() + 1;
                                uint16_t IP_len = htons(IP_len_challenge);

                                unsigned char aad_IP_len[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_IP_len[16];
                                auto cphr_buf_IP_len = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_IP_len = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                int res_IP_len = gcm_encrypt((unsigned char *) &IP_len, sizeof(uint16_t),
                                                             vec_client.at(index_socket_user - 1).cnt, aad_IP_len,
                                                             vec_client.at(index_socket_user - 1).session_key,
                                                             cphr_buf_IP_len, tag_buf_IP_len);
                                memcpy(gcm_msg_IP_len, aad_IP_len, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_IP_len + 12 + sizeof(uint32_t), cphr_buf_IP_len, sizeof(uint16_t));
                                memcpy(gcm_msg_IP_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_IP_len, 16);
                                rc = send(fds[index_socket_user].fd, (void *) gcm_msg_IP_len,
                                          (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                free(cphr_buf_IP_len);
                                free(gcm_msg_IP_len);
                                if (rc <= 0) {
                                    cerr << "[server] send() size IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                char buffer_username_IP_challenge[addr_to_string(
                                        vec_client.at(i - 1).client_addr).size()];
                                sprintf(buffer_username_IP_challenge, "%s",
                                        addr_to_string(vec_client.at(i - 1).client_addr).c_str());
                                unsigned char aad_username_IP_challenge[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_username_IP_challenge[16];
                                auto cphr_buf_username_IP_challenge = (unsigned char *) malloc(IP_len_challenge);
                                auto gcm_msg_username_IP_challenge = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + IP_len_challenge + 16);
                                int res_username = gcm_encrypt((unsigned char *) buffer_username_IP_challenge,
                                                               IP_len_challenge,
                                                               vec_client.at(index_socket_user - 1).cnt,
                                                               aad_username_IP_challenge,
                                                               vec_client.at(index_socket_user - 1).session_key,
                                                               cphr_buf_username_IP_challenge,
                                                               tag_buf_username_IP_challenge);
                                memcpy(gcm_msg_username_IP_challenge, aad_username_IP_challenge, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_username_IP_challenge + 12 + sizeof(uint32_t),
                                       cphr_buf_username_IP_challenge, IP_len_challenge);
                                memcpy(gcm_msg_username_IP_challenge + 12 + sizeof(uint32_t) + IP_len_challenge,
                                       tag_buf_username_IP_challenge, 16);
                                rc = send(fds[index_socket_user].fd, (void *) gcm_msg_username_IP_challenge,
                                          (12 + sizeof(uint32_t) + IP_len_challenge + 16), 0);
                                free(cphr_buf_username_IP_challenge);
                                free(gcm_msg_username_IP_challenge);
                                if (rc <= 0) {
                                    cerr << "[server] send() IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                //INVIO AL DESTINATARIO LA CHIAVE PUBBLICA DELLO SFIDANTE

                                BIO *mbio_pub = BIO_new(BIO_s_mem());
                                PEM_write_bio_PUBKEY(mbio_pub, vec_client.at(i - 1).client_pubkey);
                                char *pubkey_challenger_buf = nullptr;
                                long pubkey_challenger_size = BIO_get_mem_data(mbio_pub, &pubkey_challenger_buf);
                                BIO_dump_fp(stdout, (const char *) pubkey_challenger_buf, pubkey_challenger_size);
                                //invio della dimensione della chiave pubblica da inviare

                                uint64_t pubkey_challenger_size_snd = htons(pubkey_challenger_size);

                                unsigned char aad_key_len[12 + sizeof(uint32_t)];
                                unsigned char tag_key_len[16];
                                auto cphr_buf_key_len = (unsigned char *) malloc(sizeof(uint64_t));
                                auto gcm_msg_key_len = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint64_t) + 16);
                                int res_key_len = gcm_encrypt((unsigned char *) &pubkey_challenger_size_snd,
                                                              sizeof(uint64_t),
                                                              vec_client.at(index_socket_user - 1).cnt, aad_key_len,
                                                              vec_client.at(index_socket_user - 1).session_key,
                                                              cphr_buf_key_len, tag_key_len);
                                memcpy(gcm_msg_key_len, aad_key_len, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_key_len + 12 + sizeof(uint32_t), cphr_buf_key_len, sizeof(uint64_t));
                                memcpy(gcm_msg_key_len + 12 + sizeof(uint32_t) + sizeof(uint64_t), tag_key_len, 16);
                                rc = send(fds[index_socket_user].fd, (void *) gcm_msg_key_len,
                                          (12 + sizeof(uint32_t) + sizeof(uint64_t) + 16), 0);
                                free(cphr_buf_key_len);
                                free(gcm_msg_key_len);
                                if (rc <= 0) {
                                    cerr << "[server] send() size IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                unsigned char aad_pubkey_challenger[12 + sizeof(uint32_t)];
                                unsigned char tag_pubkey_challenger[16];
                                auto cphr_buf_pubkey_challenger = (unsigned char *) malloc(pubkey_challenger_size);
                                auto gcm_msg_pubkey_challenger = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + pubkey_challenger_size + 16);
                                int res_pubkey_challenger = gcm_encrypt((unsigned char *) pubkey_challenger_buf,
                                                                        pubkey_challenger_size,
                                                                        vec_client.at(index_socket_user - 1).cnt,
                                                                        aad_pubkey_challenger, vec_client.at(
                                                index_socket_user - 1).session_key, cphr_buf_pubkey_challenger,
                                                                        tag_pubkey_challenger);
                                memcpy(gcm_msg_pubkey_challenger, aad_pubkey_challenger, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_pubkey_challenger + 12 + sizeof(uint32_t), cphr_buf_pubkey_challenger,
                                       pubkey_challenger_size);
                                memcpy(gcm_msg_pubkey_challenger + 12 + sizeof(uint32_t) + pubkey_challenger_size,
                                       tag_pubkey_challenger, 16);
                                rc = send(fds[index_socket_user].fd, (void *) gcm_msg_pubkey_challenger,
                                          (12 + sizeof(uint32_t) + pubkey_challenger_size + 16), 0);
                                free(cphr_buf_pubkey_challenger);
                                free(gcm_msg_pubkey_challenger);
                                if (rc <= 0) {
                                    cerr << "[server] send() IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                //// Invio al destinatario del match_id

                                RAND_poll();
                                unsigned char match_id[NONCE_SIZE];
                                RAND_bytes(match_id, NONCE_SIZE);

                                cout << "The generated match_id is: " << endl;
                                BIO_dump_fp(stdout, (const char *) match_id, NONCE_SIZE);

                                unsigned char aad_matchid_challenger[12 + sizeof(uint32_t)];
                                unsigned char tag_matchid_challenger[16];
                                auto cphr_buf_matchid_challenger = (unsigned char *) malloc(NONCE_SIZE);
                                auto gcm_msg_matchid_challenger = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + NONCE_SIZE + 16);
                                int res_matchid_challenger = gcm_encrypt((unsigned char *) match_id,
                                                                        NONCE_SIZE,
                                                                        vec_client.at(index_socket_user - 1).cnt,
                                                                        aad_matchid_challenger, vec_client.at(
                                                index_socket_user - 1).session_key, cphr_buf_matchid_challenger,
                                                                        tag_matchid_challenger);
                                memcpy(gcm_msg_matchid_challenger, aad_matchid_challenger, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_matchid_challenger + 12 + sizeof(uint32_t), cphr_buf_matchid_challenger,
                                       NONCE_SIZE);
                                memcpy(gcm_msg_matchid_challenger + 12 + sizeof(uint32_t) + NONCE_SIZE,
                                       tag_matchid_challenger, 16);
                                rc = send(fds[index_socket_user].fd, (void *) gcm_msg_matchid_challenger,
                                          (12 + sizeof(uint32_t) + NONCE_SIZE + 16), 0);
                                free(cphr_buf_matchid_challenger);
                                free(gcm_msg_matchid_challenger);
                                if (rc <= 0) {
                                    cerr << "[server] send() match_id to challenger failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                ////Invio allo sfidante L'indirizzo IP del Dest + Porta

                                unsigned int IP_len_dest = tmp_ip_address_challenge.size() + 1;
                                uint16_t dest_IP_len = htons(IP_len_dest);

                                unsigned char aad_dest_IP_len[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_dest_IP_len[16];
                                auto cphr_buf_dest_IP_len = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_dest_IP_len = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                int res_dest_IP_len = gcm_encrypt((unsigned char *) &dest_IP_len, sizeof(uint16_t),
                                                                  vec_client.at(i - 1).cnt, aad_dest_IP_len,
                                                                  vec_client.at(i - 1).session_key,
                                                                  cphr_buf_dest_IP_len, tag_buf_dest_IP_len);
                                memcpy(gcm_msg_dest_IP_len, aad_dest_IP_len, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_dest_IP_len + 12 + sizeof(uint32_t), cphr_buf_dest_IP_len,
                                       sizeof(uint16_t));
                                memcpy(gcm_msg_dest_IP_len + 12 + sizeof(uint32_t) + sizeof(uint16_t),
                                       tag_buf_dest_IP_len, 16);
                                cout << "send 1512 riga" << endl;
                                cout << fds[i].fd << endl;
                                cout << gcm_msg_dest_IP_len << endl;
                                rc = send(fds[i].fd, (void *) gcm_msg_dest_IP_len,
                                          (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                cout << "rc send " << rc << endl;
                                free(cphr_buf_dest_IP_len);
                                free(gcm_msg_dest_IP_len);
                                if (rc <= 0) {
                                    cerr << "[server] send() size IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                cout << "riga 1519" << endl;
                                char buffer_username_IP_dest[IP_len_dest];
                                sprintf(buffer_username_IP_dest, "%s", tmp_ip_address_challenge.c_str());
                                unsigned char aad_username_IP_dest[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_username_IP_dest[16];
                                auto cphr_buf_username_IP_dest = (unsigned char *) malloc(IP_len_dest);
                                auto gcm_msg_username_IP_dest = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + IP_len_dest + 16);
                                int res_dest = gcm_encrypt((unsigned char *) buffer_username_IP_dest, IP_len_dest,
                                                           vec_client.at(i - 1).cnt, aad_username_IP_dest,
                                                           vec_client.at(i - 1).session_key, cphr_buf_username_IP_dest,
                                                           tag_buf_username_IP_dest);
                                memcpy(gcm_msg_username_IP_dest, aad_username_IP_dest, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_username_IP_dest + 12 + sizeof(uint32_t), cphr_buf_username_IP_dest,
                                       IP_len_dest);
                                memcpy(gcm_msg_username_IP_dest + 12 + sizeof(uint32_t) + IP_len_dest,
                                       tag_buf_username_IP_dest, 16);
                                rc = send(fds[i].fd, (void *) gcm_msg_username_IP_dest,
                                          (12 + sizeof(uint32_t) + IP_len_dest + 16), 0);
                                free(cphr_buf_username_IP_dest);
                                free(gcm_msg_username_IP_dest);
                                if (rc <= 0) {
                                    cerr << "[server] send() IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                cout << "riga 1539" << endl;
                                //INVIO ALLO SFIDANTE LA PORTA DI ASCOLTO DEL DESTINATARIO
                                //Invio della porta di ascolto
                                uint16_t listening_port_dest = htons(
                                        vec_client.at(index_socket_user - 1).listening_port_client);
                                cout << vec_client.at(index_socket_user - 1).listening_port_client << endl;
                                unsigned char aad_port[12 + sizeof(uint32_t)];
                                unsigned char tag_buf_port[16];
                                auto cphr_buf_port = (unsigned char *) malloc(sizeof(uint16_t));
                                auto gcm_msg_port = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                                res = gcm_encrypt((unsigned char *) &listening_port_dest, sizeof(uint16_t),
                                                  vec_client.at(i - 1).cnt, aad_port, vec_client.at(i - 1).session_key,
                                                  cphr_buf_port, tag_buf_port);
                                memcpy(gcm_msg_port, aad_port, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_port + 12 + sizeof(uint32_t), cphr_buf_port, sizeof(uint16_t));
                                memcpy(gcm_msg_port + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_port, 16);
                                ret = send(fds[i].fd, (void *) gcm_msg_port,
                                           (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                                if (ret <= 0) {
                                    cerr << "[server] send() port challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }
                                // Free up memory
                                free(gcm_msg_port);
                                free(cphr_buf_port);

                                cout << "riga 1563" << endl;

                                //INVIO ALLO SFIDANTE LA CHIAVE PUBBLICA DEL DESTINATARIO

                                BIO *mbio_pub_dest = BIO_new(BIO_s_mem());
                                PEM_write_bio_PUBKEY(mbio_pub_dest, vec_client.at(index_socket_user - 1).client_pubkey);
                                char *pubkey_dest_buf = nullptr;
                                long pubkey_dest_size = BIO_get_mem_data(mbio_pub_dest, &pubkey_dest_buf);
                                BIO_dump_fp(stdout, (const char *) pubkey_dest_buf, pubkey_dest_size);
                                //invio della dimensione della chiave pubblica da inviare

                                uint64_t pubkey_dest_size_snd = htons(pubkey_dest_size);
                                cout << pubkey_dest_size << endl;
                                unsigned char aad_dest_key_len[12 + sizeof(uint32_t)];
                                unsigned char tag_dest_key_len[16];
                                auto cphr_buf_dest_key_len = (unsigned char *) malloc(sizeof(uint64_t));
                                auto gcm_msg_dest_key_len = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + sizeof(uint64_t) + 16);
                                int res_dest_key_len = gcm_encrypt((unsigned char *) &pubkey_dest_size_snd,
                                                                   sizeof(uint64_t), vec_client.at(i - 1).cnt,
                                                                   aad_dest_key_len, vec_client.at(i - 1).session_key,
                                                                   cphr_buf_dest_key_len, tag_dest_key_len);
                                memcpy(gcm_msg_dest_key_len, aad_dest_key_len, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_dest_key_len + 12 + sizeof(uint32_t), cphr_buf_dest_key_len,
                                       sizeof(uint64_t));
                                memcpy(gcm_msg_dest_key_len + 12 + sizeof(uint32_t) + sizeof(uint64_t),
                                       tag_dest_key_len, 16);
                                int rc_dest_len = send(fds[i].fd, (void *) gcm_msg_dest_key_len,
                                                       (12 + sizeof(uint32_t) + sizeof(uint64_t) + 16), 0);
                                free(cphr_buf_dest_key_len);
                                free(gcm_msg_dest_key_len);
                                if (rc_dest_len <= 0) {
                                    cerr << "[server] send() size public key failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                unsigned char aad_pubkey_dest[12 + sizeof(uint32_t)];
                                unsigned char tag_pubkey_dest[16];
                                auto cphr_buf_pubkey_dest = (unsigned char *) malloc(pubkey_dest_size);
                                auto gcm_msg_pubkey_dest = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + pubkey_dest_size + 16);
                                int res_pubkey_dest = gcm_encrypt((unsigned char *) pubkey_dest_buf, pubkey_dest_size,
                                                                  vec_client.at(i - 1).cnt, aad_pubkey_dest,
                                                                  vec_client.at(i - 1).session_key,
                                                                  cphr_buf_pubkey_dest, tag_pubkey_dest);
                                memcpy(gcm_msg_pubkey_dest, aad_pubkey_dest, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_pubkey_dest + 12 + sizeof(uint32_t), cphr_buf_pubkey_dest,
                                       pubkey_dest_size);
                                memcpy(gcm_msg_pubkey_dest + 12 + sizeof(uint32_t) + pubkey_dest_size, tag_pubkey_dest,
                                       16);
                                rc = send(fds[i].fd, (void *) gcm_msg_pubkey_dest,
                                          (12 + sizeof(uint32_t) + pubkey_dest_size + 16), 0);

                                free(cphr_buf_pubkey_dest);
                                free(gcm_msg_pubkey_dest);
                                if (rc <= 0) {
                                    cerr << "[server] send() IP address challenge failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                //// Invio allo sfidante del match_id

                                unsigned char aad_matchid_dest[12 + sizeof(uint32_t)];
                                unsigned char tag_matchid_dest[16];
                                auto cphr_buf_matchid_dest = (unsigned char *) malloc(NONCE_SIZE);
                                auto gcm_msg_matchid_dest = (unsigned char *) malloc(
                                        12 + sizeof(uint32_t) + NONCE_SIZE + 16);
                                int res_matchid_dest = gcm_encrypt((unsigned char *) match_id, NONCE_SIZE,
                                                                  vec_client.at(i - 1).cnt, aad_matchid_dest,
                                                                  vec_client.at(i - 1).session_key,
                                                                  cphr_buf_matchid_dest, tag_matchid_dest);
                                memcpy(gcm_msg_matchid_dest, aad_matchid_dest, 12 + sizeof(uint32_t));
                                memcpy(gcm_msg_matchid_dest + 12 + sizeof(uint32_t), cphr_buf_matchid_dest,
                                       NONCE_SIZE);
                                memcpy(gcm_msg_matchid_dest + 12 + sizeof(uint32_t) + NONCE_SIZE, tag_matchid_dest,
                                       16);
                                rc = send(fds[i].fd, (void *) gcm_msg_matchid_dest,
                                          (12 + sizeof(uint32_t) + NONCE_SIZE + 16), 0);

                                free(cphr_buf_matchid_dest);
                                free(gcm_msg_matchid_dest);
                                if (rc <= 0) {
                                    cerr << "[server] send() match_id to challenger failed" << endl;
                                    close_conn = true;
                                    break;
                                }

                                cout << "Terminata esecuzione comando Challenge" << endl;
                            }

                        }
                    }
                    if (close_conn) {
                        close(fds[i].fd);
                        fds[i].fd = -1;
                        compress_array = true;
                        if (vec_client.at(i - 1).status == ONLINE) {
                            number_of_users_online--;
                        }
                        if (vec_client.at(i - 1).status == MATCHMAKING) {
                            number_of_users_matchmaking--;
                        }
                        vec_client.erase(vec_client.begin() + (i - 1));
                    }

                    break;
                } while (true);

                /*******************************************************/
                /* If the close_conn flag was turned on, we need       */
                /* to clean up this active connection. This            */
                /* clean up process includes removing the              */
                /* descriptor.                                         */
                /*******************************************************/
                if (close_conn) {
                    close(fds[i].fd);
                    fds[i].fd = -1;
                    compress_array = true;
                    if (vec_client.at(i - 1).status == ONLINE) {
                        number_of_users_online--;
                    }
                    if (vec_client.at(i - 1).status == MATCHMAKING) {
                        number_of_users_matchmaking--;
                    }
                    vec_client.erase(vec_client.begin() + (i - 1));
                }


            }  /* End of existing connection is readable             */
        } /* End of loop through pollable descriptors              */

        /***********************************************************/
        /* If the compress_array flag was turned on, we need       */
        /* to squeeze together the array and decrement the number  */
        /* of file descriptors. We do not need to move back the    */
        /* events and revents fields because the events will always*/
        /* be POLLIN in this case, and revents is output.          */
        /***********************************************************/
        if (compress_array) {
            compress_array = false;
            for (i = 0; i < nfds; i++) {
                if (fds[i].fd == -1) {
                    for (j = i; j < nfds; j++) {
                        fds[j].fd = fds[j + 1].fd;
                    }
                    i--;
                    nfds--;
                }
            }
        }

    } while (!end_server); /* End of serving running.    */

    /*************************************************************/
    /* Clean up all of the sockets that are open                 */
    /*************************************************************/
    for (i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0)
            close(fds[i].fd);
    }
    EVP_cleanup();
    return 0;
}

