#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <random>
#include "../Common/const.h"
#include "../Game/game.h"

using namespace std;


string &ltrim(string &str, const string &chars = "\t\n\v\f\r ") {
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

string &rtrim(string &str, const string &chars = "\t\n\v\f\r ") {
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

string &trim(string &str, const string &chars = "\t\n\v\f\r ") {
    return ltrim(rtrim(str, chars), chars);
}

void print_options(bool playing) {
    cout << "The following commands are available:" << endl;
    cout << "!help --> Shows available commands." << endl;
    cout << "!users --> Shows online users." << endl;
    cout << "!challenge --> Send challenge to a user." << endl;
    if (playing) {
        cout << "!move" << endl;
    }
    cout << "!quit --> Shuts down the client." << endl;
}

bool verify_server(X509 *server_cert) {
    int ret;

    X509 *cert_CA;
    FILE *file = fopen("FOC_CA_cert.pem", "r");
    if (!file)
        return false;
    cert_CA = PEM_read_X509(file, nullptr, nullptr, nullptr);
    if (!cert_CA)
        return false;
    fclose(file);

    X509_CRL *crl;
    FILE *file_crl = fopen("FOC_CA_crl.pem", "r");
    if (!file_crl)
        return false;
    crl = PEM_read_X509_CRL(file_crl, nullptr, nullptr, nullptr);
    if (!crl)
        return false;
    fclose(file_crl);

    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, cert_CA);
    X509_STORE_add_crl(store, crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    X509_STORE_CTX *ctx_store = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx_store, store, server_cert, nullptr);
    ret = X509_verify_cert(ctx_store);
    if (ret != 1)
        return false;

    X509_STORE_CTX_free(ctx_store);
    X509_STORE_free(store);

    return true;
}


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

string addr_to_string(struct sockaddr_in addr) {
    ostringstream os;
    os << inet_ntoa(addr.sin_addr) << ":" << htons(addr.sin_port);
    return os.str();
}

bool is_alphanumeric(string string_to_check) {
    auto it = find_if_not(begin(string_to_check), end(string_to_check), [](unsigned char c) {
        return isalnum(c);
    });
    return it == end(string_to_check);
}

bool is_number(const std::string &s) {
    return !s.empty() && std::find_if(s.begin(),
                                      s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

int main(int argc, char *argv[]) {

    OpenSSL_add_all_algorithms();
    int ret, sd, opcode_snd, opcode_rcv, number_users_online, on = 1;
    size_t len;
    struct sockaddr_in srv_addr{};
    string cmd;
    string username;
    bool valid_username = false;
    uint16_t lmsg;
    uint16_t opcode;
    uint16_t number_users_online_rcvd;
    vector<string> online_users;
    EVP_PKEY *pubkey_serv;
    uint32_t server_cnt = 0;
    uint32_t peer_cnt;
    unsigned char server_session_key[16];
    unsigned char peer_session_key[16];
    EVP_PKEY *prvkey;
    const char *server_name = "/C=IT/ST=Pisa/L=Pisa/O=Unipi/OU=DII/CN=FOC";
    bool playing = false;
    unsigned char match_id[NONCE_SIZE];
    struct timeval tv;
    struct sockaddr_in my_addr;
    struct sockaddr_in connecting_peer;
    socklen_t peer_addr_len;
    /* Creazione socket TCP verso il server */
    sd = socket(AF_INET, SOCK_STREAM, 0);

    /* Creazione indirizzo del server */
    // memset(&srv_addr, 0, sizeof(srv_addr)); // Pulizia (necessaria?)
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(SERVER_PORT);
    ret = inet_pton(AF_INET, argv[1], &srv_addr.sin_addr);

    //controllo indirizzo IP passato da terminale
    if (ret <= 0) {
        if (ret == 0)
            fprintf(stderr, "IP address not in presentation format\n");
        else
            perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    ret = connect(sd, (struct sockaddr *) &srv_addr, sizeof(srv_addr));

    if (ret < 0) {
        cerr << "[client] Error during connection phase!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Ricezione certificato del server verifica mediant CA + CRL
    cout << "[client] Verification server cert...." << endl;
    uint64_t cert_size_rcv;
    ret = recv(sd, (void *) &cert_size_rcv, sizeof(uint64_t), 0);
    if (ret < 0) {
        cerr << "[client] Error encountered in reception of size of cert!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout << ntohs(cert_size_rcv) << endl;

    uint64_t cert_size = htons(cert_size_rcv);
    auto *cert_buf = (unsigned char *) malloc(cert_size);
    ret = recv(sd, cert_buf, cert_size, MSG_WAITALL);
    if (ret < 0) {
        cerr << "[client] Error encountered in reception of cert!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    X509 *server_cert = d2i_X509(nullptr, (const unsigned char **) &cert_buf, cert_size);
    if (!server_cert) {
        cerr << "[client] Error while opening server certificate!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    pubkey_serv = X509_get_pubkey(server_cert);
    bool cert_verify_success = verify_server(server_cert);
    char *server_name_rcvd = X509_NAME_oneline(X509_get_subject_name(server_cert), nullptr, 0);
    X509_free(server_cert);

    if (!cert_verify_success) {
        cerr << "[client] Error while authenticating the server, exit" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    //Verifica dell'owner del certificato 
    if (strcmp(server_name, server_name_rcvd) != 0) {
        cerr << "[client] name server not corresponding with the target " << endl;
        free(server_name_rcvd);
        close(sd);
        exit(EXIT_FAILURE);
    }

    cout << "[client] Certified of " << server_name_rcvd << " verified successfully!" << endl;
    free(server_name_rcvd);

    //Alla connessione con il server il client invia il proprio username
    do {
        cout << "[client] Enter your username: ";
        getline(cin, username);
        trim(username);
        if (!cin) {
            cerr << "[client] Error while acquiring user input!" << endl;
            close(sd);
            exit(EXIT_FAILURE);
        }
        if (username.empty())
            continue;
        if (username.length() <= MAX_INPUT_LEN) {
            if (is_alphanumeric(username))
                valid_username = true;
            else {
                cout << "[client] Username must be alphanumeric! (No special characters are allowed)" << endl;
                continue;
            }
        } else
            cout << "[client] Username is too long!" << endl;
    } while (!valid_username);

    //cout << "[client] Username length: " << username.size() << endl;

    len = username.size() + 1;
    lmsg = htons(len);

    ret = send(sd, (void *) &lmsg, sizeof(uint16_t), 0);
    if (ret < 0) {
        cerr << "[client] Error encountered while sending the username size to the server!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    char buffer_username[username.length()];
    sprintf(buffer_username, "%s", username.c_str());

    ret = send(sd, (void *) buffer_username, len, 0);
    if (ret < 0) {
        cerr << "[client] Error encountered while sending the username to the server!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }


    cout << "[client] Connected to the server at " << argv[1] << ":" << SERVER_PORT << endl;

    //RICEZIONE NONCE SERVER 
    cout << "[client] Receiving nonce generated by the server" << endl;
    unsigned char nonce_server[NONCE_SIZE];
    ret = recv(sd, (void *) nonce_server, NONCE_SIZE, 0);

    if (ret == 0) {
        cerr << "[client] The connection was closed by the server." << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    if (ret < 0) {
        cerr << "[client] Error encountered while receiving te nonce generated by the server !" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //printf("RICEVUTO N_S ");
    /*for (unsigned char y : nonce_server) {
        printf("%x", y);
    }
    printf("\n");*/


    //INVIO NONCE AL SERVER
    cout << "[client] Sending nonce to the server" << endl;
    RAND_poll();
    unsigned char nonce_client[NONCE_SIZE];
    RAND_bytes(nonce_client, NONCE_SIZE);
    ret = send(sd, (void *) nonce_client, NONCE_SIZE, 0);
    if (ret < 0) {
        cerr << "[client] send nonce to the server failed." << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //printf("INVIATO N_C ");
    /*for (unsigned char y : nonce_client) {
        printf("%x", y);
    }
    printf("\n");*/

    //NEGOZIAZIONE CHIAVE SIMMETRICA => DH 

    cout << "[client] Start: loading standard DH parameters with Server" << endl;
    EVP_PKEY *params;
    if (nullptr == (params = EVP_PKEY_new())) {
        cerr << "[client] Error during the creation of params" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    DH *temp = get_dh2048();
    if (1 != EVP_PKEY_set1_DH(params, temp)) {
        cerr << "[client] Error during setting params" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    DH_free(temp);
    //cout << "Generating ephemeral DH KeyPair with Server" << endl;

    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if (!(DHctx = EVP_PKEY_CTX_new(params, nullptr))) {
        cerr << "[client] Error during the creation of params" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout << "eseguita creazione contesto" << endl;

    /* Generate a new key */
    EVP_PKEY *my_dhkey = nullptr;
    if (1 != EVP_PKEY_keygen_init(DHctx)) {
        cerr << "[client] Error during keygen_init" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout << "eseguita init key gen int " << endl;
    if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) {
        cerr << "[client] Error during keygen" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout << "eseguita key gen" << endl;

    //INVIO CHIAVE PUBBLICA DH DEL CLIENT AL SERVER + SIGN(CHIAVE_PUBBLICA, N_C, N_S)

    string file_prvkey = username + "/" + username + "_prvkey.pem";
    FILE *prvkey_file = fopen(file_prvkey.c_str(), "r");
    if (!prvkey_file) {
        cerr << "[client] cannot open file containing the privkey" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    prvkey = PEM_read_PrivateKey(prvkey_file, nullptr, nullptr, nullptr);
    fclose(prvkey_file);
    if (!prvkey) {
        cerr << "[client] read privKey failed" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    };

    const EVP_MD *md = EVP_sha256();

    BIO *mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mbio, my_dhkey);
    char *pubkey_DH_buf = nullptr;
    long pubkey_DH_size = BIO_get_mem_data(mbio, &pubkey_DH_buf);

    //invio della dimensione della chiave pubblica DH da inviare 

    uint64_t pubkey_DH_size_snd = htons(pubkey_DH_size);
    ret = send(sd, (void *) &pubkey_DH_size_snd, sizeof(uint64_t), 0);
    if (ret < 0) {
        cerr << "[client] Error sending public key DH size" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout<<"Dimensione public key DH"<<pubkey_DH_size<<endl;    

    //invio della chiave pubblica DH 
    ret = send(sd, pubkey_DH_buf, pubkey_DH_size, 0);
    if (ret < 0) {
        cerr << "[client] Error sending public key DH" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout<<"Inviata la seguente chiave pubblica DH: "<<endl;
    //BIO_dump_fp(stdout, (const char *) pubkey_DH_buf, pubkey_DH_size);


    long int to_sign_size = (NONCE_SIZE * 2) + pubkey_DH_size;
    auto *buf_to_sign = (unsigned char *) malloc(to_sign_size);

    memcpy(buf_to_sign, pubkey_DH_buf, pubkey_DH_size);
    memcpy(buf_to_sign + pubkey_DH_size, nonce_client, NONCE_SIZE);
    memcpy(buf_to_sign + pubkey_DH_size + NONCE_SIZE, nonce_server, NONCE_SIZE);

    // create the signature context:
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "[client] EVP_MD_CTX_new returned nullptr" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    auto *sgnt_buf = (unsigned char *) malloc(EVP_PKEY_size(prvkey));
    if (!sgnt_buf) {
        cerr << "[client] malloc returned nullptr" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    ret = EVP_SignInit(md_ctx, md);
    if (ret == 0) {
        cerr << "[client] EVP_SignInit returned " << ret << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    ret = EVP_SignUpdate(md_ctx, buf_to_sign, to_sign_size);
    if (ret == 0) {
        cerr << "[client] EVP_SignUpdate returned " << ret << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    free(buf_to_sign);
    unsigned int sgnt_size;
    ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
    if (ret == 0) {
        cerr << "[client] EVP_SignFinal returned " << ret << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    BIO_free(mbio);
    //invio della dimensione del digest da inviare
    uint64_t hash_size_snd = htons(sgnt_size);
    ret = send(sd, (void *) &hash_size_snd, sizeof(uint64_t), 0);
    if (ret < 0) {
        cerr << "[client] Error sending digest size" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout<<"Dimensione hash da inviare: "<<sgnt_size<<endl;

    //invio del digest
    ret = send(sd, (void *) sgnt_buf, sgnt_size, 0);
    if (ret < 0) {
        cerr << "[client] Error sending digest " << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout<<"Inviato digest della sign: "<<endl;
    //BIO_dump_fp(stdout, (const char *) sgnt_buf, sgnt_size); 

    //RICEZIONE CHIAVE PUBBLICA DH SERVER 

    //ricezione dimensione chiave pubblica server 
    uint64_t pubkey_DH_server_size_rcv = 0;
    ret = recv(sd, (void *) &pubkey_DH_server_size_rcv, sizeof(uint64_t), 0);
    if (ret < 0) {
        cerr << "[client] Error encountered in reception of  DH server's public key size!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    //Ricezione chiave pubblica DH server
    auto *pubkey_DH_server = (unsigned char *) malloc(ntohs(pubkey_DH_server_size_rcv));
    ret = recv(sd, pubkey_DH_server, ntohs(pubkey_DH_server_size_rcv), MSG_WAITALL);
    if (ret < 0) {
        cerr << "[client] Error encountered in reception of  DH server's public key!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout<<"Ricevuto da server La seguente chiave Pubblica DH "<<endl;
    //BIO_dump_fp(stdout, (const char *) pubkey_DH_server, ntohs(pubkey_DH_server_size_rcv));

    BIO *mbio_rcv = BIO_new(BIO_s_mem());
    BIO_write(mbio_rcv, pubkey_DH_server, ntohs(pubkey_DH_server_size_rcv));
    EVP_PKEY *server_pubkey = PEM_read_bio_PUBKEY(mbio_rcv, nullptr, nullptr, nullptr);

    //Ricezione dimensione digest 
    uint64_t sign_server_size_rcv = 0;
    ret = recv(sd, (void *) &sign_server_size_rcv, sizeof(uint64_t), 0);
    if (ret < 0) {
        cerr << "[client] Error encountered in reception of  DH server's digest size!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    //Ricezione del digest
    auto *sign_server_rcvd = (unsigned char *) malloc(ntohs(sign_server_size_rcv));
    ret = recv(sd, (void *) sign_server_rcvd, ntohs(sign_server_size_rcv), 0);
    if (ret < 0) {
        cerr << "[client] Error encountered in reception of  DH server's digest!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    //cout<<"Ricevuto da server il seguente digest "<<endl;
    //BIO_dump_fp(stdout, (const char *) sign_server_rcvd, ntohs(sign_server_size_rcv));

    //VERIFICA DEL DIGEST INVIATO DAL SERVER
    long int to_verify_size = (NONCE_SIZE * 2) + ntohs(pubkey_DH_server_size_rcv);
    auto *buf_to_verify = (unsigned char *) malloc(to_verify_size);
    memcpy(buf_to_verify, pubkey_DH_server, ntohs(pubkey_DH_server_size_rcv));
    memcpy(buf_to_verify + ntohs(pubkey_DH_server_size_rcv), nonce_client, NONCE_SIZE);
    memcpy(buf_to_verify + ntohs(pubkey_DH_server_size_rcv) + NONCE_SIZE, nonce_server, NONCE_SIZE);

    EVP_MD_CTX *md_ctx_sk = EVP_MD_CTX_new();
    if (!md_ctx_sk) {
        cout << "[Client]: error in EVP_MD_CTX_new" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    int rc;
    rc = EVP_VerifyInit(md_ctx_sk, md);
    if (rc == 0) {
        cout << "[Client]: error in VerifyInit" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    rc = EVP_VerifyUpdate(md_ctx_sk, buf_to_verify, to_verify_size);
    if (rc == 0) {
        cout << "[Client]: error in VerifyUpdate" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    rc = EVP_VerifyFinal(md_ctx_sk, sign_server_rcvd, ntohs(sign_server_size_rcv), pubkey_serv);
    BIO_free(mbio_rcv);
    free(sign_server_rcvd);
    free(buf_to_verify);

    if (rc != 1) {
        cout
                << "[Client]:The signature of (chiave_DH_Server + nonce_client + nonce_server) has NOT been verified correctly"
                << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    cout << "[Client]: The signature of (chiave_DH_Server + nonce_client + nonce_server) has been verified correctly"
         << endl;
    //DERIVAZIONE DEL SEGRETO 

    cout << "[client] Deriving a shared secret" << endl;
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *skey;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey, nullptr);
    if (!derive_ctx) {
        cerr << "[client] Error deriving context" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        cerr << "[client] Error derive_init" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive_set_peer(derive_ctx, server_pubkey) <= 0) {
        cerr << "[client] Error deriving_set_perr " << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_derive(derive_ctx, nullptr, &skeylen);
    skey = (unsigned char *) (malloc(int(skeylen)));
    if (!skey) {
        cerr << "[client] Error alloc shared key " << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) {
        cerr << "[client] Error deriving secret " << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }

    cout << "[client] here there is the shared secret with the server" << endl;
    BIO_dump_fp(stdout, (const char *) skey, skeylen);

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(server_pubkey);
    EVP_PKEY_free(my_dhkey);
    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);
    free(sgnt_buf);
    EVP_MD_CTX_free(md_ctx);
    //EVP_PKEY_free(prvkey);

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
    memcpy(server_session_key, digest_ss, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
#pragma optimize("", off);
    memset(digest_ss, 0, digestlen);
    memset(skey, 0, skeylen);
#pragma optimize("", on);
    free(digest_ss);
    free(skey);
    cout << "[Server]: The session key is: "
         << BIO_dump_fp(stdout, (const char *) server_session_key, EVP_CIPHER_key_length(EVP_aes_128_gcm())) << endl;


    //Invio della porta di ascolto
    random_device rand_dev;
    mt19937 mt_(rand_dev());
    uniform_int_distribution<> distr(49152, 65535);
    uint16_t listening_port = distr(mt_);
    uint16_t list_port_snd = htons(listening_port);
    unsigned char aad[12 + sizeof(uint32_t)];
    unsigned char tag_buf[16];
    auto cphr_buf = (unsigned char *) malloc(sizeof(uint16_t));
    auto gcm_msg = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
    int res = gcm_encrypt((unsigned char *) &list_port_snd, sizeof(uint16_t), server_cnt, aad, server_session_key,
                          cphr_buf, tag_buf);
    memcpy(gcm_msg, aad, 12 + sizeof(uint32_t));
    memcpy(gcm_msg + 12 + sizeof(uint32_t), cphr_buf, sizeof(uint16_t));
    memcpy(gcm_msg + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf, 16);
    ret = send(sd, (void *) gcm_msg, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
    if (ret <= 0) {
        cerr << "[client] Error encountered while sending challenge user command to the server!" << endl;
        close(sd);
        exit(EXIT_FAILURE);
    }
    // Free up memory
    free(gcm_msg);
    free(cphr_buf);


    print_options(playing);
    do {
        cout << "> ";
        getline(cin, cmd);
        trim(cmd);
        if (!cin) {
            cout << "[client] Error while acquiring command!" << endl;
            continue;
        }

        const char delimiter_address = ' ';
        string token;
        stringstream ss(cmd);
        vector<string> command;
        while (getline(ss, token, delimiter_address)) {
            command.push_back(token);
        }

        if (command.at(0).empty()) {
            continue;
        } else if (command.at(0) == "!help") {
            print_options(playing);
            continue;
        } else if (command.at(0) == "!quit") {
            close(sd);
            exit(EXIT_SUCCESS);
        } else if (command.at(0) == "!waiting_req") {
            opcode_snd = WAITING_REQ_OPC;
            opcode = htons(opcode_snd);
            cout << "Invio opcode di richiesta: " << opcode_snd << endl;
            unsigned char aad_wait[12 + sizeof(uint32_t)];
            unsigned char tag_buf_wait[16];
            auto cphr_buf_wait = (unsigned char *) malloc(sizeof(uint16_t));
            auto gcm_msg_wait = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
            int res = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t), server_cnt, aad_wait, server_session_key,
                                  cphr_buf_wait, tag_buf_wait);
            memcpy(gcm_msg_wait, aad_wait, 12 + sizeof(uint32_t));
            memcpy(gcm_msg_wait + 12 + sizeof(uint32_t), cphr_buf_wait, sizeof(uint16_t));
            memcpy(gcm_msg_wait + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_wait, 16);
            int ret = send(sd, (void *) gcm_msg_wait, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
            free(cphr_buf_wait);
            free(gcm_msg_wait);
            if (ret <= 0) {
                cerr << "[Client] send() size IP address challenge failed" << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }
            cout << "Waiting for Challenge..." << endl;
            tv.tv_sec = 25; //timeout in seconds
            tv.tv_usec = 0;
            int res_rcv = setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof(tv));
            if (res_rcv < 0) {
                cerr << "[Client] setsockopt() failed" << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }
            auto gcm_msg_ch = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
            int rc_req = recv(sd, (void *) gcm_msg_ch, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), MSG_WAITALL);
            if (rc_req < 0) {
                if (errno == EWOULDBLOCK) {
                    cout << "Timeout expired" << endl;
                    // Avverto il server che non sono più nello stato matchmaking
                    opcode_snd = END_OF_MATCHMAKING;
                    opcode = htons(opcode_snd);
                    cout << "Invio opcode di richiesta: " << opcode_snd << endl;
                    unsigned char aad_end[12 + sizeof(uint32_t)];
                    unsigned char tag_buf_end[16];
                    auto cphr_buf_end = (unsigned char *) malloc(sizeof(uint16_t));
                    auto gcm_msg_end = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                    int res_end = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t), server_cnt, aad_end,
                                              server_session_key, cphr_buf_end, tag_buf_end);
                    memcpy(gcm_msg_end, aad_end, 12 + sizeof(uint32_t));
                    memcpy(gcm_msg_end + 12 + sizeof(uint32_t), cphr_buf_end, sizeof(uint16_t));
                    memcpy(gcm_msg_end + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_end, 16);
                    int ret_end = send(sd, (void *) gcm_msg_end, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                    free(cphr_buf_end);
                    free(gcm_msg_end);
                    if (ret_end <= 0) {
                        cerr << "[Client] send() size IP address challenge failed" << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                }
            } else { //cout << "New request received" << endl;
                //ricevo l'opcode che indica una nuova richiesta di challenge
                unsigned char aad_ch[12 + sizeof(uint32_t)];
                unsigned char iv_ch[12];
                unsigned char tag_buf_ch[16];
                auto cphr_buf_ch = (unsigned char *) malloc(sizeof(uint16_t));
                auto plain_buf_ch = (unsigned char *) malloc(sizeof(uint16_t));
                memcpy(aad_ch, gcm_msg_ch, 12 + sizeof(uint32_t));
                memcpy(iv_ch, gcm_msg_ch, 12);
                memcpy(cphr_buf_ch, gcm_msg_ch + 12 + sizeof(uint32_t), sizeof(uint16_t));
                memcpy(tag_buf_ch, gcm_msg_ch + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                int res_ch = gcm_decrypt(cphr_buf_ch, sizeof(uint16_t), server_cnt, aad_ch, tag_buf_ch,
                                         server_session_key, iv_ch, 12, plain_buf_ch);
                if (res_ch == -2) {
                    cout << "[Client] counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_ch == -1) {
                    cout << "[Client] Error encountered in decryption of message" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                opcode_rcv = *(uint16_t *) plain_buf_ch;
                opcode = ntohs(opcode_rcv);

                // Free up memory
                free(gcm_msg_ch);
                free(cphr_buf_ch);
                free(plain_buf_ch);

                if (opcode != NEW_CHALLENGE_REQ_OPC) {
                    cout << "[Client] not expected opcode" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                //ricezione della lunghezza username dello sfidante
                auto gcm_user_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                int rc = recv(sd, (void *) gcm_user_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), MSG_WAITALL);
                unsigned char aad_len[12 + sizeof(uint32_t)];
                unsigned char iv_len[12];
                unsigned char tag_buf_len[16];
                auto cphr_buf_len = (unsigned char *) malloc(sizeof(uint16_t));
                auto plain_buf_len = (unsigned char *) malloc(sizeof(uint16_t));
                memcpy(aad_len, gcm_user_len, 12 + sizeof(uint32_t));
                memcpy(iv_len, gcm_user_len, 12);
                memcpy(cphr_buf_len, gcm_user_len + 12 + sizeof(uint32_t), sizeof(uint16_t));
                memcpy(tag_buf_len, gcm_user_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                int res_len = gcm_decrypt(cphr_buf_len, sizeof(uint16_t), server_cnt, aad_len, tag_buf_len,
                                          server_session_key, iv_len, 12, plain_buf_len);
                if (res_len == -2) {
                    cout << "[Client] counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_len == -1) {
                    cout << "[Client] Error encountered in decryption of message" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                uint16_t username_len = *(uint16_t *) plain_buf_len;
                uint16_t username_len_real = ntohs(username_len);

                // Free up memory
                free(gcm_user_len);
                free(cphr_buf_len);
                free(plain_buf_len);

                //Ricezione dello username dello sfidante
                char username_challenger[username_len_real];

                auto gcm_user_challenger = (unsigned char *) malloc(12 + sizeof(uint32_t) + username_len_real + 16);
                rc = recv(sd, (void *) gcm_user_challenger, (12 + sizeof(uint32_t) + username_len_real + 16),
                          MSG_WAITALL);
                if (rc < 0) {
                    if (errno != EWOULDBLOCK) {
                        cerr << "[Client] recv username of challenge failed" << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    break;
                }

                if (rc == 0) {
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                unsigned char aad_user_challenger[12 + sizeof(uint32_t)];
                unsigned char iv_user_challenger[12];
                unsigned char tag_buf_user_challenger[16];
                auto cphr_buf_user_challenger = (unsigned char *) malloc(username_len_real);
                memcpy(aad_user_challenger, gcm_user_challenger, 12 + sizeof(uint32_t));
                memcpy(iv_user_challenger, gcm_user_challenger, 12);
                memcpy(cphr_buf_user_challenger, gcm_user_challenger + 12 + sizeof(uint32_t), username_len_real);
                memcpy(tag_buf_user_challenger, gcm_user_challenger + 12 + sizeof(uint32_t) + username_len_real, 16);
                int res_user_challenger = gcm_decrypt(cphr_buf_user_challenger, username_len_real, server_cnt,
                                                      aad_user_challenger, tag_buf_user_challenger, server_session_key,
                                                      iv_user_challenger, 12, (unsigned char *) username_challenger);
                if (res_user_challenger == -2) {
                    cout << "[Client] Client's counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_user_challenger == -1) {
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                string user_challenger = (char *) username_challenger;
                cout << "New request of challenge!! FROM: " << user_challenger << endl;

                // Free up memory
                free(gcm_user_challenger);
                free(cphr_buf_user_challenger);

                cout << "Do you ACCEPT the challenge? Y/N" << endl;
                string response;
                struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
                string line;
                bool expired = false;
                int ret = 2;
                while (ret == 2) {
                    ret = poll(&pfd, 1, 10000);
                    if (ret == 1) {
                        getline(cin, response);
                        trim(response);
                        if (!cin) {
                            cout << "[client] Error while acquiring command!" << endl;
                            continue;
                        }
                        if (response != "Y" && response != "N") {
                            cout << "Please, Insert a valid answer!" << endl;
                            ret = 2;
                        } else break;
                    } else if (ret == 0) {
                        cout << "time out expired" << endl;
                        expired = true;
                    }
                }

                if (expired)
                    response = "N";

                opcode_snd = READY;
                opcode = htons(opcode_snd);
                cout << "avverto" << endl;
                int ret_send = send(sd, (void *) &opcode, sizeof(uint16_t), 0);
                if (ret_send <= 0) {
                    cerr << "[Client] send() size IP address challenge failed" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }



                // RICEVERE oPCODE DAL SERVER e SE DISCONNESSO CONTINUEù
                cout << "Ricezione opcode dal server per sapere se si è disconnesso" << endl;
                auto gcm_msg_conn = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                rc = recv(sd, (void *) gcm_msg_conn, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                          MSG_WAITALL);
                if (rc < 0) {
                    if (errno != EWOULDBLOCK) {
                        cout << "[Client] Client Disconnecting..." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    break;
                }

                if (rc == 0) {
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                unsigned char aad_conn[12 + sizeof(uint32_t)];
                unsigned char iv_conn[12];
                unsigned char tag_buf_conn[16];
                auto cphr_buf_conn = (unsigned char *) malloc(sizeof(uint16_t));
                auto plain_buf_conn = (unsigned char *) malloc(sizeof(uint16_t));
                memcpy(aad_conn, gcm_msg_conn, 12 + sizeof(uint32_t));
                memcpy(iv_conn, gcm_msg_conn, 12);
                memcpy(cphr_buf_conn, gcm_msg_conn + 12 + sizeof(uint32_t), sizeof(uint16_t));
                memcpy(tag_buf_conn, gcm_msg_conn + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                int res_conn = gcm_decrypt(cphr_buf_conn, sizeof(uint16_t), server_cnt, aad_conn, tag_buf_conn,
                                           server_session_key, iv_conn, 12, plain_buf_conn);
                if (res_conn == -2) {
                    cout << "Client's counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_conn == -1) {
                    cout << "[client] error in decrypting" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                uint16_t opcode_rcvd = *(uint16_t *) plain_buf_conn;
                opcode = ntohs(opcode_rcvd);

                // Free up memory
                free(gcm_msg_conn);
                free(cphr_buf_conn);
                free(plain_buf_conn);
                if (opcode == DISCONNECTED) {
                    cout << "ADVERSARY disconnected" << endl;
                    continue;
                }

                if (response == "Y")
                    opcode_snd = CHALLENGE_ACCEPTED;
                else opcode_snd = CHALLENGE_REFUSED;
                opcode = htons(opcode_snd);
                cout << "[Client]: Sending the response to the server: opcode " << opcode_snd << endl;
                unsigned char aad_resp[12 + sizeof(uint32_t)];
                unsigned char tag_buf_resp[16];
                auto cphr_buf_resp = (unsigned char *) malloc(sizeof(uint16_t));
                auto gcm_msg_resp = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                int res = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t), server_cnt, aad_resp,
                                      server_session_key, cphr_buf_resp, tag_buf_resp);
                memcpy(gcm_msg_resp, aad_resp, 12 + sizeof(uint32_t));
                memcpy(gcm_msg_resp + 12 + sizeof(uint32_t), cphr_buf_resp, sizeof(uint16_t));
                memcpy(gcm_msg_resp + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_resp, 16);
                ret = send(sd, (void *) gcm_msg_resp, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                free(cphr_buf_resp);
                free(gcm_msg_resp);
                if (ret <= 0) {
                    cerr << "[Client] send() size IP address challenge failed" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (response == "N") continue;

                //Attendo che Il server mi mandi l'indirizzo IP dell'avversario
                auto gcm_challenge_IP_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                ret = recv(sd, (void *) gcm_challenge_IP_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                           MSG_WAITALL);
                if (ret <= 0) {
                    cerr << "[client] Challenge IP len rcv failed." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                unsigned char aad_challenge_IP_len[12 + sizeof(uint32_t)];
                unsigned char iv_challenge_IP_len[12];
                unsigned char tag_buf_challenge_IP_len[16];
                auto cphr_buf_challenge_IP_len = (unsigned char *) malloc(sizeof(uint16_t));
                auto plain_buf_challenge_IP_len = (unsigned char *) malloc(sizeof(uint16_t));
                memcpy(aad_challenge_IP_len, gcm_challenge_IP_len, 12 + sizeof(uint32_t));
                memcpy(iv_challenge_IP_len, gcm_challenge_IP_len, 12);
                memcpy(cphr_buf_challenge_IP_len, gcm_challenge_IP_len + 12 + sizeof(uint32_t), sizeof(uint16_t));
                memcpy(tag_buf_challenge_IP_len, gcm_challenge_IP_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                int ret_challenge_IP_len = gcm_decrypt(cphr_buf_challenge_IP_len, sizeof(uint16_t), server_cnt,
                                                       aad_challenge_IP_len, tag_buf_challenge_IP_len,
                                                       server_session_key, iv_challenge_IP_len, 12,
                                                       plain_buf_challenge_IP_len);
                if (ret_challenge_IP_len == -2) {
                    cout << "[client] Server's counter out of sync." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (ret_challenge_IP_len == -1) {
                    cerr << "[client] Error encountered in decryption of message from server."
                         << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                uint16_t challenge_IP_len = *(uint16_t *) plain_buf_challenge_IP_len;
                // Free up memory
                free(gcm_challenge_IP_len);
                free(cphr_buf_challenge_IP_len);
                free(plain_buf_challenge_IP_len);

                cout << "IP Len challenge " << ntohs(challenge_IP_len) << endl;

                //Ricezione dell'indirizzo ip del destinatario della richiesta di sfida dal server
                uint16_t IP_len_real = ntohs(challenge_IP_len);
                char IP_to_challenge[IP_len_real];

                auto gcm_IP_challenge = (unsigned char *) malloc(12 + sizeof(uint32_t) + IP_len_real + 16);
                ret = recv(sd, (void *) gcm_IP_challenge, (12 + sizeof(uint32_t) + IP_len_real + 16), MSG_WAITALL);
                if (ret <= 0) {
                    cerr << "[client] Challenge IP rcv failed." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                unsigned char aad_IP_challenge[12 + sizeof(uint32_t)];
                unsigned char iv_IP_challenge[12];
                unsigned char tag_buf_IP_challenge[16];
                auto cphr_buf_IP_challenge = (unsigned char *) malloc(IP_len_real);
                memcpy(aad_IP_challenge, gcm_IP_challenge, 12 + sizeof(uint32_t));
                memcpy(iv_IP_challenge, gcm_IP_challenge, 12);
                memcpy(cphr_buf_IP_challenge, gcm_IP_challenge + 12 + sizeof(uint32_t), IP_len_real);
                memcpy(tag_buf_IP_challenge, gcm_IP_challenge + 12 + sizeof(uint32_t) + IP_len_real, 16);
                int res_IP_challenge = gcm_decrypt(cphr_buf_IP_challenge, IP_len_real, server_cnt, aad_IP_challenge,
                                                   tag_buf_IP_challenge, server_session_key, iv_IP_challenge, 12,
                                                   (unsigned char *) IP_to_challenge);
                if (res_IP_challenge == -2) {
                    cout << "[Client] Server's counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_IP_challenge == -2) {
                    cout << "[Client] Error encountered in decryption of message from Server " << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                string IP_challenge = (char *) IP_to_challenge;
                cout << "IP: " << IP_challenge << endl;

                // Free up memory
                free(gcm_IP_challenge);
                free(cphr_buf_IP_challenge);

                //RICEZIONE DELLA CHIAVE PUBBLICA DELL'AVVERSARIO ///////////////////////
                uint64_t pubkey_challenger_size_rcv = 0;

                auto gcm_key_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint64_t) + 16);
                ret = recv(sd, (void *) gcm_key_len, (12 + sizeof(uint32_t) + sizeof(uint64_t) + 16), MSG_WAITALL);
                if (ret <= 0) {
                    cerr << "[client] Challenge IP len rcv failed." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                unsigned char aad_key_len[12 + sizeof(uint32_t)];
                unsigned char iv_key_len[12];
                unsigned char tag_key_len[16];
                auto cphr_buf_key_len = (unsigned char *) malloc(sizeof(uint64_t));
                auto plain_buf_key_len = (unsigned char *) malloc(sizeof(uint64_t));
                memcpy(aad_key_len, gcm_key_len, 12 + sizeof(uint32_t));
                memcpy(iv_key_len, gcm_key_len, 12);
                memcpy(cphr_buf_key_len, gcm_key_len + 12 + sizeof(uint32_t), sizeof(uint64_t));
                memcpy(tag_key_len, gcm_key_len + 12 + sizeof(uint32_t) + sizeof(uint64_t), 16);
                int ret_key_len = gcm_decrypt(cphr_buf_key_len, sizeof(uint64_t), server_cnt, aad_key_len, tag_key_len,
                                              server_session_key, iv_key_len, 12, plain_buf_key_len);
                if (ret_key_len == -2) {
                    cout << "[client] Server's counter out of sync." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (ret_key_len == -1) {
                    cerr << "[client] Error encountered in decryption of message from server."
                         << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                pubkey_challenger_size_rcv = *(uint64_t *) plain_buf_key_len;
                // Free up memory
                free(gcm_key_len);
                free(cphr_buf_key_len);
                free(plain_buf_key_len);

                uint64_t pubkey_challenger_size_real = ntohs(pubkey_challenger_size_rcv);
                cout << "Public key size: " << pubkey_challenger_size_real << endl;

                auto *pubkey_challenger = (unsigned char *) malloc(
                        12 + sizeof(uint32_t) + pubkey_challenger_size_real + 16);
                char pubkey_challenger_buf[pubkey_challenger_size_real];
                int ret_key = recv(sd, pubkey_challenger, (12 + sizeof(uint32_t) + pubkey_challenger_size_real + 16),
                                   MSG_WAITALL);
                if (ret_key < 0) {
                    cerr << "[client] Error encountered in reception of challenger's public key!" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                unsigned char aad_pubkey[12 + sizeof(uint32_t)];
                unsigned char iv_pubkey[12];
                unsigned char tag_pubkey[16];
                auto cphr_buf_pubkey = (unsigned char *) malloc(pubkey_challenger_size_real);
                memcpy(aad_pubkey, pubkey_challenger, 12 + sizeof(uint32_t));
                memcpy(iv_pubkey, pubkey_challenger, 12);
                memcpy(cphr_buf_pubkey, pubkey_challenger + 12 + sizeof(uint32_t), pubkey_challenger_size_real);
                memcpy(tag_pubkey, pubkey_challenger + 12 + sizeof(uint32_t) + pubkey_challenger_size_real, 16);
                int res_pubkey = gcm_decrypt(cphr_buf_pubkey, pubkey_challenger_size_real, server_cnt, aad_pubkey,
                                             tag_pubkey, server_session_key, iv_pubkey, 12,
                                             (unsigned char *) pubkey_challenger_buf);
                if (res_pubkey == -1) {
                    cout << "[Client] Sever's counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_pubkey == -2) {
                    cout << "[Client] Error encountered in decryption of message from Server " << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                // Free up memory
                free(pubkey_challenger);
                free(cphr_buf_pubkey);

                cout << "Received from the server the public key of " + user_challenger + ":" << endl;
                BIO_dump_fp(stdout, (const char *) pubkey_challenger_buf, pubkey_challenger_size_real);

                BIO *mbio_rcv = BIO_new(BIO_s_mem());
                BIO_write(mbio_rcv, pubkey_challenger_buf, pubkey_challenger_size_real);
                EVP_PKEY *peer_pubkey = PEM_read_bio_PUBKEY(mbio_rcv, nullptr, nullptr, nullptr);
                BIO_free(mbio_rcv);

                //// Ricezione del match_id

                auto *matchid_challenger = (unsigned char *) malloc(
                        12 + sizeof(uint32_t) + NONCE_SIZE + 16);
                memset(match_id, 0, NONCE_SIZE);
                int ret_matchid = recv(sd, matchid_challenger, (12 + sizeof(uint32_t) + NONCE_SIZE + 16),
                                       MSG_WAITALL);
                if (ret_matchid < 0) {
                    cerr << "[client] Error encountered in reception of match_id!" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                unsigned char aad_matchid[12 + sizeof(uint32_t)];
                unsigned char iv_matchid[12];
                unsigned char tag_matchid[16];
                auto cphr_buf_matchid = (unsigned char *) malloc(NONCE_SIZE);
                memcpy(aad_matchid, matchid_challenger, 12 + sizeof(uint32_t));
                memcpy(iv_matchid, matchid_challenger, 12);
                memcpy(cphr_buf_matchid, matchid_challenger + 12 + sizeof(uint32_t), NONCE_SIZE);
                memcpy(tag_matchid, matchid_challenger + 12 + sizeof(uint32_t) + NONCE_SIZE, 16);
                int res_matchid = gcm_decrypt(cphr_buf_matchid, NONCE_SIZE, server_cnt, aad_matchid,
                                              tag_matchid, server_session_key, iv_matchid, 12,
                                              (unsigned char *) match_id);
                if (res_pubkey == -1) {
                    cout << "[Client] Sever's counter out of sync. Disconnecting..." << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                if (res_pubkey == -2) {
                    cout << "[Client] Error encountered in decryption of message from Server " << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                // Free up memory
                free(matchid_challenger);
                free(cphr_buf_matchid);

                cout << "The received match_id is: " << endl;
                BIO_dump_fp(stdout, (const char *) match_id, NONCE_SIZE);

                BIO *mbio_rcv_sh = BIO_new(BIO_s_mem());
                BIO_write(mbio_rcv_sh, pubkey_challenger_buf, pubkey_challenger_size_real);
                EVP_PKEY *peer_challenger_pubkey = PEM_read_bio_PUBKEY(mbio_rcv, nullptr, nullptr, nullptr);
                BIO_free(mbio_rcv_sh);

                /* Creazione socket d'ascolto peer to peer per le challenge requests*/
                int listen_peer = socket(AF_INET, SOCK_STREAM, 0);
                if (listen_peer < 0) {
                    cerr << "socket() failed" << endl;
                    exit(EXIT_FAILURE);
                }

                ret = setsockopt(listen_peer, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
                /*rc = ioctl(listen_peer, FIONBIO, (char *) &on);

                if (rc < 0) {
                     cerr << "ioctl() failed" << endl;
                     close(listen_peer);
                     exit(EXIT_FAILURE);
                }
                if (ret < 0) {
                          cerr << "setsockopt() failed" << endl;
                          close(listen_peer);
                          exit(EXIT_FAILURE);
                }*/
                memset(&my_addr, 0, sizeof(my_addr));
                my_addr.sin_family = AF_INET;
                my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
                my_addr.sin_port = htons(listening_port);
                //cout << "porta" << (uint16_t)my_addr.sin_port << endl;
                ret = bind(listen_peer, (struct sockaddr *) &my_addr, sizeof(my_addr));
                if (ret < 0) {
                    cerr << "bind() failed" << endl;
                    close(listen_peer);
                    exit(EXIT_FAILURE);
                }
                cout << "[Client] Waiting for connection to " + user_challenger + "..." << endl;
                ret = listen(listen_peer, 32);
                if (ret < 0) {
                    cerr << "listen() failed" << endl;
                    close(listen_peer);
                    exit(EXIT_FAILURE);
                }
                int new_sd = accept(listen_peer, (struct sockaddr *) &connecting_peer, &peer_addr_len);
                if (new_sd < 0) {
                    if (errno != EWOULDBLOCK) {
                        cerr << "accept() failed" << endl;
                        exit(EXIT_FAILURE);
                    }
                    continue;
                }
                cout << "[Client] Your are CONNECTED to " + user_challenger + "!" << endl;
                close(listen_peer);


                ///ricezione DEL NONCE ALL'AVVERSARIO
                cout << "[client] Receiving nonce generated " + user_challenger << endl;
                unsigned char nonce_challenger[NONCE_SIZE];
                ret = recv(new_sd, (void *) nonce_challenger, NONCE_SIZE, 0);

                if (ret == 0) {
                    cerr << "[client] The connection was closed." << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                if (ret < 0) {
                    cerr << "[client] Error encountered while receiving the nonce !" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                cout << "[Client] Nonce received is " << endl;
                BIO_dump_fp(stdout, (const char *) nonce_challenger, NONCE_SIZE);

                //// Generazione del nonce da inviare all'avversario

                RAND_poll();
                unsigned char nonce_to_send[NONCE_SIZE];
                RAND_bytes(nonce_to_send, NONCE_SIZE);

                ret = send(new_sd, (void *) nonce_to_send, NONCE_SIZE, 0);
                if (ret < 0) {
                    cerr << "[client] send nonce to the server failed." << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                cout << "Il nonce da inviare all'avversario è: " << endl;
                BIO_dump_fp(stdout, (const char *) nonce_to_send, NONCE_SIZE);

                //// Generazione chiave pubblica DH da inviare all'avversario

                EVP_PKEY *params;
                if (nullptr == (params = EVP_PKEY_new())) {
                    cerr << "[client] Error during the creation of params" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                DH *temp = get_dh2048();
                if (1 != EVP_PKEY_set1_DH(params, temp)) {
                    cerr << "[client] Error during setting params" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                DH_free(temp);
                //cout << "Generating ephemeral DH KeyPair with Server" << endl;

                /* Create context for the key generation */
                EVP_PKEY_CTX *DHctx;
                if (!(DHctx = EVP_PKEY_CTX_new(params, nullptr))) {
                    cerr << "[client] Error during the creation of params" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                //cout << "eseguita creazione contesto" << endl;

                /* Generate a new key */
                EVP_PKEY *my_dhkey = nullptr;
                if (1 != EVP_PKEY_keygen_init(DHctx)) {
                    cerr << "[client] Error during keygen_init" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                //cout << "eseguita init key gen int " << endl;
                if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) {
                    cerr << "[client] Error during keygen" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                //// Invio al peer di chiave pubblica e sgn(chiave pubblica, nonces)

                BIO *mbio = BIO_new(BIO_s_mem());
                PEM_write_bio_PUBKEY(mbio, my_dhkey);
                char *pubkey_DH_buf = nullptr;
                long pubkey_DH_size = BIO_get_mem_data(mbio, &pubkey_DH_buf);

                uint64_t pubkey_DH_size_snd = htons(pubkey_DH_size);
                ret = send(new_sd, (void *) &pubkey_DH_size_snd, sizeof(uint64_t), 0);
                if (ret < 0) {
                    cerr << "[client] Error sending public key DH size" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                ret = send(new_sd, pubkey_DH_buf, pubkey_DH_size, 0);
                if (ret < 0) {
                    cerr << "[client] Error sending public key DH" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                cout << "public key generated: " << endl;
                BIO_dump_fp(stdout, (const char *) pubkey_DH_buf, pubkey_DH_size);

                long int to_sign_size = (NONCE_SIZE * 3) + pubkey_DH_size;
                auto *buf_to_sign = (unsigned char *) malloc(to_sign_size);

                memcpy(buf_to_sign, pubkey_DH_buf, pubkey_DH_size);
                memcpy(buf_to_sign + pubkey_DH_size, match_id, NONCE_SIZE);
                memcpy(buf_to_sign + pubkey_DH_size + NONCE_SIZE, nonce_to_send, NONCE_SIZE);
                memcpy(buf_to_sign + pubkey_DH_size + NONCE_SIZE * 2, nonce_challenger, NONCE_SIZE);

                // create the signature context:
                EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
                if (!md_ctx) {
                    cerr << "[client] EVP_MD_CTX_new returned nullptr" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                auto *sgnt_buf = (unsigned char *) malloc(EVP_PKEY_size(prvkey));
                if (!sgnt_buf) {
                    cerr << "[client] malloc returned nullptr" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                ret = EVP_SignInit(md_ctx, md);
                if (ret == 0) {
                    cerr << "[client] EVP_SignInit returned " << ret << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                ret = EVP_SignUpdate(md_ctx, buf_to_sign, to_sign_size);
                if (ret == 0) {
                    cerr << "[client] EVP_SignUpdate returned " << ret << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                free(buf_to_sign);
                unsigned int sgnt_size;
                ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
                if (ret == 0) {
                    cerr << "[client] EVP_SignFinal returned " << ret << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                BIO_free(mbio);

                uint64_t hash_size_snd = htons(sgnt_size);
                cout << "hash_size_send: " << sgnt_size << endl;
                ret = send(new_sd, (void *) &hash_size_snd, sizeof(uint64_t), 0);
                if (ret < 0) {
                    cerr << "[client] Error sending digest size" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                //cout<<"Dimensione hash da inviare: "<<sgnt_size<<endl;

                //invio del digest
                ret = send(new_sd, (void *) sgnt_buf, sgnt_size, 0);
                if (ret < 0) {
                    cerr << "[client] Error sending digest " << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                //// Ricezione chiave pubblica DH dal peer

                uint64_t len_pubkey_rcvd;
                int len_username;
                ret = recv(new_sd, (void *) &len_pubkey_rcvd, sizeof(uint64_t), 0);
                if (ret < 0) {
                    cerr << "[client] Error encountered while receiving len username's online user!" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                uint64_t len_pubkey_real = ntohs(len_pubkey_rcvd);
                char pubkey_DH_challenger[len_pubkey_real];

                ret = recv(new_sd, pubkey_DH_challenger, len_pubkey_real, MSG_WAITALL);
                if (ret < 0) {
                    cerr << "[client] Error encountered in reception of  DH server's public key!" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                //cout<<"Ricevuto da server La seguente chiave Pubblica DH "<<endl;
                //BIO_dump_fp(stdout, (const char *) pubkey_DH_server, ntohs(pubkey_DH_server_size_rcv));

                BIO *mbio_rcv2 = BIO_new(BIO_s_mem());
                BIO_write(mbio_rcv2, pubkey_DH_challenger, len_pubkey_real);
                EVP_PKEY *challenger_pubkey = PEM_read_bio_PUBKEY(mbio_rcv2, nullptr, nullptr, nullptr);
                BIO_free(mbio_rcv2);

                cout << "received public key of challenger: " << endl;
                BIO_dump_fp(stdout, (const char *) pubkey_DH_challenger, len_pubkey_real);

                //// Ricezione firma chiave pubblica + nonce

                int buf_to_verify_size = NONCE_SIZE * 3 + len_pubkey_real;
                unsigned char buf_to_verify[buf_to_verify_size];
                memcpy(buf_to_verify, pubkey_DH_challenger, len_pubkey_real);
                memcpy(buf_to_verify + len_pubkey_real, match_id, NONCE_SIZE);
                memcpy(buf_to_verify + len_pubkey_real + NONCE_SIZE, nonce_challenger, NONCE_SIZE);
                memcpy(buf_to_verify + len_pubkey_real + NONCE_SIZE * 2, nonce_to_send, NONCE_SIZE);

                uint64_t hash_size_rcv;
                ret = recv(new_sd, (void *) &hash_size_rcv, sizeof(uint64_t), 0);
                if (ret < 0) {
                    cerr << "[client] Error encountered while receiving hash size!" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                int hash_size_real = ntohs(hash_size_rcv);
                cout << "hash size: " << hash_size_real << endl;

                unsigned char sgn_peer_rcvd[hash_size_real];
                ret = recv(new_sd, sgn_peer_rcvd, hash_size_real, MSG_WAITALL);
                if (ret < 0) {
                    cerr << "[client] Error encountered in reception of  DH server's public key!" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                EVP_MD_CTX *md_ctx_sk = EVP_MD_CTX_new();
                if (!md_ctx_sk) {
                    cout << "[Client]: error in EVP_MD_CTX_new" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }
                rc = EVP_VerifyInit(md_ctx_sk, md);
                if (rc == 0) {
                    cout << "[Client]: error in VerifyInit" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                rc = EVP_VerifyUpdate(md_ctx_sk, buf_to_verify, buf_to_verify_size);
                if (rc == 0) {
                    cout << "[Client]: error in VerifyUpdate" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                rc = EVP_VerifyFinal(md_ctx_sk, sgn_peer_rcvd, hash_size_real, peer_pubkey);

                if (rc != 1) {
                    cout
                            << "[client] The signature of the peer has NOT been verified correctly " << rc <<
                            endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                cout << "[client] Signature of peer correctly verified!" << endl;

                //// Generazione segreto condiviso peer-to-peer

                EVP_PKEY_CTX *derive_ctx;
                unsigned char *skey;
                size_t skeylen;
                derive_ctx = EVP_PKEY_CTX_new(my_dhkey, nullptr);
                if (!derive_ctx) {
                    cerr << "[client] Error deriving context" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
                    cerr << "[client] Error derive_init" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                if (EVP_PKEY_derive_set_peer(derive_ctx, challenger_pubkey) <= 0) {
                    cerr << "[client] Error deriving_set_peer " << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                EVP_PKEY_derive(derive_ctx, nullptr, &skeylen);
                skey = (unsigned char *) (malloc(int(skeylen)));
                if (!skey) {
                    cerr << "[client] Error alloc shared key " << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) {
                    cerr << "[client] Error deriving secret " << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                EVP_PKEY_CTX_free(derive_ctx);
                EVP_PKEY_free(challenger_pubkey);
                EVP_PKEY_free(my_dhkey);
                EVP_PKEY_CTX_free(DHctx);
                EVP_PKEY_free(params);
                EVP_MD_CTX_free(md_ctx);

                auto *digest_ss = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()));
                unsigned int digestlen;
                EVP_MD_CTX *md_ctx_hash;
                md_ctx_hash = EVP_MD_CTX_new();
                EVP_DigestInit(md_ctx_hash, md);
                EVP_DigestUpdate(md_ctx_hash, (unsigned char *) skey, skeylen);
                EVP_DigestFinal(md_ctx_hash, digest_ss, &digestlen);
                EVP_MD_CTX_free(md_ctx_hash);
                //cout << "The dimension of the digest is:" << digestlen << endl;
                memcpy(peer_session_key, digest_ss, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
#pragma optimize("", off);
                memset(digest_ss, 0, digestlen);
                memset(skey, 0, skeylen);
#pragma optimize("", on);
                free(digest_ss);
                free(skey);
                cout << "[client] The session key with the peer is: "
                     << BIO_dump_fp(stdout, (const char *) peer_session_key, EVP_CIPHER_key_length(EVP_aes_128_gcm()))
                     << endl;

                playing = true;
                peer_cnt = 0;

                unsigned char aad_peer[12 + sizeof(uint32_t)];
                unsigned char iv_peer[12];
                unsigned char tag_peer[16];
                unsigned char cphr_buf_peer[sizeof(uint16_t)];
                unsigned char pltx_buf_peer[sizeof(uint16_t)];
                unsigned char gcm_msg_peer[12 + sizeof(uint32_t) + sizeof(uint16_t) + 16];
                uint16_t message;

                cout << "Rolling dice... ";
                random_device rd;
                mt19937 mt(rd());
                uniform_int_distribution<> dist(1, 20);
                int dice_roll = dist(mt);
                cout << dice_roll << "!" << endl;

                ret = recv(new_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                           MSG_WAITALL);
                if (ret <= 0) {
                    cerr << "[client] Error encountered in reception of message from peer!" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                memcpy(iv_peer, gcm_msg_peer, 12);
                memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                  tag_peer, peer_session_key, iv_peer, 12,
                                  (unsigned char *) pltx_buf_peer);
                if (res == -1) {
                    cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }
                if (res == -2) {
                    cout << "[client] Error encountered in decryption of message from peer. " << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                message = *(uint16_t *) pltx_buf_peer;

                cout << "Opponent rolled: " << message << "." << endl;

                bool first = false;
                if (dice_roll > message) {
                    cout << "You go first!" << endl;
                    first = true;
                } else
                    cout << "Opponent goes first!" << endl;

                message = dice_roll;
                res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer, peer_session_key,
                                  cphr_buf_peer, tag_peer);
                memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                ret = send(new_sd, (void *) gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                if (ret <= 0) {
                    cerr << "[Client] send() to peer failed" << endl;
                    close(new_sd);
                    exit(EXIT_FAILURE);
                }

                /*** The game begins. ***/
                initGame();
                printField();
                int column;

                if (!first) {
                    cout << "Opponent's turn...";
                    cout.flush();
                    ret = recv(new_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                               MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Error encountered in reception of message from peer!" << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }

                    memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                    memcpy(iv_peer, gcm_msg_peer, 12);
                    memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                    memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                    res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                      tag_peer, peer_session_key, iv_peer, 12,
                                      (unsigned char *) pltx_buf_peer);
                    if (res == -1) {
                        cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res == -2) {
                        cout << "[client] Error encountered in decryption of message from peer. " << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }

                    message = *(uint16_t *) pltx_buf_peer;

                    // TODO check legal value

                    move(message, 1);
                }

                while (!endGame && counterMoves < 42) {
                    bool valid = false;
                    do {
                        cout << "Your turn!" << endl;
                        cout << "> ";
                        getline(cin, cmd);
                        trim(cmd);
                        string token;
                        stringstream ss(cmd);
                        const char delimiter = ' ';
                        vector<string> command;
                        while (getline(ss, token, delimiter)) {
                            command.push_back(token);
                        }
                        if (command.at(0).empty()) {
                            continue;
                        } else if (command.at(0) == "!concede") {
                            // TODO
                            endGame = true;
                            break;
                        } else if (command.at(0) == "!move") {
                            if (is_number(command.at(1))) {
                                column = stoi(command.at(1));
                                if (move(column, 0)) {
                                    valid = true;
                                }
                            }
                        }
                    } while (!valid);

                    message = column;
                    res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                      peer_session_key,
                                      cphr_buf_peer, tag_peer);
                    memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                    memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                    memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                    ret = send(new_sd, (void *) gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                               0);
                    if (ret <= 0) {
                        cerr << "[Client] send() to peer failed" << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }

                    if (winner == 0) {
                        message = GAME_OVER;
                        res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                          peer_session_key,
                                          cphr_buf_peer, tag_peer);
                        memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                        memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                        memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                        ret = send(new_sd, (void *) gcm_msg_peer,
                                   (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   0);
                        if (ret <= 0) {
                            cerr << "[Client] send() to peer failed" << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }
                        cout << "You won!" << endl;
                        cout << "Closing connection with peer..." << endl;
                        close(new_sd);
                        break;
                    }

                    if (counterMoves == 42) {
                        message = GAME_OVER_TIE;
                        res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                          peer_session_key,
                                          cphr_buf_peer, tag_peer);
                        memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                        memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                        memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                        ret = send(new_sd, (void *) gcm_msg_peer,
                                   (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   0);
                        if (ret <= 0) {
                            cerr << "[Client] send() to peer failed" << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }
                        cout << "You tied!" << endl;
                        cout << "Closing connection with peer..." << endl;
                        close(new_sd);
                        break;
                    }

                    cout << "Opponent's turn...";
                    cout.flush();

                    ret = recv(new_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                               MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Error encountered in reception of message from peer!" << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }

                    memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                    memcpy(iv_peer, gcm_msg_peer, 12);
                    memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                    memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                    res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                      tag_peer, peer_session_key, iv_peer, 12,
                                      (unsigned char *) pltx_buf_peer);
                    if (res == -1) {
                        cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res == -2) {
                        cout << "[client] Error encountered in decryption of message from peer. " << endl;
                        close(new_sd);
                        exit(EXIT_FAILURE);
                    }

                    message = *(uint16_t *) pltx_buf_peer;

                    column = message;
                    move(column, 1);

                    if (winner == 1) {
                        ret = recv(new_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   MSG_WAITALL);
                        if (ret <= 0) {
                            cerr << "[client] Error encountered in reception of message from peer!" << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }

                        memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                        memcpy(iv_peer, gcm_msg_peer, 12);
                        memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                        memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                        res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                          tag_peer, peer_session_key, iv_peer, 12,
                                          (unsigned char *) pltx_buf_peer);
                        if (res == -1) {
                            cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }
                        if (res == -2) {
                            cout << "[client] Error encountered in decryption of message from peer. " << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }

                        message = *(uint16_t *) pltx_buf_peer;
                        if (message == GAME_OVER) {
                            cout << "You lost!" << endl;
                        } else {
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }
                        cout << "Closing connection with peer..." << endl;
                        close(new_sd);
                        break;
                    }

                    if (counterMoves == 42) {
                        ret = recv(new_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   MSG_WAITALL);
                        if (ret <= 0) {
                            cerr << "[client] Error encountered in reception of message from peer!" << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }

                        memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                        memcpy(iv_peer, gcm_msg_peer, 12);
                        memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                        memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                        res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                          tag_peer, peer_session_key, iv_peer, 12,
                                          (unsigned char *) pltx_buf_peer);
                        if (res == -1) {
                            cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }
                        if (res == -2) {
                            cout << "[client] Error encountered in decryption of message from peer. " << endl;
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }

                        message = *(uint16_t *) pltx_buf_peer;
                        if (message == GAME_OVER_TIE) {
                            cout << "You tied!" << endl;
                        } else {
                            close(new_sd);
                            exit(EXIT_FAILURE);
                        }
                        cout << "Closing connection with peer..." << endl;
                        close(new_sd);
                        break;
                    }
                }
            }

        } else if (command.at(0) == "!challenge") {
            if (command.size() < 2) {
                cout << "You have to insert the name of the adversary!!" << endl;
                continue;
            }
            if (command.at(1).size() >= MAX_INPUT_LEN) {
                cout << "The input size is too BIG!!" << endl;
                continue;
            }
            opcode_snd = CHALLENGE_REQUEST_OPC;
            opcode = htons(opcode_snd);
            unsigned char aad[12 + sizeof(uint32_t)];
            unsigned char tag_buf[16];
            auto cphr_buf = (unsigned char *) malloc(sizeof(uint16_t));
            auto gcm_msg = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
            int res = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t), server_cnt, aad, server_session_key,
                                  cphr_buf,
                                  tag_buf);
            memcpy(gcm_msg, aad, 12 + sizeof(uint32_t));
            memcpy(gcm_msg + 12 + sizeof(uint32_t), cphr_buf, sizeof(uint16_t));
            memcpy(gcm_msg + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf, 16);
            ret = send(sd, (void *) gcm_msg, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
            free(cphr_buf);
            free(gcm_msg);
            if (ret <= 0) {
                cerr << "[client] Error encountered while sending challenge user command to the server!" << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }

            uint16_t user_len;
            string username_challenge = command.at(1);
            cout << username_challenge << endl;

            unsigned int user_len_h = username_challenge.size() + 1;
            user_len = htons(user_len_h);

            unsigned char aad_user_len[12 + sizeof(uint32_t)];
            unsigned char tag_buf_user_len[16];
            auto cphr_buf_user_len = (unsigned char *) malloc(sizeof(uint16_t));
            auto gcm_msg_user_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
            int res_user_len = gcm_encrypt((unsigned char *) &user_len, sizeof(uint16_t), server_cnt, aad_user_len,
                                           server_session_key, cphr_buf_user_len,
                                           tag_buf_user_len);
            memcpy(gcm_msg_user_len, aad_user_len, 12 + sizeof(uint32_t));
            memcpy(gcm_msg_user_len + 12 + sizeof(uint32_t), cphr_buf_user_len, sizeof(uint16_t));
            memcpy(gcm_msg_user_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf_user_len, 16);
            ret = send(sd, (void *) gcm_msg_user_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
            free(cphr_buf_user_len);
            free(gcm_msg_user_len);
            if (ret <= 0) {
                cerr << "[client] Error encountered while sending show online users command to the server!" << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }

            char buffer_username_challenge[username_challenge.length()];
            sprintf(buffer_username_challenge, "%s", username_challenge.c_str());

            unsigned char aad_username_challenge[12 + sizeof(uint32_t)];
            unsigned char tag_buf_username_challenge[16];
            auto cphr_buf_username_challenge = (unsigned char *) malloc(user_len_h);
            auto gcm_msg_username_challenge = (unsigned char *) malloc(12 + sizeof(uint32_t) + user_len_h + 16);
            int res_username_challenge = gcm_encrypt((unsigned char *) buffer_username_challenge, user_len_h,
                                                     server_cnt, aad_username_challenge, server_session_key,
                                                     cphr_buf_username_challenge,
                                                     tag_buf_username_challenge);
            memcpy(gcm_msg_username_challenge, aad_username_challenge, 12 + sizeof(uint32_t));
            memcpy(gcm_msg_username_challenge + 12 + sizeof(uint32_t), cphr_buf_username_challenge, user_len_h);
            memcpy(gcm_msg_username_challenge + 12 + sizeof(uint32_t) + user_len_h, tag_buf_username_challenge, 16);
            ret = send(sd, (void *) gcm_msg_username_challenge, (12 + sizeof(uint32_t) + user_len_h + 16), 0);
            free(cphr_buf_username_challenge);
            free(gcm_msg_username_challenge);
            if (ret <= 0) {
                cerr << "[client] Error encountered while sending challenge user command to the server!" << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }

            auto gcm_challenge_status = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
            ret = recv(sd, (void *) gcm_challenge_status, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                       MSG_WAITALL);
            if (ret <= 0) {
                cerr << "[client] Challenge opcode failed." << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }

            unsigned char aad_challenge_status[12 + sizeof(uint32_t)];
            unsigned char iv_challenge_status[12];
            unsigned char tag_buf_challenge_status[16];
            auto cphr_buf_challenge_status = (unsigned char *) malloc(sizeof(uint16_t));
            auto plain_buf_challenge_status = (unsigned char *) malloc(sizeof(uint16_t));
            memcpy(aad_challenge_status, gcm_challenge_status, 12 + sizeof(uint32_t));
            memcpy(iv_challenge_status, gcm_challenge_status, 12);
            memcpy(cphr_buf_challenge_status, gcm_challenge_status + 12 + sizeof(uint32_t), sizeof(uint16_t));
            memcpy(tag_buf_challenge_status, gcm_challenge_status + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
            int ret_challenge_status = gcm_decrypt(cphr_buf_challenge_status, sizeof(uint16_t), server_cnt,
                                                   aad_challenge_status, tag_buf_challenge_status,
                                                   server_session_key, iv_challenge_status, 12,
                                                   plain_buf_challenge_status);
            if (ret_challenge_status == -2) {
                cout << "[client] Server's counter out of sync." << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }
            if (ret_challenge_status == -1) {
                cerr << "[client] Error encountered in decryption of message from server."
                     << endl;
                close(sd);
                exit(EXIT_FAILURE);
            }

            uint16_t challenge_status = *(uint16_t *) plain_buf_challenge_status;
            // Free up memory
            free(gcm_challenge_status);
            free(cphr_buf_challenge_status);
            free(plain_buf_challenge_status);

            cout << "opcode challenge " << challenge_status << endl;

            switch (challenge_status) {
                case MATCHMAKING: {

                    cout << "Request has been forwarded to the adversary" << endl;
                    cout << "Waiting for response..." << endl;
                    auto gcm_msg_reply = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                    rc = recv(sd, (void *) gcm_msg_reply, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), MSG_WAITALL);
                    if (rc < 0) {
                        if (errno != EWOULDBLOCK) {
                            cerr << "[Client] recv username of challenge failed" << endl;
                            close(sd);
                            exit(EXIT_FAILURE);
                        }
                        break;
                    }

                    if (rc == 0) {
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    unsigned char aad_reply[12 + sizeof(uint32_t)];
                    unsigned char iv_reply[12];
                    unsigned char tag_buf_reply[16];
                    auto cphr_buf_reply = (unsigned char *) malloc(sizeof(uint16_t));
                    auto plain_buf_reply = (unsigned char *) malloc(sizeof(uint16_t));
                    memcpy(aad_reply, gcm_msg_reply, 12 + sizeof(uint32_t));
                    memcpy(iv_reply, gcm_msg_reply, 12);
                    memcpy(cphr_buf_reply, gcm_msg_reply + 12 + sizeof(uint32_t), sizeof(uint16_t));
                    memcpy(tag_buf_reply, gcm_msg_reply + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                    int res_reply = gcm_decrypt(cphr_buf_reply, sizeof(uint16_t), server_cnt, aad_reply, tag_buf_reply,
                                                server_session_key, iv_reply, 12, plain_buf_reply);
                    if (res_reply == -2) {
                        cout << "[Client] counter out of sync. Disconnecting..." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res_reply == -1) {
                        cout << "[Client] Error encountered in decryption of message" << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    opcode_rcv = *(uint16_t *) plain_buf_reply;
                    opcode = ntohs(opcode_rcv);
                    free(gcm_msg_reply);
                    free(cphr_buf_reply);
                    free(plain_buf_reply);

                    if (opcode == CHALLENGE_REFUSED) {
                        cout << username_challenge + " has NOT accepted your challenge!!" << endl;
                        continue;
                    }
                    cout << username_challenge + " has accepted your challenge!!" << endl;
                    cout << "waiting to receive IP address and public key..." << endl;
                    // Ricezione INDIRIZZO IP del Destinatario////
                    auto gcm_dest_IP_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                    ret = recv(sd, (void *) gcm_dest_IP_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                               MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Challenge IP len rcv failed." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    unsigned char aad_dest_IP_len[12 + sizeof(uint32_t)];
                    unsigned char iv_dest_IP_len[12];
                    unsigned char tag_buf_dest_IP_len[16];
                    auto cphr_buf_dest_IP_len = (unsigned char *) malloc(sizeof(uint16_t));
                    auto plain_buf_dest_IP_len = (unsigned char *) malloc(sizeof(uint16_t));
                    memcpy(aad_dest_IP_len, gcm_dest_IP_len, 12 + sizeof(uint32_t));
                    memcpy(iv_dest_IP_len, gcm_dest_IP_len, 12);
                    memcpy(cphr_buf_dest_IP_len, gcm_dest_IP_len + 12 + sizeof(uint32_t), sizeof(uint16_t));
                    memcpy(tag_buf_dest_IP_len, gcm_dest_IP_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                    int ret_dest_IP_len = gcm_decrypt(cphr_buf_dest_IP_len, sizeof(uint16_t), server_cnt,
                                                      aad_dest_IP_len, tag_buf_dest_IP_len, server_session_key,
                                                      iv_dest_IP_len, 12, plain_buf_dest_IP_len);
                    if (ret_dest_IP_len == -2) {
                        cout << "[client] Server's counter out of sync." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (ret_dest_IP_len == -1) {
                        cerr << "[client] Error encountered in decryption of message from server."
                             << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    uint16_t dest_IP_len = *(uint16_t *) plain_buf_dest_IP_len;
                    // Free up memory
                    free(gcm_dest_IP_len);
                    free(cphr_buf_dest_IP_len);
                    free(plain_buf_dest_IP_len);

                    cout << "IP Len challenge " << ntohs(dest_IP_len) << endl;

                    //Ricezione dell'indirizzo ip del destinatario della richiesta di sfida dal server
                    uint16_t dest_IP_len_real = ntohs(dest_IP_len);
                    char IP_to_dest[dest_IP_len_real];

                    auto gcm_IP_dest = (unsigned char *) malloc(12 + sizeof(uint32_t) + dest_IP_len_real + 16);
                    ret = recv(sd, (void *) gcm_IP_dest, (12 + sizeof(uint32_t) + dest_IP_len_real + 16), MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Challenge IP rcv failed." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    unsigned char aad_IP_dest[12 + sizeof(uint32_t)];
                    unsigned char iv_IP_dest[12];
                    unsigned char tag_buf_IP_dest[16];
                    auto cphr_buf_IP_dest = (unsigned char *) malloc(dest_IP_len_real);
                    memcpy(aad_IP_dest, gcm_IP_dest, 12 + sizeof(uint32_t));
                    memcpy(iv_IP_dest, gcm_IP_dest, 12);
                    memcpy(cphr_buf_IP_dest, gcm_IP_dest + 12 + sizeof(uint32_t), dest_IP_len_real);
                    memcpy(tag_buf_IP_dest, gcm_IP_dest + 12 + sizeof(uint32_t) + dest_IP_len_real, 16);
                    int res_IP_dest = gcm_decrypt(cphr_buf_IP_dest, dest_IP_len_real, server_cnt, aad_IP_dest,
                                                  tag_buf_IP_dest, server_session_key, iv_IP_dest, 12,
                                                  (unsigned char *) IP_to_dest);
                    if (res_IP_dest == -1) {
                        cout << "[Client] Sever's counter out of sync. Disconnecting..." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res_IP_dest == -2) {
                        cout << "[Client] Error encountered in decryption of message from Server " << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    string IP_dest = (char *) IP_to_dest;
                    cout << "IP: " << IP_dest << endl;

                    // Free up memory
                    free(gcm_IP_dest);
                    free(cphr_buf_IP_dest);

                    //RICEZIONE PORTA DI ASCOLTO DEL DESTINATARIO
                    auto gcm_msg_list_port = (unsigned char *) malloc(
                            12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                    rc = recv(sd, (void *) gcm_msg_list_port,
                              (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                              MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Challenge port rcv failed." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
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
                    int res_list_port = gcm_decrypt(cphr_buf_list_port, sizeof(uint16_t), server_cnt, aad_list_port,
                                                    tag_buf_list_port, server_session_key, iv_list_port, 12,
                                                    plain_buf_list_port);
                    if (res_list_port == -2) {
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res == -1) {
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    uint16_t listening_port_dest = *(uint16_t *) plain_buf_list_port;
                    uint16_t listening_port_dest_real = ntohs(listening_port_dest);
                    cout << "listening port: " << listening_port_dest_real << endl;


                    ///RICEZIONE CHIAVE PUBBLICA DESTINATARIO///////////////
                    uint64_t pubkey_dest_size_rcv = 0;

                    auto gcm_key_len_dest = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint64_t) + 16);
                    ret = recv(sd, (void *) gcm_key_len_dest, (12 + sizeof(uint32_t) + sizeof(uint64_t) + 16),
                               MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Challenge IP len rcv failed." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    unsigned char aad_key_len_dest[12 + sizeof(uint32_t)];
                    unsigned char iv_key_len_dest[12];
                    unsigned char tag_key_len_dest[16];
                    auto cphr_buf_key_len_dest = (unsigned char *) malloc(sizeof(uint64_t));
                    auto plain_buf_key_len_dest = (unsigned char *) malloc(sizeof(uint64_t));
                    memcpy(aad_key_len_dest, gcm_key_len_dest, 12 + sizeof(uint32_t));
                    memcpy(iv_key_len_dest, gcm_key_len_dest, 12);
                    memcpy(cphr_buf_key_len_dest, gcm_key_len_dest + 12 + sizeof(uint32_t), sizeof(uint64_t));
                    memcpy(tag_key_len_dest, gcm_key_len_dest + 12 + sizeof(uint32_t) + sizeof(uint64_t), 16);
                    int ret_key_len_dest = gcm_decrypt(cphr_buf_key_len_dest, sizeof(uint64_t), server_cnt,
                                                       aad_key_len_dest, tag_key_len_dest, server_session_key,
                                                       iv_key_len_dest, 12, plain_buf_key_len_dest);
                    if (ret_key_len_dest == -2) {
                        cout << "[client] Server's counter out of sync." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (ret_key_len_dest == -1) {
                        cerr << "[client] Error encountered in decryption of message from server."
                             << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    pubkey_dest_size_rcv = *(uint64_t *) plain_buf_key_len_dest;
                    uint64_t pubkey_dest_size_real = ntohs(pubkey_dest_size_rcv);
                    cout << "Public key size: " << pubkey_dest_size_real << endl;

                    auto *pubkey_dest = (unsigned char *) malloc(12 + sizeof(uint32_t) + pubkey_dest_size_real + 16);
                    char pubkey_dest_buf[pubkey_dest_size_real];
                    int ret_key_dest = recv(sd, pubkey_dest, (12 + sizeof(uint32_t) + pubkey_dest_size_real + 16),
                                            MSG_WAITALL);
                    if (ret_key_dest < 0) {
                        cerr << "[client] Error encountered in reception of challenger's public key!" << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    unsigned char aad_pubkey_dest[12 + sizeof(uint32_t)];
                    unsigned char iv_pubkey_dest[12];
                    unsigned char tag_pubkey_dest[16];
                    auto cphr_buf_pubkey_dest = (unsigned char *) malloc(pubkey_dest_size_real);
                    memcpy(aad_pubkey_dest, pubkey_dest, 12 + sizeof(uint32_t));
                    memcpy(iv_pubkey_dest, pubkey_dest, 12);
                    memcpy(cphr_buf_pubkey_dest, pubkey_dest + 12 + sizeof(uint32_t), pubkey_dest_size_real);
                    memcpy(tag_pubkey_dest, pubkey_dest + 12 + sizeof(uint32_t) + pubkey_dest_size_real, 16);
                    int res_pubkey_dest = gcm_decrypt(cphr_buf_pubkey_dest, pubkey_dest_size_real, server_cnt,
                                                      aad_pubkey_dest, tag_pubkey_dest, server_session_key,
                                                      iv_pubkey_dest, 12, (unsigned char *) pubkey_dest_buf);

                    if (res_pubkey_dest == -2) {
                        cout << "[Client] Sever's counter out of sync. Disconnecting..." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res_pubkey_dest == -1) {
                        cout << "[Client] Error encountered in decryption of message from Server " << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    // Free up memory
                    free(pubkey_dest);
                    free(cphr_buf_pubkey_dest);

                    cout << "Received from the server the public key of " + username_challenge + ":" << endl;
                    BIO_dump_fp(stdout, (const char *) pubkey_dest_buf, pubkey_dest_size_real);

                    BIO *mbio_rcv_dest = BIO_new(BIO_s_mem());
                    BIO_write(mbio_rcv_dest, pubkey_dest_buf, pubkey_dest_size_real);
                    EVP_PKEY *peer_dest_pubkey = PEM_read_bio_PUBKEY(mbio_rcv_dest, nullptr, nullptr, nullptr);

                    //// Ricezione del match_id dal server

                    auto *matchid_dest = (unsigned char *) malloc(12 + sizeof(uint32_t) + NONCE_SIZE + 16);
                    memset(match_id, 0, NONCE_SIZE);
                    int ret_matchid_dest = recv(sd, matchid_dest, (12 + sizeof(uint32_t) + NONCE_SIZE + 16),
                                                MSG_WAITALL);
                    if (ret_matchid_dest < 0) {
                        cerr << "[client] Error encountered in reception of challenger's match_id!" << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    unsigned char aad_matchid_dest[12 + sizeof(uint32_t)];
                    unsigned char iv_matchid_dest[12];
                    unsigned char tag_matchid_dest[16];
                    auto cphr_buf_matchid_dest = (unsigned char *) malloc(NONCE_SIZE);
                    memcpy(aad_matchid_dest, matchid_dest, 12 + sizeof(uint32_t));
                    memcpy(iv_matchid_dest, matchid_dest, 12);
                    memcpy(cphr_buf_matchid_dest, matchid_dest + 12 + sizeof(uint32_t), NONCE_SIZE);
                    memcpy(tag_matchid_dest, matchid_dest + 12 + sizeof(uint32_t) + NONCE_SIZE, 16);
                    int res_matchid_dest = gcm_decrypt(cphr_buf_matchid_dest, NONCE_SIZE, server_cnt,
                                                       aad_matchid_dest, tag_matchid_dest, server_session_key,
                                                       iv_matchid_dest, 12, (unsigned char *) match_id);

                    if (res_pubkey_dest == -2) {
                        cout << "[Client] Sever's counter out of sync. Disconnecting..." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res_pubkey_dest == -1) {
                        cout << "[Client] Error encountered in decryption of message from Server " << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }

                    // Free up memory
                    free(matchid_dest);
                    free(cphr_buf_matchid_dest);

                    cout << "The received match_id is: " << endl;
                    BIO_dump_fp(stdout, (const char *) match_id, NONCE_SIZE);

                    cout << "[Client] Connecting to " + username_challenge << endl;
                    //DA QUESTO PUNTO IN POI NELLE DUE VARIABILI SONO DISPONIBILI L'INDIRIZZO IP E LA PORTA DEL DESTINATARIO DELLA SFIDA
                    //E' QUINDI NECESSARIO APRIRE UNA CONNESSIONE TCP
                    struct sockaddr_in addr_peer_challenge;
                    const char delimiter_address = ':';

                    string token;
                    stringstream ss(IP_dest);
                    vector<string> info_user_challenge;

                    while (getline(ss, token, delimiter_address)) {
                        info_user_challenge.push_back(token);
                        //cout<<"TOKEN: "<<token<<endl;
                    }
                    //Creazione socket TCP verso il peer
                    int challenge_sd = socket(AF_INET, SOCK_STREAM, 0);

                    /* Creazione indirizzo del peer */
                    addr_peer_challenge.sin_family = AF_INET;
                    addr_peer_challenge.sin_port = htons(listening_port_dest_real);
                    //addr_peer_challenge.sin_port = htons(stoi(info_user_challenge[1]));
                    inet_pton(AF_INET, info_user_challenge[0].c_str(), &addr_peer_challenge.sin_addr);
                    sleep(4); //per la sincronizzazione
                    ret = connect(challenge_sd, (struct sockaddr *) &addr_peer_challenge, sizeof(addr_peer_challenge));
                    if (ret < 0) {
                        cerr << "[client] Error during connection phase!" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    cout << "[Client] You are Connected to " + username_challenge << endl;

                    //invio NONCE
                    cout << "[client] Sending nonce to " + username_challenge << endl;
                    RAND_poll();
                    unsigned char nonce_client_peer[NONCE_SIZE];
                    RAND_bytes(nonce_client_peer, NONCE_SIZE);
                    ret = send(challenge_sd, (void *) nonce_client_peer, NONCE_SIZE, 0);
                    if (ret <= 0) {
                        cerr << "[client] send nonce to the peer failed." << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    cout << "nonce_client_peer" << endl;
                    BIO_dump_fp(stdout, (const char *) nonce_client_peer, NONCE_SIZE);

                    // Ricezione del nonce da parte dell'avversario

                    unsigned char nonce_challenger[NONCE_SIZE];
                    ret = recv(challenge_sd, (void *) nonce_challenger, NONCE_SIZE, 0);

                    if (ret == 0) {
                        cerr << "[client] The connection was closed." << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    if (ret < 0) {
                        cerr << "[client] Error encountered while receiving the nonce !" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    cout << "Il nonce ricevuto dall'avversario è :" << endl;
                    BIO_dump_fp(stdout, (const char *) nonce_challenger, NONCE_SIZE);

                    //// Ricezione chiave pubblica DH dal peer

                    uint64_t len_pubkey_rcvd;
                    int len_username;
                    ret = recv(challenge_sd, (void *) &len_pubkey_rcvd, sizeof(uint64_t), 0);
                    if (ret < 0) {
                        cerr << "[client] Error encountered while receiving len username's online user!" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    uint64_t len_pubkey_real = ntohs(len_pubkey_rcvd);
                    char pubkey_DH_challenger[len_pubkey_real];

                    ret = recv(challenge_sd, pubkey_DH_challenger, len_pubkey_real, MSG_WAITALL);
                    if (ret < 0) {
                        cerr << "[client] Error encountered in reception of  DH server's public key!" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    //cout<<"Ricevuto da server La seguente chiave Pubblica DH "<<endl;
                    //BIO_dump_fp(stdout, (const char *) pubkey_DH_server, ntohs(pubkey_DH_server_size_rcv));

                    BIO *mbio_rcv = BIO_new(BIO_s_mem());
                    BIO_write(mbio_rcv, pubkey_DH_challenger, len_pubkey_real);
                    EVP_PKEY *challenger_pubkey = PEM_read_bio_PUBKEY(mbio_rcv, nullptr, nullptr, nullptr);

                    cout << "received public key of challenger: " << endl;
                    BIO_dump_fp(stdout, (const char *) pubkey_DH_challenger, len_pubkey_real);

                    //// Ricezione firma chiave pubblica + nonce

                    int buf_to_verify_size = NONCE_SIZE * 3 + len_pubkey_real;
                    unsigned char buf_to_verify[buf_to_verify_size];
                    memcpy(buf_to_verify, pubkey_DH_challenger, len_pubkey_real);
                    memcpy(buf_to_verify + len_pubkey_real, match_id, NONCE_SIZE);
                    memcpy(buf_to_verify + len_pubkey_real + NONCE_SIZE, nonce_challenger, NONCE_SIZE);
                    memcpy(buf_to_verify + len_pubkey_real + NONCE_SIZE * 2, nonce_client_peer, NONCE_SIZE);

                    uint64_t hash_size_rcv;
                    ret = recv(challenge_sd, (void *) &hash_size_rcv, sizeof(uint64_t), 0);
                    if (ret < 0) {
                        cerr << "[client] Error encountered while receiving hash size!" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    int hash_size_real = ntohs(hash_size_rcv);
                    cout << "hash size: " << hash_size_real << endl;

                    unsigned char sgn_peer_rcvd[hash_size_real];
                    ret = recv(challenge_sd, sgn_peer_rcvd, hash_size_real, MSG_WAITALL);
                    if (ret < 0) {
                        cerr << "[client] Error encountered in reception of  DH server's public key!" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    EVP_MD_CTX *md_ctx_sk = EVP_MD_CTX_new();
                    if (!md_ctx_sk) {
                        cout << "[Client]: error in EVP_MD_CTX_new" << endl;
                        close(sd);
                        exit(EXIT_FAILURE);
                    }
                    rc = EVP_VerifyInit(md_ctx_sk, md);
                    if (rc == 0) {
                        cout << "[Client]: error in VerifyInit" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    rc = EVP_VerifyUpdate(md_ctx_sk, buf_to_verify, buf_to_verify_size);
                    if (rc == 0) {
                        cout << "[Client]: error in VerifyUpdate" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    rc = EVP_VerifyFinal(md_ctx_sk, sgn_peer_rcvd, hash_size_real, peer_dest_pubkey);
                    BIO_free(mbio_rcv);

                    if (rc != 1) {
                        cout
                                << "[client] The signature of the peer has NOT been verified correctly " << rc <<
                                endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    cout << "[client] Signature of peer correctly verified!" << endl;

                    //// Generazione chiave pubblica da inviare al peer

                    EVP_PKEY *params;
                    if (nullptr == (params = EVP_PKEY_new())) {
                        cerr << "[client] Error during the creation of params" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    DH *temp = get_dh2048();
                    if (1 != EVP_PKEY_set1_DH(params, temp)) {
                        cerr << "[client] Error during setting params" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    DH_free(temp);
                    //cout << "Generating ephemeral DH KeyPair with Server" << endl;

                    /* Create context for the key generation */
                    EVP_PKEY_CTX *DHctx;
                    if (!(DHctx = EVP_PKEY_CTX_new(params, nullptr))) {
                        cerr << "[client] Error during the creation of params" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    //cout << "eseguita creazione contesto" << endl;

                    /* Generate a new key */
                    EVP_PKEY *my_dhkey = nullptr;
                    if (1 != EVP_PKEY_keygen_init(DHctx)) {
                        cerr << "[client] Error during keygen_init" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    //cout << "eseguita init key gen int " << endl;
                    if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) {
                        cerr << "[client] Error during keygen" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    //// Invio al peer di chiave pubblica e sgn(chiave pubblica, nonces)

                    BIO *mbio = BIO_new(BIO_s_mem());
                    PEM_write_bio_PUBKEY(mbio, my_dhkey);
                    char *pubkey_DH_buf = nullptr;
                    long pubkey_DH_size = BIO_get_mem_data(mbio, &pubkey_DH_buf);

                    uint64_t pubkey_DH_size_snd = htons(pubkey_DH_size);
                    ret = send(challenge_sd, (void *) &pubkey_DH_size_snd, sizeof(uint64_t), 0);
                    if (ret < 0) {
                        cerr << "[client] Error sending public key DH size" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    ret = send(challenge_sd, pubkey_DH_buf, pubkey_DH_size, 0);
                    if (ret < 0) {
                        cerr << "[client] Error sending public key DH" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    cout << "public key generated: " << endl;
                    BIO_dump_fp(stdout, (const char *) pubkey_DH_buf, pubkey_DH_size);

                    long int to_sign_size = (NONCE_SIZE * 3) + pubkey_DH_size;
                    auto *buf_to_sign = (unsigned char *) malloc(to_sign_size);

                    memcpy(buf_to_sign, pubkey_DH_buf, pubkey_DH_size);
                    memcpy(buf_to_sign + pubkey_DH_size, match_id, NONCE_SIZE);
                    memcpy(buf_to_sign + pubkey_DH_size + NONCE_SIZE, nonce_client_peer, NONCE_SIZE);
                    memcpy(buf_to_sign + pubkey_DH_size + NONCE_SIZE * 2, nonce_challenger, NONCE_SIZE);

                    // create the signature context:
                    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
                    if (!md_ctx) {
                        cerr << "[client] EVP_MD_CTX_new returned nullptr" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    auto *sgnt_buf = (unsigned char *) malloc(EVP_PKEY_size(prvkey));
                    if (!sgnt_buf) {
                        cerr << "[client] malloc returned nullptr" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    ret = EVP_SignInit(md_ctx, md);
                    if (ret == 0) {
                        cerr << "[client] EVP_SignInit returned " << ret << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    ret = EVP_SignUpdate(md_ctx, buf_to_sign, to_sign_size);
                    if (ret == 0) {
                        cerr << "[client] EVP_SignUpdate returned " << ret << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    free(buf_to_sign);
                    unsigned int sgnt_size;
                    ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
                    if (ret == 0) {
                        cerr << "[client] EVP_SignFinal returned " << ret << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    BIO_free(mbio);

                    uint64_t hash_size_snd = htons(sgnt_size);
                    cout << "hash_size_send: " << sgnt_size << endl;
                    ret = send(challenge_sd, (void *) &hash_size_snd, sizeof(uint64_t), 0);
                    if (ret < 0) {
                        cerr << "[client] Error sending digest size" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    //cout<<"Dimensione hash da inviare: "<<sgnt_size<<endl;

                    //invio del digest
                    ret = send(challenge_sd, (void *) sgnt_buf, sgnt_size, 0);
                    if (ret < 0) {
                        cerr << "[client] Error sending digest " << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    //// Generazione segreto condiviso peer-to-peer

                    EVP_PKEY_CTX *derive_ctx;
                    unsigned char *skey;
                    size_t skeylen;
                    derive_ctx = EVP_PKEY_CTX_new(my_dhkey, nullptr);
                    if (!derive_ctx) {
                        cerr << "[client] Error deriving context" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
                        cerr << "[client] Error derive_init" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    if (EVP_PKEY_derive_set_peer(derive_ctx, challenger_pubkey) <= 0) {
                        cerr << "[client] Error deriving_set_perr " << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    EVP_PKEY_derive(derive_ctx, nullptr, &skeylen);
                    skey = (unsigned char *) (malloc(int(skeylen)));
                    if (!skey) {
                        cerr << "[client] Error alloc shared key " << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) {
                        cerr << "[client] Error deriving secret " << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    EVP_PKEY_CTX_free(derive_ctx);
                    EVP_PKEY_free(challenger_pubkey);
                    EVP_PKEY_free(my_dhkey);
                    EVP_PKEY_CTX_free(DHctx);
                    EVP_PKEY_free(params);
                    EVP_MD_CTX_free(md_ctx);

                    auto *digest_ss = (unsigned char *) malloc(EVP_MD_size(EVP_sha256()));
                    unsigned int digestlen;
                    EVP_MD_CTX *md_ctx_hash;
                    md_ctx_hash = EVP_MD_CTX_new();
                    EVP_DigestInit(md_ctx_hash, md);
                    EVP_DigestUpdate(md_ctx_hash, (unsigned char *) skey, skeylen);
                    EVP_DigestFinal(md_ctx_hash, digest_ss, &digestlen);
                    EVP_MD_CTX_free(md_ctx_hash);
                    //cout << "The dimension of the digest is:" << digestlen << endl;
                    memcpy(peer_session_key, digest_ss, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
#pragma optimize("", off);
                    memset(digest_ss, 0, digestlen);
                    memset(skey, 0, skeylen);
#pragma optimize("", on);
                    free(digest_ss);
                    free(skey);
                    cout << "[client] The session key with the peer is: "
                         << BIO_dump_fp(stdout, (const char *) peer_session_key,
                                        EVP_CIPHER_key_length(EVP_aes_128_gcm())) << endl;


                    playing = true; // La seguente variabile viene settata nei peer a true per indicare che stanno giocando -> se questa è true la print_options stampa più comandi rispetto a quando questa variabile è false
                    peer_cnt = 0;

                    unsigned char aad_peer[12 + sizeof(uint32_t)];
                    unsigned char iv_peer[12];
                    unsigned char tag_peer[16];
                    unsigned char cphr_buf_peer[sizeof(uint16_t)];
                    unsigned char pltx_buf_peer[sizeof(uint16_t)];
                    unsigned char gcm_msg_peer[12 + sizeof(uint32_t) + sizeof(uint16_t) + 16];
                    uint16_t message;

                    cout << "Rolling dice... ";
                    random_device rd;
                    mt19937 mt(rd());
                    uniform_int_distribution<> dist(1, 20);
                    int dice_roll = dist(mt);
                    cout << dice_roll << "!" << endl;

                    message = dice_roll;
                    res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                      peer_session_key,
                                      cphr_buf_peer, tag_peer);
                    memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                    memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                    memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                    ret = send(challenge_sd, (void *) gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                    if (ret <= 0) {
                        cerr << "[Client] send() to peer failed" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    ret = recv(challenge_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                               MSG_WAITALL);
                    if (ret <= 0) {
                        cerr << "[client] Error encountered in reception of message from peer!" << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                    memcpy(iv_peer, gcm_msg_peer, 12);
                    memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                    memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                    res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                      tag_peer, peer_session_key, iv_peer, 12,
                                      (unsigned char *) pltx_buf_peer);
                    if (res == -1) {
                        cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }
                    if (res == -2) {
                        cout << "[client] Error encountered in decryption of message from peer. " << endl;
                        close(challenge_sd);
                        exit(EXIT_FAILURE);
                    }

                    message = *(uint16_t *) pltx_buf_peer;

                    cout << "Opponent rolled: " << message << "." << endl;

                    bool first = false;
                    if (dice_roll >= message) {
                        cout << "You go first!" << endl;
                        first = true;
                    } else
                        cout << "Opponent goes first!" << endl;

                    /*** The game begins. ***/
                    initGame();
                    printField();
                    int column;

                    if (!first) {
                        cout << "Opponent's turn...";
                        cout.flush();
                        ret = recv(challenge_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   MSG_WAITALL);
                        if (ret <= 0) {
                            cerr << "[client] Error encountered in reception of message from peer!" << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }

                        memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                        memcpy(iv_peer, gcm_msg_peer, 12);
                        memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                        memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                        res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                          tag_peer, peer_session_key, iv_peer, 12,
                                          (unsigned char *) pltx_buf_peer);
                        if (res == -1) {
                            cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }
                        if (res == -2) {
                            cout << "[client] Error encountered in decryption of message from peer. " << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }

                        message = *(uint16_t *) pltx_buf_peer;

                        // TODO check legal value

                        move(message, 1);
                    }

                    while (!endGame && counterMoves < 42) {
                        bool valid = false;
                        do {
                            cout << "Your turn!" << endl;
                            cout << "> ";
                            getline(cin, cmd);
                            trim(cmd);
                            string token;
                            stringstream ss(cmd);
                            const char delimiter = ' ';
                            vector<string> command;
                            while (getline(ss, token, delimiter)) {
                                command.push_back(token);
                            }
                            if (command.at(0).empty()) {
                                continue;
                            } else if (command.at(0) == "!concede") {
                                // TODO
                                endGame = true;
                                break;
                            } else if (command.at(0) == "!move") {
                                if (is_number(command.at(1))) {
                                    column = stoi(command.at(1));
                                    if (move(column, 0)) {
                                        valid = true;
                                    }
                                }
                            }
                        } while (!valid);

                        message = column;
                        res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                          peer_session_key,
                                          cphr_buf_peer, tag_peer);
                        memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                        memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                        memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                        ret = send(challenge_sd, (void *) gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   0);
                        if (ret <= 0) {
                            cerr << "[Client] send() to peer failed" << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }

                        if (winner == 0) {
                            message = GAME_OVER;
                            res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                              peer_session_key,
                                              cphr_buf_peer, tag_peer);
                            memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                            memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                            memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                            ret = send(challenge_sd, (void *) gcm_msg_peer,
                                       (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                       0);
                            if (ret <= 0) {
                                cerr << "[Client] send() to peer failed" << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }
                            cout << "You won!" << endl;
                            cout << "Closing connection with peer..." << endl;
                            close(challenge_sd);
                            break;
                        }

                        if (counterMoves == 42) {
                            message = GAME_OVER_TIE;
                            res = gcm_encrypt((unsigned char *) &message, sizeof(uint16_t), peer_cnt, aad_peer,
                                              peer_session_key,
                                              cphr_buf_peer, tag_peer);
                            memcpy(gcm_msg_peer, aad_peer, 12 + sizeof(uint32_t));
                            memcpy(gcm_msg_peer + 12 + sizeof(uint32_t), cphr_buf_peer, sizeof(uint16_t));
                            memcpy(gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_peer, 16);
                            ret = send(challenge_sd, (void *) gcm_msg_peer,
                                       (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                       0);
                            if (ret <= 0) {
                                cerr << "[Client] send() to peer failed" << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }
                            cout << "You tied!" << endl;
                            cout << "Closing connection with peer..." << endl;
                            close(challenge_sd);
                            break;
                        }

                        cout << "Opponent's turn...";
                        cout.flush();

                        ret = recv(challenge_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                   MSG_WAITALL);
                        if (ret <= 0) {
                            cerr << "[client] Error encountered in reception of message from peer!" << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }

                        memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                        memcpy(iv_peer, gcm_msg_peer, 12);
                        memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                        memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                        res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                          tag_peer, peer_session_key, iv_peer, 12,
                                          (unsigned char *) pltx_buf_peer);
                        if (res == -1) {
                            cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }
                        if (res == -2) {
                            cout << "[client] Error encountered in decryption of message from peer. " << endl;
                            close(challenge_sd);
                            exit(EXIT_FAILURE);
                        }

                        message = *(uint16_t *) pltx_buf_peer;

                        column = message;
                        move(column, 1);

                        if (winner == 1) {
                            ret = recv(challenge_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                       MSG_WAITALL);
                            if (ret <= 0) {
                                cerr << "[client] Error encountered in reception of message from peer!" << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }

                            memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                            memcpy(iv_peer, gcm_msg_peer, 12);
                            memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                            memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                            res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                              tag_peer, peer_session_key, iv_peer, 12,
                                              (unsigned char *) pltx_buf_peer);
                            if (res == -1) {
                                cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }
                            if (res == -2) {
                                cout << "[client] Error encountered in decryption of message from peer. " << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }

                            message = *(uint16_t *) pltx_buf_peer;
                            if (message == GAME_OVER) {
                                cout << "You lost!" << endl;
                            } else {
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }
                            cout << "Closing connection with peer..." << endl;
                            close(challenge_sd);
                            break;
                        }

                        if (counterMoves == 42) {
                            ret = recv(challenge_sd, gcm_msg_peer, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16),
                                       MSG_WAITALL);
                            if (ret <= 0) {
                                cerr << "[client] Error encountered in reception of message from peer!" << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }

                            memcpy(aad_peer, gcm_msg_peer, 12 + sizeof(uint32_t));
                            memcpy(iv_peer, gcm_msg_peer, 12);
                            memcpy(cphr_buf_peer, gcm_msg_peer + 12 + sizeof(uint32_t), sizeof(uint16_t));
                            memcpy(tag_peer, gcm_msg_peer + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                            res = gcm_decrypt(cphr_buf_peer, sizeof(uint16_t), peer_cnt, aad_peer,
                                              tag_peer, peer_session_key, iv_peer, 12,
                                              (unsigned char *) pltx_buf_peer);
                            if (res == -1) {
                                cout << "[client] Peer's counter out of sync. Disconnecting..." << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }
                            if (res == -2) {
                                cout << "[client] Error encountered in decryption of message from peer. " << endl;
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }

                            message = *(uint16_t *) pltx_buf_peer;
                            if (message == GAME_OVER_TIE) {
                                cout << "You tied!" << endl;
                            } else {
                                close(challenge_sd);
                                exit(EXIT_FAILURE);
                            }
                            cout << "Closing connection with peer..." << endl;
                            close(challenge_sd);
                            break;
                        }

                    }

                        //print_options(playing);
                        break;
                    }
                    case OFFLINE:
                        cout << "[client] User " << username_challenge << " is offline." << endl;
                    break;
                    case UNREGISTERED:
                        cout << "[client] User " << username_challenge << " is not registered on this server!" << endl;
                    break;
                    case ERROR_CHALLENGE_SELF:
                        cout << "[client] You cannot challenge yourself!" << endl;
                    break;
                    case ONLINE:
                        cout << "[client] User " << username_challenge << " is online but not in MATCHMAKING state"
                             << endl;
                    break;
                    default:
                        cout << "[client] Connection with " << username_challenge << "failed." << endl;
                    break;
                }


                    continue;
            } else if (command.at(0) == "!users") {
                //invio opcode richiesta di visualizzazione degli utenti online al server
                opcode_snd = SHOW_ONLINE_USERS_OPC;
                opcode = htons(opcode_snd);
                unsigned char aad[12 + sizeof(uint32_t)];
                unsigned char tag_buf[16];
                auto cphr_buf = (unsigned char *) malloc(sizeof(uint16_t));
                auto gcm_msg = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                int res = gcm_encrypt((unsigned char *) &opcode, sizeof(uint16_t), server_cnt, aad, server_session_key,
                                      cphr_buf,
                                      tag_buf);
                memcpy(gcm_msg, aad, 12 + sizeof(uint32_t));
                memcpy(gcm_msg + 12 + sizeof(uint32_t), cphr_buf, sizeof(uint16_t));
                memcpy(gcm_msg + 12 + sizeof(uint32_t) + sizeof(uint16_t), tag_buf, 16);
                ret = send(sd, (void *) gcm_msg, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), 0);
                free(cphr_buf);
                free(gcm_msg);
                if (ret <= 0) {
                    cerr << "[client] Error encountered while sending show online users command to the server!" << endl;
                    close(sd);
                    exit(EXIT_FAILURE);
                }

                //Attesa ricezione numero di utenti attualmente in matchmaking
                online_users.erase(online_users.begin(), online_users.end()); //pulizia lista utenti online

                auto gcm_msg_num_users = (unsigned char *) malloc(
                                12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                rc = recv(sd, (void *) gcm_msg_num_users, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), MSG_WAITALL);
                if (rc < 0) {
                    if (errno != EWOULDBLOCK) {
                           cerr << "recv() num users failed" << endl;
                            close(sd);
                            exit(EXIT_FAILURE);
                    }
                    break;
                }

                if (rc == 0) {
                           cerr << "[client] Disconnection receiving number of users!" << endl;
                           close(sd);
                           exit(EXIT_FAILURE);
                }

                unsigned char aad_num_users[12 + sizeof(uint32_t)];
                unsigned char iv_num_users[12];
                unsigned char tag_buf_num_users[16];
                auto cphr_buf_num_users = (unsigned char *) malloc(sizeof(uint16_t));
                auto plain_buf_num_users = (unsigned char *) malloc(sizeof(uint16_t));
                memcpy(aad_num_users, gcm_msg_num_users, 12 + sizeof(uint32_t));
                memcpy(iv_num_users, gcm_msg_num_users, 12);
                memcpy(cphr_buf_num_users, gcm_msg_num_users + 12 + sizeof(uint32_t), sizeof(uint16_t));
                memcpy(tag_buf_num_users, gcm_msg_num_users + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                res = gcm_decrypt(cphr_buf_num_users, sizeof(uint16_t), server_cnt, aad_num_users, tag_buf_num_users, server_session_key, iv_num_users, 12, plain_buf_num_users);
                if (res == -2) {
                         cout << "[server] Client's counter out of sync. Disconnecting..." << endl;
                         close(sd);
                         exit(EXIT_FAILURE);
                }
                if (res == -1) {
                         cout << "[Client] Error encountered in decryption of message from server" << endl;
                         close(sd);
                         exit(EXIT_FAILURE);
                }

                uint16_t num_users = *(uint16_t *) plain_buf_num_users;
                number_users_online = ntohs(num_users);
                cout << "Actual number of users in MATCHMAKING: " << number_users_online << endl;
                // Free up memory
                free(gcm_msg_num_users);
                free(cphr_buf_num_users);
                free(plain_buf_num_users);


                //Ricezione degli username degli utenti attualmente online
                for (int k = 0; k < number_users_online; k++) {
                    auto gcm_msg_num_users_len = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                    rc = recv(sd, (void *) gcm_msg_num_users_len, (12 + sizeof(uint32_t) + sizeof(uint16_t) + 16), MSG_WAITALL);
                    if (rc < 0) {
                    	if (errno != EWOULDBLOCK) {
                           	cerr << "recv() num users failed" << endl;
                            	close(sd);
                            	exit(EXIT_FAILURE);
                   	 }
                   	 break;
                    }

                    if (rc == 0) {
                           cerr << "[client] Disconnection receiving number of users!" << endl;
                           close(sd);
                           exit(EXIT_FAILURE);
                    }

                    unsigned char aad_num_users_len[12 + sizeof(uint32_t)];
                    unsigned char iv_num_users_len[12];
                    unsigned char tag_buf_num_users_len[16];
                    auto cphr_buf_num_users_len = (unsigned char *) malloc(sizeof(uint16_t));
                    auto plain_buf_num_users_len = (unsigned char *) malloc(sizeof(uint16_t));
                    memcpy(aad_num_users_len, gcm_msg_num_users_len, 12 + sizeof(uint32_t));
                    memcpy(iv_num_users_len, gcm_msg_num_users_len, 12);
                    memcpy(cphr_buf_num_users_len, gcm_msg_num_users_len + 12 + sizeof(uint32_t), sizeof(uint16_t));
                    memcpy(tag_buf_num_users_len, gcm_msg_num_users_len + 12 + sizeof(uint32_t) + sizeof(uint16_t), 16);
                    res = gcm_decrypt(cphr_buf_num_users_len, sizeof(uint16_t), server_cnt, aad_num_users_len, tag_buf_num_users_len, server_session_key, iv_num_users_len, 12, plain_buf_num_users_len);
                    if (res == -2) {
                         cout << "[server] Client's counter out of sync. Disconnecting..." << endl;
                         close(sd);
                         exit(EXIT_FAILURE);
                    }
                    if (res == -1) {
                         cout << "[Client] Error encountered in decryption of message from server" << endl;
                         close(sd);
                         exit(EXIT_FAILURE);
                    }

                    uint16_t len_username_rcvd = *(uint16_t *) plain_buf_num_users_len;
                    int len_username = ntohs(len_username_rcvd);
                    
                    
                    //char tmp_msg[len_username];
                    auto gcm_msg_num_users = (unsigned char *) malloc(12 + sizeof(uint32_t) + sizeof(uint16_t) + 16);
                    rc = recv(sd, (void *) gcm_msg_num_users, (12 + sizeof(uint32_t) + len_username + 16), MSG_WAITALL);
                    if (rc < 0) {
                    	if (errno != EWOULDBLOCK) {
                           	cerr << "recv() list users failed" << endl;
                            	close(sd);
                            	exit(EXIT_FAILURE);
                   	 }
                   	 break;
                    }

                    if (rc == 0) {
                           cerr << "[client] Disconnection receiving list of users!" << endl;
                           close(sd);
                           exit(EXIT_FAILURE);
                    }

                    unsigned char aad_num_users[12 + sizeof(uint32_t)];
                    unsigned char iv_num_users[12];
                    unsigned char tag_buf_num_users[16];
                    auto cphr_buf_num_users = (unsigned char *) malloc(len_username);
                    auto plain_buf_num_users = (unsigned char *) malloc(len_username);
                    memcpy(aad_num_users, gcm_msg_num_users, 12 + sizeof(uint32_t));
                    memcpy(iv_num_users, gcm_msg_num_users, 12);
                    memcpy(cphr_buf_num_users, gcm_msg_num_users + 12 + sizeof(uint32_t), len_username);
                    memcpy(tag_buf_num_users, gcm_msg_num_users + 12 + sizeof(uint32_t) + len_username, 16);
                    res = gcm_decrypt(cphr_buf_num_users, len_username, server_cnt, aad_num_users, tag_buf_num_users, server_session_key, iv_num_users, 12, plain_buf_num_users);
                    if (res == -2) {
                         cout << "[server] Client's counter out of sync. Disconnecting..." << endl;
                         close(sd);
                         exit(EXIT_FAILURE);
                    }
                    if (res == -1) {
                         cout << "[Client] Error encountered in decryption of message from server" << endl;
                         close(sd);
                         exit(EXIT_FAILURE);
                    }

                    string tmp_string = (char *) plain_buf_num_users;
                    online_users.push_back(tmp_string);
                }

                //Stampa della lista degli utenti online
                for (auto &online_user : online_users)
                    cout << online_user << endl;

            } else {
                cout << "[client] Unknown command." << endl;
            }

        }
        while (true);
    }

