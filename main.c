#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>
#define BACKLOG 10
#define DEBUG_LEVEL 0

#define TOKEN_DUMP if(DEBUG_LEVEL & 1)
#define TRACE_PARSER if(DEBUG_LEVEL & 2)
#define TRACE_AST if(DEBUG_LEVEL & 4)
#define VAR_DUMP if(DEBUG_LEVEL & 8)
#define TRACE_VARS if(DEBUG_LEVEL & 16)
#define DUMP_PATHS if(DEBUG_LEVEL & 32)
#define DUMP_SQL_GETTER if(DEBUG_LEVEL & 64)
#define TRACE_SYS_FILE_READ_CALLS if(DEBUG_LEVEL & 128)


#define PORT 443
#define BIND_ADDR "192.168.1.212"
#define DOMAIN "opaq.co.il"
#define CERT_FILE "/home/opaq/ITLC_https_v2-main/Backend/certs/fullchain.pem"
#define KEY_FILE  "/home/opaq/ITLC_https_v2-main/Backend/certs/privkey.pem"
#define HOME      "/home/opaq/ITLC_https_v2-main/"

#define ANSI_RESET    "\e[0m"
#define ANSI_GREEN    "\e[32m"
#define ANSI_CYAN     "\e[36m"
#define ANSI_YELLOW   "\e[33m"
#define ANSI_BOLD_RED "\e[1;31m"
#define ANSI_DIM_GRAY "\e[2;37m"
#define ANSI_MAGENTA  "\e[35m"

#define LIST_2D(...) (char *[]){__VA_ARGS__}

char * domain;
char * bind_addr;
int https_port;

//#include "https/https.c"
void bind_signal_handlers();
void* handle_http(void *arg);
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);
void * handle_client(void *arg);
#define BUFFER_SIZE 8192
#define MAX_URI_LENGTH 4096
#define MAX_HEADER_BLOCK 65536

typedef struct {
    size_t size;
    char *data;
} FileInfo;
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>


/* return 1 if s contains "..", else 0 */
static int contains_dotdot(const char *s) {
    if (!s) return 1;
    for (const char *p = s; *p; ++p) {
        if (p[0] == '.' && p[1] == '.') return 1;
    }
    return 0;
}

/* Simple allowed-file check using stat + access only.
 * home should be like "/var/www/" (prefer trailing slash).
 * host is the site folder (e.g., "example.com").
 * uri is the request path (e.g., "/index.html" or "index.html").
 * Returns 1 if file exists, is regular, and readable; otherwise 0.
 */
int is_file_allowed(const char *home, const char *host, const char *uri) {
    if (!home || !host || !uri) return 0;

    if (contains_dotdot(host) || contains_dotdot(uri)) return 0;

    /* normalize uri: skip leading slash */
    const char *u = uri;
    if (u[0] == '/') u++;

    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s/%s", home, host, u);
    if (n < 0 || n >= (int)sizeof(candidate)) return 0;

    struct stat st;
    if (stat(candidate, &st) != 0) return 0;        /* not exists or stat error */
    if (!S_ISREG(st.st_mode)) return 0;             /* not a regular file */
    if (access(candidate, R_OK) != 0) return 0;     /* not readable */

    return 1;
}



FileInfo get_file(const char* host, const char* filename) {
    FileInfo result;
    result.data = NULL;
    result.size = 0;
    char path[1024];
   // if(strcmp(host,"localhost") == 0)
   strcpy(path, HOME);
    strcat(path, host);
    strcat(path, filename);
//     printf("%s\n", path);
    FILE* file = fopen(path, "r");
    if (!file) {
        perror("Failed to open file");
        return result;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(file);
        return result;
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell failed");
        fclose(file);
        return result;
    }
    rewind(file);

    unsigned char* buffer = (unsigned char*)calloc(size/sizeof(unsigned char), sizeof(unsigned char));
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return result;
    }

    size_t read = fread(buffer, 1, size, file);
    fclose(file);

    if (read != (size_t)size) {
        fprintf(stderr, "Only read %zu of %ld bytes\n", read, size);
        free(buffer);
        return result;
    }

    result.data = buffer;
    result.size = read;
    //itlc = result;
    return result;
}
typedef enum {
    M_OPTIONS,
    M_DELETE,
    M_CONNECT,
    M_GET,
    M_PUT,
    M_PATCH,
    M_TRACE,
    M_HEAD,
    M_POST,
    M_UNSUPPORTED
} Method;
typedef struct {
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;
    struct sockaddr_in address;
} connection_t;

typedef struct {
    connection_t *con;
    Method method;
    char ip[INET_ADDRSTRLEN];

    /* buffer holding request-line + headers + body (no copies) */
    char *buffer;
    char * to_free_buffer;
    int buffer_size;
    int total_read;

    /* version */
    char * version;

    /* URI */
    char * uri;
    char * query;
    char ** headers;
    
    /* body */
    char * body;
    char * host;

} Request;
typedef struct {
    const char *extension;
    const char *mime_type;
} MimeType;

static const MimeType mime_map[] = {
    { "aac", "audio/aac" },
    { "abw", "application/x-abiword" },
    { "arc", "application/x-freearc" },
    { "avi", "video/x-msvideo" },
    { "azw", "application/vnd.amazon.ebook" },
    { "bin", "application/octet-stream" },
    { "bmp", "image/bmp" },
    { "bz", "application/x-bzip" },
    { "bz2", "application/x-bzip2" },
    { "csh", "application/x-csh" },
    { "css", "text/css" },
    { "csv", "text/csv" },
    { "doc", "application/msword" },
    { "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    { "eot", "application/vnd.ms-fontobject" },
    { "epub", "application/epub+zip" },
    { "gz", "application/gzip" },
    { "gif", "image/gif" },
    { "htm", "text/html" },
    { "html", "text/html" },
    { "ico", "image/vnd.microsoft.icon" },
    { "ics", "text/calendar" },
    { "jar", "application/java-archive" },
    { "jpeg", "image/jpeg" },
    { "jpg", "image/jpeg" },
    { "js", "application/javascript" },
    { "json", "application/json" },
    { "jsonld", "application/ld+json" },
    { "mid", "audio/midi" },
    { "midi", "audio/midi" },
    { "mjs", "text/javascript" },
    { "mp3", "audio/mpeg" },
    { "mp4", "video/mp4" },
    { "mpeg", "video/mpeg" },
    { "mpkg", "application/vnd.apple.installer+xml" },
    { "odp", "application/vnd.oasis.opendocument.presentation" },
    { "ods", "application/vnd.oasis.opendocument.spreadsheet" },
    { "odt", "application/vnd.oasis.opendocument.text" },
    { "oga", "audio/ogg" },
    { "ogv", "video/ogg" },
    { "ogx", "application/ogg" },
    { "opus", "audio/opus" },
    { "otf", "font/otf" },
    { "png", "image/png" },
    { "pdf", "application/pdf" },
    { "php", "application/x-httpd-php" },
    { "ppt", "application/vnd.ms-powerpoint" },
    { "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
    { "rar", "application/vnd.rar" },
    { "rtf", "application/rtf" },
    { "sh", "application/x-sh" },
    { "svg", "image/svg+xml" },
    { "tar", "application/x-tar" },
    { "tif", "image/tiff" },
    { "tiff", "image/tiff" },
    { "ts", "video/mp2t" },
    { "ttf", "font/ttf" },
    { "txt", "text/plain" },
    { "vsd", "application/vnd.visio" },
    { "wav", "audio/wav" },
    { "weba", "audio/webm" },
    { "webm", "video/webm" },
    { "webp", "image/webp" },
    { "woff", "font/woff" },
    { "woff2", "font/woff2" },
    { "xhtml", "application/xhtml+xml" },
    { "xls", "application/vnd.ms-excel" },
    { "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
    { "xml", "application/xml" },
    { "xul", "application/vnd.mozilla.xul+xml" },
    { "zip", "application/zip" },
    { "3gp", "video/3gpp" },
    { "3g2", "video/3gpp2" },
    { "7z", "application/x-7z-compressed" },
    { "MOV", "video/quicktime" },
    { "mov", "video/quicktime"},
    { NULL, NULL }
};


int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    bind_addr = malloc(16*sizeof(char));
    domain = malloc(256*sizeof(char));
    strcpy(domain, DOMAIN);
    https_port = PORT;
    strcpy(bind_addr, BIND_ADDR);
    
    int arg = 0;
    
    for (int i = 1; i < argc && argv[i+1]; i++) { 
      printf("arg %d: %s %s\n", arg, argv[i], argv[i+1]);
      arg++;
      if(argc - i >= 1)
        switch(argv[i][1]){
         case 'b':
          strcpy(bind_addr, argv[i+1]);
          i++;
          break;
         case 'p':
           https_port = atoi(argv[i+1]);
           i++;
           break;
         case 'd':
           memset(domain, '\0', 256*sizeof(char));
           strcpy(domain, argv[i+1]);
           i++;
           break;
         default:
          printf("ERROR: unknown parameter: %s\n", argv[i]);
          exit(1);
        }
      else
        printf("Invalid Parameters\n");
    }
    
    
    // bind_signal_handlers();

/*
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    // Connect to MySQL
    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        //return EXIT_FAILURE;
    }

    if (mysql_real_connect(conn, "127.0.0.1", "admin", "Aa123456!@#",
                           "web", 3306, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
        //return EXIT_FAILURE;
    } */

/*
    if(0) printf("Insert Done.\nRows affected: %d.\n", 
        insert_row(conn, "web", "users", 
            LIST_2D("username","password","full_name"), 
            LIST_2D("test","test","INSERT GOOD"), 
            3
        ).affected_rows);

    SQL_RESULT result_seq = 
        select_rows(conn, 
            "web", "users", 
            "full_name, seq",
            LIST_2D("username", "password"), 
            LIST_2D("itamar", "Aa123456"), 
            2,
            "and"
        );

    // print_sql_result(&result_seq);
    free_sql_result(&result_seq);

   

    
    
    
    if(0) printf("Update Done.\nRows affected: %d.\n", 
        update_row(conn, "web", "users", 
            LIST_2D("username","password","full_name"), 
            LIST_2D("test","test","UPDATE GOOD"), 
            3,
            "seq", 
            "12"
        ).affected_rows);



    SQL_RESULT result;
    get_rows_sql_file(conn, "/home/itamar/Workspace/sql/users.sql", &result);
    print_sql_result(&result);
    free_sql_result(&result);

//*/
//    https_start();
    pthread_t thread;
    if (pthread_create(&thread, NULL, handle_http, NULL) != 0) {
      perror("Thread creation failed");
    } else {
      pthread_detach(thread);
      printf("Thread created\n");
    }
    //*/
   //*



    SSL_CTX *ctx = create_ssl_context();
    configure_ssl_context(ctx);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Socket creation failed");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(https_port);
    addr.sin_addr.s_addr = inet_addr(bind_addr); //INADDR_ANY;

    int reuse = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt failed");
        close(s);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }


    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(s);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(s, BACKLOG) < 0) {
        perror("Listen failed");
        close(s);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout,"\e[0;93mHTTPS Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", bind_addr, https_port);
    /*
       pthread_t thread2;
    if (pthread_create(&thread2, NULL, handle_http, NULL) != 0) {
      perror("Thread creation failed");
    } else {
      pthread_detach(thread2);
    }*/

    while (1) {
        connection_t *connection = malloc(sizeof(connection_t));
        if (!connection) {
            perror("Memory allocation failed");
            continue;
        }

        socklen_t client_len = sizeof(connection->address);
        connection->sock = accept(s, (struct sockaddr *)&connection->address, &client_len);
        connection->ctx = ctx;

        if (connection->sock < 0) {
            perror("Accept failed");
            free(connection);
            continue;
        }

        // Spawn a new thread for handling the client
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, connection) != 0) {
            perror("Thread creation failed");
            close(connection->sock);
            free(connection);
        } else {
            pthread_detach(thread); // Detach the thread to avoid memory leaks
        }
    }

    fprintf(stdout,"SERVER CRASHED\n");
    close(s);
    SSL_CTX_free(ctx);
    //while(1);
  //  mysql_close(conn);
    return 0;
}




void* handle_http(void *arg) {

int s = socket(AF_INET, SOCK_STREAM, 0);
if (s < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
}

int reuse = 1;
setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

struct sockaddr_in https;
memset(&https, 0, sizeof(https));
https.sin_family = AF_INET;
https.sin_port = htons(80);
https.sin_addr.s_addr = inet_addr(bind_addr);   // or htonl(INADDR_ANY)

if (bind(s, (struct sockaddr*)&https, sizeof(https)) < 0) {
    perror("bind failed");
    close(s);
    exit(EXIT_FAILURE);
}

if (listen(s, BACKLOG) < 0) {
    perror("listen failed");
    close(s);
    exit(EXIT_FAILURE);
}

while (1) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    int client_fd = accept(s, (struct sockaddr*)&addr, &addr_len);
    if (client_fd < 0) {
        perror("accept failed");
        continue;
    }

    //printf("REDIRECT\n");
char buffer[1024];
    recv(client_fd, buffer, sizeof(buffer), 0); 
    char *response = malloc(1024);
    sprintf(response,"HTTP/1.1 302 Found\r\nLocation: https://%s/\r\nConnection: close\r\n\r\n", domain);
    /*    "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "hi";*/
//const char *redirect = "HTTP/1.1 302 Found\r\n" "Location: https://www.google.com/\r\n" "Connection: close\r\n" "\r\n"; 
send(client_fd, response, strlen(response), 0);
   // send(client_fd, response, strlen(response), 0);
    close(client_fd);
}


    return NULL;
}


void print_signal_error(int sig_num) {
    const char *sig_name;

    switch (sig_num) {
        case SIGHUP:    sig_name = "SIGHUP (Hangup detected)"; break;
        case SIGINT:    sig_name = "SIGINT (Interrupt from keyboard)"; break;
        case SIGQUIT:   sig_name = "SIGQUIT (Quit from keyboard)"; break;
        case SIGILL:    sig_name = "SIGILL (Illegal instruction)"; break;
        case SIGTRAP:   sig_name = "SIGTRAP (Trace/breakpoint trap)"; break;
        case SIGABRT:   sig_name = "SIGABRT (Abort signal)"; break;
        case SIGBUS:    sig_name = "SIGBUS (Bus error)"; break;
        case SIGFPE:    sig_name = "SIGFPE (Floating point exception)"; break;
        case SIGKILL:   sig_name = "SIGKILL (Kill signal)"; break;
        case SIGUSR1:   sig_name = "SIGUSR1 (User-defined signal 1)"; break;
        case SIGSEGV:   sig_name = "SIGSEGV (Segmentation fault)"; break;
        case SIGUSR2:   sig_name = "SIGUSR2 (User-defined signal 2)"; break;
        case SIGPIPE:   sig_name = "SIGPIPE (Broken pipe)"; break;
        case SIGALRM:   sig_name = "SIGALRM (Timer signal)"; break;
        case SIGTERM:   sig_name = "SIGTERM (Termination signal)"; break;
        case SIGSTKFLT: sig_name = "SIGSTKFLT (Stack fault on coprocessor)"; break;
        case SIGCHLD:   sig_name = "SIGCHLD (Child stopped or terminated)"; break;
        case SIGCONT:   sig_name = "SIGCONT (Continue if stopped)"; break;
        case SIGSTOP:   sig_name = "SIGSTOP (Stop process)"; break;
        case SIGTSTP:   sig_name = "SIGTSTP (Stop typed at terminal)"; break;
        case SIGTTIN:   sig_name = "SIGTTIN (Terminal input for background process)"; break;
        case SIGTTOU:   sig_name = "SIGTTOU (Terminal output for background process)"; break;
        case SIGURG:    sig_name = "SIGURG (Urgent condition on socket)"; break;
        case SIGXCPU:   sig_name = "SIGXCPU (CPU time limit exceeded)"; break;
        case SIGXFSZ:   sig_name = "SIGXFSZ (File size limit exceeded)"; break;
        case SIGVTALRM: sig_name = "SIGVTALRM (Virtual alarm clock)"; break;
        case SIGPROF:   sig_name = "SIGPROF (Profiling timer expired)"; break;
        case SIGWINCH:  sig_name = "SIGWINCH (Window size change)"; break;
        case SIGIO:     sig_name = "SIGIO (I/O now possible)"; break;
        case SIGPWR:    sig_name = "SIGPWR (Power failure)"; break;
        case SIGSYS:    sig_name = "SIGSYS (Bad system call)"; break;
        default:        sig_name = "Unknown signal"; break;
    }

    fprintf(stdout, "Received signal %d: %s\n", sig_num, sig_name);
}
void handler(int sig) {
    print_signal_error(sig);
//    fprintf(stdout, "Caught signal %d\n", sig);
//    exit(EXIT_FAILURE);
}

void bind_signal_handlers(){
    signal(SIGHUP, handler);
//    signal(SIGINT, handler);
//    signal(SIGQUIT, handler);
    signal(SIGILL, handler);
    signal(SIGTRAP, handler);
    signal(SIGABRT, handler);
#ifdef SIGIOT
    signal(SIGIOT, handler);
#endif
    signal(SIGBUS, handler);
    signal(SIGFPE, handler);
//    signal(SIGKILL, handler); // Cannot be caught or ignored
    signal(SIGUSR1, handler);
    signal(SIGSEGV, handler);
    signal(SIGUSR2, handler);
    signal(SIGPIPE, handler);
    signal(SIGALRM, handler);
//    signal(SIGTERM, handler);
    signal(SIGCHLD, handler);
    signal(SIGCONT, handler);
  //  signal(SIGSTOP, handler); // Cannot be caught or ignored
    signal(SIGTSTP, handler);
    signal(SIGTTIN, handler);
    signal(SIGTTOU, handler);
    signal(SIGURG, handler);
    signal(SIGXCPU, handler);
    signal(SIGXFSZ, handler);
    signal(SIGVTALRM, handler);
    signal(SIGPROF, handler);
    signal(SIGWINCH, handler);
    signal(SIGPOLL, handler);
#ifdef SIGPWR
    signal(SIGPWR, handler);
#endif
#ifdef SIGSYS
    signal(SIGSYS, handler);
#endif
}

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    // After creating SSL_CTX
SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x08http/1.1", 9); // length-prefixed "http/1.1"

// Also disable NPN if enabled.
// Ensure you are NOT setting ALPN to include "h2".

    if (!ctx) {
        perror("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Enable session caching for better performance
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load certificate file");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load private key file");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
}
//*


ssize_t ssl_read_all(SSL *ssl, void *buf, size_t maxlen) {
    size_t total = 0;
    unsigned char *p = buf;
    if (maxlen > 8192)
        maxlen = 8192;  // enforce limit
    while (total < maxlen) {
        int n = SSL_read(ssl, p + total, maxlen - total);
        if (n > 0) {
            total += n;
            continue;
        }
        int err = SSL_get_error(ssl, n);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Non-fatal, retry
            continue;
        }
        // Fatal error or clean shutdown
        if (n == 0) {
            // Clean EOF
            break;
        }
        // Real error
        return -1;
    }

    return (ssize_t)total;
}
void close_socket(Request * req){
    close(req->con->sock);
    free(req->con);
}
void terminate_con(Request * req){
    SSL_shutdown(req->con->ssl);
    SSL_free(req->con->ssl);
    close(req->con->sock);
    free(req->con);;
    free(req->to_free_buffer);
    free(req);
}
char * method_to_str(Method method){
  switch(method){
    case M_OPTIONS: return "OPTIONS";
    case M_DELETE:  return "DELETE";
    case M_CONNECT: return "CONNECT";
    case M_GET:     return "GET";
    case M_PUT:     return "PUT";
    case M_PATCH:   return "PATCH";
    case M_TRACE:   return "TRACE";
    case M_HEAD:    return "HEAD";
    case M_POST:    return "POST";
    default:      return "UNSUPPORTED_METHOD";
  }
}


#define READ_MAX_RETRIES 200
#define READ_TIMEOUT_SECS 5
//*/
//* ssl_write_all: writes full buffer, returns bytes written or -1 on fatal error */
int ssl_write_all(SSL *ssl, const char *buffer, int buffer_size) {
    int total_written = 0;
    int retries = 0;

    while (total_written < buffer_size) {
        int ret = SSL_write(ssl,
                            buffer + total_written,
                            buffer_size - total_written);

        if (ret > 0) {
            total_written += ret;
            retries = 0;
            continue;
        }

        int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            int fd = SSL_get_fd(ssl);
            if (fd < 0) {
                if (++retries > READ_MAX_RETRIES)
                    return -1;
                usleep(1000);
                continue;
            }

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);

            struct timeval tv = { READ_TIMEOUT_SECS, 0 };

            int sel;
            if (err == SSL_ERROR_WANT_READ)
                sel = select(fd + 1, &fds, NULL, NULL, &tv);
            else
                sel = select(fd + 1, NULL, &fds, NULL, &tv);

            if (sel <= 0) {
                if (sel == 0)
                    fprintf(stderr, "ssl_write_all: timeout waiting for socket\n");
                else
                    perror("ssl_write_all: select");
                return -1;
            }

            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN)
            return total_written;

        if (err == SSL_ERROR_SYSCALL) {
            perror("SSL_write syscall error");
            return -1;
        }

        if (err == SSL_ERROR_SSL) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        fprintf(stderr, "ssl_write_all: unknown SSL error %d\n", err);
        return -1;
    }

    return total_written;
}

void send_response(Request * req, char * response, unsigned long length){
    if (ssl_write_all(req->con->ssl, response, length) <= 0) {
        perror("SSL write failed");
        ERR_print_errors_fp(stderr);
        
    }
}

//*/
/* Helper: trim leading/trailing whitespace in-place, return pointer to trimmed start */
static char *trim_inplace(char *s) {
    if (!s) return NULL;
    /* trim leading */
    while (*s && (*s == ' ' || *s == '\t')) s++;
    /* trim trailing */
    char *end = s + strlen(s) - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return s;
}
const char *get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "text/html";
    const char *ext = dot + 1;

    for (int i = 0; mime_map[i].extension != NULL; ++i) {
        if (strcasecmp(ext, mime_map[i].extension) == 0) {
            return mime_map[i].mime_type;
        }
    }
    return "application/octet-stream";
}

void *handle_client(void *arg) {
    connection_t *con = (connection_t *)arg;
    Request *req = calloc(1, sizeof(Request));
    if (!req) {
        perror("calloc Request");
        close(con->sock);
        free(con);
        return NULL;
    }
    req->con = con;

    req->buffer = malloc(BUFFER_SIZE);
    if (!req->buffer) {
        perror("malloc buffer");
        terminate_con(req);
        return NULL;
    }
    req->to_free_buffer = req->buffer;
    req->buffer_size = BUFFER_SIZE;

    inet_ntop(AF_INET, &con->address.sin_addr, req->ip, INET_ADDRSTRLEN);

    con->ssl = SSL_new(con->ctx);
    if (!con->ssl) {
        ERR_print_errors_fp(stderr);
        terminate_con(req);
        return NULL;
    }
    req->con->ssl = con->ssl;
    SSL_set_fd(con->ssl, con->sock);

    if (SSL_accept(con->ssl) <= 0) {
       // fprintf(stderr, "SSL_accept failed: ");
       // ERR_print_errors_fp(stderr);
        terminate_con(req);
        return NULL;
    }
    //fprintf(stderr, "SSL_accept OK for %s\n", req->ip);

    /* Read until CRLFCRLF (headers end) */
    int total = 0;
    int retries = 0;
    int headers_end = -1;
    while (total < req->buffer_size - 1) {
        int r = SSL_read(con->ssl, req->buffer + total, req->buffer_size - 1 - total);
        if (r > 0) {
            total += r;
            /* search for CRLFCRLF */
            for (int i = (total >= 4 ? total - r - 3 : 0); i <= total - 4; ++i) {
                if (req->buffer[i] == '\r' && req->buffer[i+1] == '\n' &&
                    req->buffer[i+2] == '\r' && req->buffer[i+3] == '\n') {
                    headers_end = i + 4;
                    break;
                }
            }
            if (headers_end >= 0) break;
            continue;
        }
        if (r == 0) {
            /* peer closed */
            fprintf(stderr, "peer closed during read\n");
            terminate_con(req);
            return NULL;
        }
        int err = SSL_get_error(con->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (++retries > READ_MAX_RETRIES) {
                fprintf(stderr, "too many read retries\n");
                terminate_con(req);
                return NULL;
            }
            int fd = SSL_get_fd(con->ssl);
            if (fd >= 0) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(fd, &rfds);
                struct timeval tv = { READ_TIMEOUT_SECS, 0 };
                int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
                if (sel <= 0) {
                    fprintf(stderr, "read select timeout or error\n");
                    terminate_con(req);
                    return NULL;
                }
                continue;
            } else {
                usleep(1000);
                continue;
            }
        } else {
            ERR_print_errors_fp(stderr);
            terminate_con(req);
            return NULL;
        }
    }

    if (headers_end < 0) {
        fprintf(stderr, "headers not complete or buffer overflow\n");
        terminate_con(req);
        return NULL;
    }

    /* Null-terminate the buffer for safe string ops */
    if (total >= req->buffer_size) total = req->buffer_size - 1;
    req->buffer[total] = '\0';
    req->total_read = total;

    /* Parse request-line (first line up to CRLF) */
    int reqline_end = -1;
    for (int i = 0; i < total - 1; ++i) {
        if (req->buffer[i] == '\r' && req->buffer[i+1] == '\n') {
            reqline_end = i;
            break;
        }
    }
    if (reqline_end < 0) {
        fprintf(stderr, "malformed request-line\n");
        terminate_con(req);
        return NULL;
    }

    /* Make request-line a C string */
    req->buffer[reqline_end] = '\0';

    /* tokens: METHOD SP URI SP VERSION */
    char *cursor = req->buffer;
    char *method_tok = cursor;
    char *sp = strchr(cursor, ' ');
    if (!sp) { terminate_con(req); return NULL; }
    *sp = '\0';
    cursor = sp + 1;

    char *uri_tok = cursor;
    sp = strchr(cursor, ' ');
    if (!sp) { terminate_con(req); return NULL; }
    *sp = '\0';
    cursor = sp + 1;

    char *version_tok = cursor;
    /* version_tok ends at reqline_end (we already null-terminated) */

    /* set method enum */
    if (strcasecmp(method_tok, "GET") == 0) req->method = M_GET;
    else if (strcasecmp(method_tok, "POST") == 0) req->method = M_POST;
    else if (strcasecmp(method_tok, "PUT") == 0) req->method = M_PUT;
    else if (strcasecmp(method_tok, "PATCH") == 0) req->method = M_PATCH;
    else if (strcasecmp(method_tok, "DELETE") == 0) req->method = M_DELETE;
    else if (strcasecmp(method_tok, "OPTIONS") == 0) req->method = M_OPTIONS;
    else if (strcasecmp(method_tok, "HEAD") == 0) req->method = M_HEAD;
    else if (strcasecmp(method_tok, "TRACE") == 0) req->method = M_TRACE;
    else if (strcasecmp(method_tok, "CONNECT") == 0) req->method = M_CONNECT;
    else req->method = M_UNSUPPORTED;

    req->version = version_tok;

    /* set uri and query pointers (in-place) */
    char *qmark = strchr(uri_tok, '?');
    if (qmark) {
        *qmark = '\0';
        req->uri = uri_tok;
        req->query = qmark + 1;
    } else {
        req->uri = uri_tok;
        req->query = NULL;
    }

    /* Parse headers: each header line between reqline_end+2 and headers_end-1 */
    int hdr_start = reqline_end + 2; /* skip CRLF */
    int hdr_end = headers_end;       /* points after CRLFCRLF */
    /* Count header lines first */
    int count = 0;
    for (int i = hdr_start; i < hdr_end - 1; ) {
        int le = i;
        while (le < hdr_end - 1 && !(req->buffer[le] == '\r' && req->buffer[le+1] == '\n')) le++;
        if (le >= hdr_end - 1) break;
        count++;
        i = le + 2;
    }

    if (count > 0) {
        req->headers = calloc(count + 1, sizeof(char *));
        if (!req->headers) {
            perror("calloc headers");
            terminate_con(req);
            return NULL;
        }
    } else {
        req->headers = NULL;
    }

    int idx = 0;
    for (int i = hdr_start; i < hdr_end - 1; ) {
        int le = i;
        while (le < hdr_end - 1 && !(req->buffer[le] == '\r' && req->buffer[le+1] == '\n')) le++;
        if (le >= hdr_end - 1) break;
        /* null-terminate this header line */
        req->buffer[le] = '\0';
        req->headers[idx++] = req->buffer + i; /* pointer to "Name: value" */
        /* check for Host header and set req->host to trimmed value */
        char *colon = strchr(req->buffer + i, ':');
        if (colon) {
            *colon = ':'; /* keep colon in the header string */
            char *name = req->buffer + i;
            /* compare case-insensitive */
            if (strncasecmp(name, "Host:", 5) == 0) {
                char *val = colon + 1;
                val = trim_inplace(val);
                req->host = val;
            }
        }
        i = le + 2;
    }
    if (req->headers) req->headers[idx] = NULL;

    /* Body (if any) starts at headers_end and continues to total (we may not have read full body) */
    if (total > headers_end) {
        req->body = req->buffer + headers_end;
    } else {
        req->body = NULL;
    }

    /* Log summary */
    // fprintf(stderr, "Request from %s: method=%s uri=%s version=%s host=%s\n",
    //         req->ip,
    //         method_tok,
    //         req->uri ? req->uri : "(null)",
    //         req->version ? req->version : "(null)",
    //         req->host ? req->host : "(none)");

    /* Build response */
    char *res = malloc(1024);
        
    FileInfo file;
    if(strcmp(req->uri, "/") == 0 || is_file_allowed(HOME, req->host, req->uri)){
            
        if(strcmp(req->uri, "/") == 0 )
            file = get_file(req->host, "/index.html");
        else
            file = get_file(req->host, req->uri);
        sprintf(res, "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s; charset=utf-8\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n", get_mime_type(req->uri), file.size);
            

/* Example: color the host in bold red, method green, uri cyan, version yellow, ip dim, timestamp magenta */
printf( "%s%s%s: %s%s%s uri=%s%s%s version=%s%s%s host=%s%s%s\n",
        ANSI_MAGENTA, req->ip, ANSI_RESET,
        ANSI_GREEN, method_to_str(req->method), ANSI_RESET,
        ANSI_CYAN, req->uri, ANSI_RESET,
        ANSI_YELLOW, req->version, ANSI_RESET,
        ANSI_BOLD_RED, req->host, ANSI_RESET
        );

            // req->ip,
            // method_tok,
            // req->uri ? req->uri : "(null)",
            // req->version ? req->version : "(null)",
            // req->host ? req->host : "(none)");
            //printf("%s\n", res);
        int wrote = ssl_write_all(con->ssl, res, (int)strlen(res));
        if (wrote < 0) {
            fprintf(stderr, "ssl_write_all failed\n");
            ERR_print_errors_fp(stderr);
            terminate_con(req);
            return NULL;
        }
        wrote = ssl_write_all(con->ssl, file.data, file.size);
        if (wrote < 0) {
            fprintf(stderr, "ssl_write_all failed\n");
            ERR_print_errors_fp(stderr);
            terminate_con(req);
            return NULL;
        }
        fprintf(stderr, "wrote %d bytes to %s\n", wrote, req->ip);
    }else{
        sprintf(res, "HTTP/1.1 404 Not Found\r\n"
            "Connection: close\r\n"
            "\r\n");
            int wrote = ssl_write_all(con->ssl, res, (int)strlen(res));
        if (wrote < 0) {
            fprintf(stderr, "ssl_write_all failed\n");
            ERR_print_errors_fp(stderr);
            terminate_con(req);
            return NULL;
        }
    }
    

    /* polite shutdown */
    if (SSL_shutdown(con->ssl) == 0) SSL_shutdown(con->ssl);

    /* cleanup: free headers array and buffer via terminate_con */
    /* terminate_con will free req->to_free_buffer and req itself */
    /* but it also frees req->con; ensure we don't double-free connection_t */
    /* We already used req->con pointer from arg; terminate_con expects req->con valid */
    terminate_con(req);
    return NULL;
}
