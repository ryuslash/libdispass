#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <limits.h>

#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAXLEN (SHA512_DIGEST_LENGTH * 2)

char *
base64encode(const void *data, int len)
{ /* Copied from http://stackoverflow.com/a/16511093/459915 */
    BIO *b64_bio, *mem_bio;
    BUF_MEM *mem_bio_mem_ptr;
    char *ret;

    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64_bio, data, len);
    BIO_flush(b64_bio);

    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);
    BIO_set_close(mem_bio, BIO_NOCLOSE);
    BIO_free_all(b64_bio);

    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';
    ret = calloc((*mem_bio_mem_ptr).length, sizeof(char));
    strncpy(ret, (*mem_bio_mem_ptr).data, (*mem_bio_mem_ptr).length);
    BUF_MEM_free(mem_bio_mem_ptr);

    return ret;
}

void
sha512_to_string(unsigned char *data, char *buff)
{
    int i;

    for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        char sbuff[3] = { '\0' };
        sprintf(sbuff, "%02x", data[i]);
        strcat(buff, sbuff);
    }
}

void
rmchar(char rm, char **s)
{
    int i, j = 0;
    char *new;
    size_t len;

    if (!strchr(*s, rm))
        return;

    len = strlen(*s);
    new = calloc(len + 1, sizeof(char));

    for (i = 0; i < len; i++) {
        char c;

        if ((c = (*s)[i]) != rm)
            new[j++] = c;
    }

    strncpy(*s, new, len);
    free(new);
}

char *
dispass1(char *label, char *password, int len, int seqno)
{
    int i;
    unsigned char *d;
    long tbufflen = strlen(label) + strlen(password) + 1;
    char *tbuff = calloc(tbufflen, sizeof(char));
    char buff[MAXLEN + 1] = { '\0' };
    char *b64;

    strcat(tbuff, label);
    strcat(tbuff, password);
    d = SHA512(tbuff, strlen(tbuff), 0);
    free(tbuff);
    sha512_to_string(d, buff);
    b64 = base64encode(buff, strlen(buff));
    b64[MIN(len, MAXLEN)] = '\0';
    rmchar('=', &b64);

    return b64;
}

char *
dispass2(char *label, char *password, int len, int seqno)
{
    int i;
    unsigned char *d;
    char ibuff[300];
    char *tbuff, *b64;
    char buff[MAXLEN + 1] = { '\0' };

    sprintf(ibuff, "%llu", seqno);
    tbuff = calloc(strlen(label) + strlen(ibuff) + strlen(password) + 1,
                   sizeof(char));
    strcat(tbuff, label);
    strcat(tbuff, ibuff);
    strcat(tbuff, password);
    d = SHA512(tbuff, strlen(tbuff), 0);
    free(tbuff);
    sha512_to_string(d, buff);
    b64 = base64encode(buff, strlen(buff));
    b64[MIN(len, MAXLEN)] = '\0';
    rmchar('=', &b64);

    return b64;
}

int main(int argc, char *argv[])
{
    char *test1, *test2, *test3, *test4;

    test1 = dispass1("test", "qqqqqqqq", 30, 0);
    test2 = dispass1("test2", "qqqqqqqq", 50, 0);
    test3 = dispass2("test", "qqqqqqqq", 30, 1);
    test4 = dispass2("test2", "qqqqqqqq", 50, 10);

    printf("%s\n", test1);
    printf("%s\n", test2);
    printf("%s\n", test3);
    printf("%s\n", test4);

    free(test1);
    free(test2);
    free(test3);
    free(test4);

    return 0;
}
