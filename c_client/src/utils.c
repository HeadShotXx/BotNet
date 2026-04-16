#include "utils.h"
#include <wincrypt.h>
#include <ctype.h>

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0;
    if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &out_len)) {
        return NULL;
    }
    char* out = (char*)malloc(out_len);
    if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &out_len)) {
        free(out);
        return NULL;
    }
    if (output_length) *output_length = out_len;
    return out;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0;
    if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {
        return NULL;
    }
    unsigned char* out = (unsigned char*)malloc(out_len);
    if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, out, &out_len, NULL, NULL)) {
        free(out);
        return NULL;
    }
    if (output_length) *output_length = out_len;
    return out;
}

char* str_replace(const char* orig, const char* rep, const char* with) {
    char* result;
    char* ins;
    char* tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep) return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = strlen(with);

    ins = (char*)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result) return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

void str_trim(char* s) {
    char* p = s;
    int l = strlen(p);
    while (l > 0 && isspace(p[l - 1])) p[--l] = 0;
    while (*p && isspace(*p)) ++p, --l;
    memmove(s, p, l + 1);
}

void sock_send(SOCKET sock, HANDLE mutex, const char* msg) {
    if (mutex) WaitForSingleObject(mutex, INFINITE);
    char* buf = (char*)malloc(strlen(msg) + 2);
    sprintf(buf, "%s\n", msg);
    send(sock, buf, (int)strlen(buf), 0);
    free(buf);
    if (mutex) ReleaseMutex(mutex);
}

static int is_leap(unsigned long long y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

void get_formatted_time(unsigned long long secs, char* out_buf) {
    unsigned long long minute = (secs % 3600) / 60;
    unsigned long long hour = (secs % 86400) / 3600;
    unsigned long long days = secs / 86400;
    unsigned long long year = 1970;
    while (1) {
        unsigned long long days_in_year = is_leap(year) ? 366 : 365;
        if (days < days_in_year) break;
        days -= days_in_year;
        year++;
    }
    unsigned long long months[] = {31, is_leap(year) ? 29u : 28u, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned long long month = 1;
    for (int i = 0; i < 12; i++) {
        if (days < months[i]) break;
        days -= months[i];
        month++;
    }
    sprintf(out_buf, "%02llu.%02llu.%llu %02llu:%02llu", days + 1, month, year, hour, minute);
}
