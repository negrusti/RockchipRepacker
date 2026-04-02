#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <strings.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#define RKFW_HEADER_SIZE 0x66u
#define RKAF_ENTRY_SIZE  0x70u
#define RKAF_MAX_ENTRIES 32u
#define DEFAULT_CHIP_ID  0x00000060u
#define DEFAULT_CODE     0x01050000u

#ifdef _WIN32
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

typedef enum ImageKind {
    IMAGE_UNKNOWN = 0,
    IMAGE_RKFW,
    IMAGE_RKAF,
} ImageKind;

typedef struct {
    char path[4096];
    FILE *fp;
    uint64_t size;
} InputFile;

typedef struct {
    char path[4096];
    FILE *fp;
} OutputFile;

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint64_t total_len;
    uint8_t block[64];
    size_t block_len;
} Md5Ctx;

typedef struct {
    char name[64];
    char file_name[64];
    char data_file[256];
    uint32_t nand_size;
    uint32_t pos;
    uint32_t nand_addr;
    uint32_t img_size;
    uint32_t orig_size;
    bool has_data_file;
} RkafEntry;

typedef struct {
    char model[35];
    char id[31];
    char manufacturer[57];
    uint32_t unknown1;
    uint32_t version;
    uint32_t image_size;
    uint32_t stored_rkcrc;
    uint32_t header_size;
    size_t entry_count;
    RkafEntry entries[RKAF_MAX_ENTRIES];
} RkafManifest;

typedef struct {
    uint16_t header_len;
    uint32_t version;
    uint32_t code;
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint32_t chip_id;
    uint32_t load_off;
    uint32_t load_len;
    uint32_t data_off;
    uint32_t data_len;
    uint32_t unknown1;
    uint32_t rkfw_type;
    uint32_t sysfs_type;
    uint32_t backup_end;
    uint32_t unknown2;
    bool append_md5;
    bool nested_is_rkaf;
    char loader_file[256];
    char update_file[256];
    char update_dir[256];
} RkfwManifest;

typedef struct {
    ImageKind kind;
    RkfwManifest rkfw;
    RkafManifest rkaf;
} Manifest;

static void warnx(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void write_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value & 0xffu);
    p[1] = (uint8_t)((value >> 8) & 0xffu);
}

static void write_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value & 0xffu);
    p[1] = (uint8_t)((value >> 8) & 0xffu);
    p[2] = (uint8_t)((value >> 16) & 0xffu);
    p[3] = (uint8_t)((value >> 24) & 0xffu);
}

static uint32_t align_up_u32(uint32_t value, uint32_t alignment)
{
    if (alignment == 0) {
        return value;
    }
    return (value + alignment - 1u) / alignment * alignment;
}

static uint32_t rkaf_entry_stored_size(const RkafEntry *entry)
{
    if (entry->img_size == 0) {
        return 0;
    }
    if (entry->img_size < entry->orig_size) {
        return entry->img_size << 11;
    }
    return entry->img_size;
}

static bool unwrap_signed_blob(const uint8_t *data,
                               size_t data_size,
                               const char **suffix_out,
                               const uint8_t **inner_out,
                               size_t *inner_size_out)
{
    uint32_t inner_size;

    if (data_size < 12) {
        return false;
    }
    if (memcmp(data, "PARM", 4) != 0 && memcmp(data, "KRNL", 4) != 0) {
        return false;
    }

    inner_size = read_le32(data + 4);
    if ((size_t)inner_size + 12u != data_size) {
        return false;
    }

    *suffix_out = memcmp(data, "PARM", 4) == 0 ? ".parm" : ".krnl";
    *inner_out = data + 8;
    *inner_size_out = inner_size;
    return true;
}

static bool rkaf_manifest_uses_block_units(const RkafManifest *manifest)
{
    size_t i;

    for (i = 0; i < manifest->entry_count; i++) {
        const RkafEntry *entry = &manifest->entries[i];
        if (strcmp(entry->file_name, "RESERVED") == 0 || strcmp(entry->file_name, "SELF") == 0) {
            continue;
        }
        if (entry->img_size != 0 && entry->img_size < entry->orig_size) {
            return true;
        }
    }
    return false;
}

static void copy_trimmed_string(char *dst, size_t dst_size, const uint8_t *src, size_t src_len)
{
    size_t len = 0;
    while (len < src_len && src[len] != '\0') {
        len++;
    }
    while (len > 0 && (src[len - 1] == ' ' || src[len - 1] == '\t')) {
        len--;
    }
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void copy_padded_string(uint8_t *dst, size_t dst_len, const char *src)
{
    size_t len = strlen(src);
    memset(dst, 0, dst_len);
    if (len > dst_len) {
        len = dst_len;
    }
    memcpy(dst, src, len);
}

static bool is_dir_sep(char c)
{
    return c == '/' || c == '\\';
}

static int compare_no_case(const char *lhs, const char *rhs)
{
#ifdef _WIN32
    return _stricmp(lhs, rhs);
#else
    return strcasecmp(lhs, rhs);
#endif
}

static int mkdir_one(const char *path)
{
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

static int seek_file(FILE *fp, uint64_t offset)
{
#ifdef _WIN32
    return _fseeki64(fp, (__int64)offset, SEEK_SET);
#else
    return fseeko(fp, (off_t)offset, SEEK_SET);
#endif
}

static void fill_local_time(struct tm *out_tm)
{
    time_t now = time(NULL);

    memset(out_tm, 0, sizeof(*out_tm));
#ifdef _WIN32
    localtime_s(out_tm, &now);
#else
    if (localtime_r(&now, out_tm) == NULL) {
        memset(out_tm, 0, sizeof(*out_tm));
    }
#endif
}

static void path_join(char *dst, size_t dst_size, const char *lhs, const char *rhs)
{
    size_t lhs_len = strlen(lhs);
    if (lhs_len == 0) {
        snprintf(dst, dst_size, "%s", rhs);
    } else if (is_dir_sep(lhs[lhs_len - 1])) {
        snprintf(dst, dst_size, "%s%s", lhs, rhs);
    } else {
        snprintf(dst, dst_size, "%s%c%s", lhs, PATH_SEP, rhs);
    }
}

static int mkdir_p(const char *path)
{
    char tmp[4096];
    size_t i;
    size_t start = 1;
    if (strlen(path) >= sizeof(tmp)) {
        return -1;
    }
    strcpy(tmp, path);
    for (i = 0; tmp[i] != '\0'; i++) {
        if (is_dir_sep(tmp[i])) {
            tmp[i] = PATH_SEP;
        }
    }
#ifdef _WIN32
    if (isalpha((unsigned char)tmp[0]) && tmp[1] == ':' && tmp[2] == PATH_SEP) {
        start = 3;
    }
#endif
    for (i = start; tmp[i] != '\0'; i++) {
        if (tmp[i] != PATH_SEP) {
            continue;
        }
        tmp[i] = '\0';
        if (tmp[0] != '\0' && mkdir_one(tmp) != 0 && errno != EEXIST) {
            return -1;
        }
        tmp[i] = PATH_SEP;
    }
    if (mkdir_one(tmp) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int ensure_parent_dir(const char *path)
{
    char tmp[4096];
    char *slash;
    if (strlen(path) >= sizeof(tmp)) {
        return -1;
    }
    strcpy(tmp, path);
    slash = strrchr(tmp, '/');
    {
        char *backslash = strrchr(tmp, '\\');
        if (backslash != NULL && (slash == NULL || backslash > slash)) {
            slash = backslash;
        }
    }
    if (!slash) {
        return 0;
    }
    *slash = '\0';
    if (tmp[0] == '\0') {
        return 0;
    }
    return mkdir_p(tmp);
}

static void sanitize_component(const char *src, char *dst, size_t dst_size)
{
    size_t i;
    size_t out = 0;
    for (i = 0; src[i] != '\0' && out + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '.' || c == '_' || c == '-') {
            dst[out++] = (char)c;
        } else {
            dst[out++] = '_';
        }
    }
    if (out == 0 && dst_size > 1) {
        dst[out++] = '_';
    }
    dst[out] = '\0';
}

static void sanitize_relative_path(const char *src, char *dst, size_t dst_size)
{
    char component[128];
    size_t out = 0;
    size_t i = 0;

    if (dst_size == 0) {
        return;
    }

    dst[0] = '\0';
    while (src[i] != '\0') {
        size_t comp_len = 0;
        size_t j;

        while (is_dir_sep(src[i])) {
            i++;
        }
        if (src[i] == '\0') {
            break;
        }

        while (src[i] != '\0' && !is_dir_sep(src[i]) && comp_len + 1 < sizeof(component)) {
            component[comp_len++] = src[i++];
        }
        component[comp_len] = '\0';

        if (strcmp(component, ".") == 0 || strcmp(component, "..") == 0 || component[0] == '\0') {
            while (src[i] != '\0' && !is_dir_sep(src[i])) {
                i++;
            }
            continue;
        }

        sanitize_component(component, component, sizeof(component));
        if (out != 0 && out + 1 < dst_size) {
            dst[out++] = PATH_SEP;
        }
        for (j = 0; component[j] != '\0' && out + 1 < dst_size; j++) {
            dst[out++] = component[j];
        }

        while (src[i] != '\0' && !is_dir_sep(src[i])) {
            i++;
        }
    }

    if (out == 0) {
        sanitize_component(src, dst, dst_size);
        return;
    }
    dst[out] = '\0';
}

static void choose_entry_output_name(const RkafManifest *manifest,
                                     size_t entry_index,
                                     const RkafEntry *entry,
                                     char *data_rel,
                                     size_t data_rel_size)
{
    char safe_path[256];
    char candidate[256];
    size_t suffix = 2;
    size_t j;

    sanitize_relative_path(entry->file_name[0] ? entry->file_name : entry->name, safe_path, sizeof(safe_path));
    snprintf(candidate, sizeof(candidate), "%s", safe_path);

    for (;;) {
        bool collision = false;

        for (j = 0; j < entry_index; j++) {
            if (manifest->entries[j].has_data_file && strcmp(manifest->entries[j].data_file, candidate) == 0) {
                collision = true;
                break;
            }
        }

        if (!collision) {
            snprintf(data_rel, data_rel_size, "%s", candidate);
            return;
        }

        snprintf(candidate, sizeof(candidate), "%s_%zu", safe_path, suffix);
        suffix++;
    }
}

static int open_input(InputFile *in, const char *path)
{
    struct stat st;
    memset(in, 0, sizeof(*in));
    snprintf(in->path, sizeof(in->path), "%s", path);
    in->fp = fopen(path, "rb");
    if (!in->fp) {
        return -1;
    }
    if (stat(path, &st) != 0) {
        fclose(in->fp);
        in->fp = NULL;
        return -1;
    }
    in->size = (uint64_t)st.st_size;
    return 0;
}

static void close_input(InputFile *in)
{
    if (in->fp) {
        fclose(in->fp);
        in->fp = NULL;
    }
}

static int open_output(OutputFile *out, const char *path)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", path);
    if (ensure_parent_dir(path) != 0) {
        return -1;
    }
    out->fp = fopen(path, "wb");
    return out->fp ? 0 : -1;
}

static int close_output(OutputFile *out)
{
    int rc = 0;
    if (out->fp) {
        rc = fclose(out->fp);
        out->fp = NULL;
    }
    return rc;
}

static void md5_init(Md5Ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->a = 0x67452301u;
    ctx->b = 0xefcdab89u;
    ctx->c = 0x98badcfeu;
    ctx->d = 0x10325476u;
}

static uint32_t md5_left_rotate(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32u - c));
}

static void md5_process_block(Md5Ctx *ctx, const uint8_t block[64])
{
    static const uint32_t s[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    static const uint32_t k[64] = {
        0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
        0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
        0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
        0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
        0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
        0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
        0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
        0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
        0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
        0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
        0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
        0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
        0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
        0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
        0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
        0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
    };
    uint32_t a = ctx->a, b = ctx->b, c = ctx->c, d = ctx->d;
    uint32_t m[16];
    size_t i;
    for (i = 0; i < 16; i++) {
        m[i] = read_le32(block + i * 4);
    }
    for (i = 0; i < 64; i++) {
        uint32_t f, g, temp;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = (uint32_t)i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5u * (uint32_t)i + 1u) % 16u;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3u * (uint32_t)i + 5u) % 16u;
        } else {
            f = c ^ (b | ~d);
            g = (7u * (uint32_t)i) % 16u;
        }
        temp = d;
        d = c;
        c = b;
        b = b + md5_left_rotate(a + f + k[i] + m[g], s[i]);
        a = temp;
    }
    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
}

static void md5_update(Md5Ctx *ctx, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    ctx->total_len += len;
    while (len > 0) {
        size_t take = sizeof(ctx->block) - ctx->block_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->block + ctx->block_len, bytes, take);
        ctx->block_len += take;
        bytes += take;
        len -= take;
        if (ctx->block_len == sizeof(ctx->block)) {
            md5_process_block(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void md5_final(Md5Ctx *ctx, uint8_t digest[16])
{
    uint64_t bits = ctx->total_len * 8u;
    uint8_t pad[64] = {0x80};
    uint8_t len_buf[8];
    size_t i;
    for (i = 0; i < 8; i++) {
        len_buf[i] = (uint8_t)((bits >> (8u * i)) & 0xffu);
    }
    md5_update(ctx, pad, (ctx->block_len < 56) ? (56 - ctx->block_len) : (120 - ctx->block_len));
    md5_update(ctx, len_buf, sizeof(len_buf));
    write_le32(digest + 0, ctx->a);
    write_le32(digest + 4, ctx->b);
    write_le32(digest + 8, ctx->c);
    write_le32(digest + 12, ctx->d);
}

static void digest_to_hex(const uint8_t digest[16], char hex[33])
{
    static const char table[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < 16; i++) {
        hex[i * 2] = table[(digest[i] >> 4) & 0xfu];
        hex[i * 2 + 1] = table[digest[i] & 0xfu];
    }
    hex[32] = '\0';
}

static uint32_t rkcrc32_update(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    const uint32_t poly = 0x04c10db7u;
    size_t i;
    for (i = 0; i < len; i++) {
        uint32_t cur = (uint32_t)bytes[i] << 24;
        int bit;
        crc ^= cur;
        for (bit = 0; bit < 8; bit++) {
            if (crc & 0x80000000u) {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

static int slurp_file(const char *path, uint8_t **data_out, size_t *size_out)
{
    InputFile in;
    uint8_t *buf;

    if (open_input(&in, path) != 0) {
        return -1;
    }
    if (in.size > SIZE_MAX) {
        close_input(&in);
        errno = EFBIG;
        return -1;
    }

    buf = (uint8_t *)malloc((size_t)in.size);
    if (!buf) {
        close_input(&in);
        return -1;
    }
    if (in.size > 0 && fread(buf, 1, (size_t)in.size, in.fp) != (size_t)in.size) {
        free(buf);
        close_input(&in);
        return -1;
    }

    close_input(&in);
    *data_out = buf;
    *size_out = (size_t)in.size;
    return 0;
}

static int write_file(const char *path, const void *data, size_t size)
{
    OutputFile out;
    if (open_output(&out, path) != 0) {
        return -1;
    }
    if (size > 0 && fwrite(data, 1, size, out.fp) != size) {
        close_output(&out);
        return -1;
    }
    close_output(&out);
    return 0;
}

static ImageKind detect_image_kind(const uint8_t *buf, size_t size)
{
    if (size >= 4 && memcmp(buf, "RKFW", 4) == 0) {
        return IMAGE_RKFW;
    }
    if (size >= 4 && memcmp(buf, "RKAF", 4) == 0) {
        return IMAGE_RKAF;
    }
    return IMAGE_UNKNOWN;
}

static char *trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return s;
}

static int parse_u32_value(const char *value, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(value, &end, 0);
    if (errno != 0 || end == value || *trim(end) != '\0' || v > 0xfffffffful) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int parse_bool_value(const char *value, bool *out)
{
    if (strcmp(value, "1") == 0 || compare_no_case(value, "true") == 0 || compare_no_case(value, "yes") == 0) {
        *out = true;
        return 0;
    }
    if (strcmp(value, "0") == 0 || compare_no_case(value, "false") == 0 || compare_no_case(value, "no") == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

static int write_rkaf_manifest(const char *dir, const RkafManifest *manifest)
{
    char path[4096];
    OutputFile out;
    size_t i;

    path_join(path, sizeof(path), dir, "manifest.ini");
    if (open_output(&out, path) != 0) {
        return -1;
    }

    fprintf(out.fp, "[image]\n");
    fprintf(out.fp, "format=RKAF\n");
    fprintf(out.fp, "model=%s\n", manifest->model);
    fprintf(out.fp, "id=%s\n", manifest->id);
    fprintf(out.fp, "manufacturer=%s\n", manifest->manufacturer);
    fprintf(out.fp, "version=0x%08" PRIx32 "\n", manifest->version);
    fprintf(out.fp, "unknown1=0x%08" PRIx32 "\n", manifest->unknown1);
    fprintf(out.fp, "header_size=0x%08" PRIx32 "\n", manifest->header_size);
    fprintf(out.fp, "entry_count=%zu\n", manifest->entry_count);
    fprintf(out.fp, "image_size=0x%08" PRIx32 "\n", manifest->image_size);
    fprintf(out.fp, "stored_rkcrc=0x%08" PRIx32 "\n", manifest->stored_rkcrc);
    fprintf(out.fp, "\n");

    for (i = 0; i < manifest->entry_count; i++) {
        const RkafEntry *entry = &manifest->entries[i];
        fprintf(out.fp, "[entry%zu]\n", i);
        fprintf(out.fp, "name=%s\n", entry->name);
        fprintf(out.fp, "file_name=%s\n", entry->file_name);
        fprintf(out.fp, "data_file=%s\n", entry->has_data_file ? entry->data_file : "");
        fprintf(out.fp, "nand_size=0x%08" PRIx32 "\n", entry->nand_size);
        fprintf(out.fp, "pos=0x%08" PRIx32 "\n", entry->pos);
        fprintf(out.fp, "nand_addr=0x%08" PRIx32 "\n", entry->nand_addr);
        fprintf(out.fp, "img_size=0x%08" PRIx32 "\n", entry->img_size);
        fprintf(out.fp, "orig_size=0x%08" PRIx32 "\n", entry->orig_size);
        fprintf(out.fp, "\n");
    }

    close_output(&out);
    return 0;
}

static int write_rkfw_manifest(const char *dir, const RkfwManifest *manifest)
{
    char path[4096];
    OutputFile out;

    path_join(path, sizeof(path), dir, "manifest.ini");
    if (open_output(&out, path) != 0) {
        return -1;
    }

    fprintf(out.fp, "[image]\n");
    fprintf(out.fp, "format=RKFW\n");
    fprintf(out.fp, "header_len=0x%04" PRIx16 "\n", manifest->header_len);
    fprintf(out.fp, "version=0x%08" PRIx32 "\n", manifest->version);
    fprintf(out.fp, "code=0x%08" PRIx32 "\n", manifest->code);
    fprintf(out.fp, "year=%u\n", (unsigned)manifest->year);
    fprintf(out.fp, "month=%u\n", (unsigned)manifest->month);
    fprintf(out.fp, "day=%u\n", (unsigned)manifest->day);
    fprintf(out.fp, "hour=%u\n", (unsigned)manifest->hour);
    fprintf(out.fp, "minute=%u\n", (unsigned)manifest->minute);
    fprintf(out.fp, "second=%u\n", (unsigned)manifest->second);
    fprintf(out.fp, "chip_id=0x%08" PRIx32 "\n", manifest->chip_id);
    fprintf(out.fp, "load_off=0x%08" PRIx32 "\n", manifest->load_off);
    fprintf(out.fp, "load_len=0x%08" PRIx32 "\n", manifest->load_len);
    fprintf(out.fp, "data_off=0x%08" PRIx32 "\n", manifest->data_off);
    fprintf(out.fp, "data_len=0x%08" PRIx32 "\n", manifest->data_len);
    fprintf(out.fp, "unknown1=0x%08" PRIx32 "\n", manifest->unknown1);
    fprintf(out.fp, "rkfw_type=0x%08" PRIx32 "\n", manifest->rkfw_type);
    fprintf(out.fp, "sysfs_type=0x%08" PRIx32 "\n", manifest->sysfs_type);
    fprintf(out.fp, "backup_end=0x%08" PRIx32 "\n", manifest->backup_end);
    fprintf(out.fp, "unknown2=0x%08" PRIx32 "\n", manifest->unknown2);
    fprintf(out.fp, "append_md5=%d\n", manifest->append_md5 ? 1 : 0);
    fprintf(out.fp, "nested_is_rkaf=%d\n", manifest->nested_is_rkaf ? 1 : 0);
    fprintf(out.fp, "loader_file=%s\n", manifest->loader_file);
    fprintf(out.fp, "update_file=%s\n", manifest->update_file);
    fprintf(out.fp, "update_dir=%s\n", manifest->update_dir);

    close_output(&out);
    return 0;
}

static int load_manifest(const char *dir, Manifest *manifest)
{
    char path[4096];
    InputFile in;
    char line[2048];
    char section[64] = "";
    int current_entry = -1;

    memset(manifest, 0, sizeof(*manifest));
    path_join(path, sizeof(path), dir, "manifest.ini");
    if (open_input(&in, path) != 0) {
        return -1;
    }

    while (fgets(line, sizeof(line), in.fp)) {
        char *raw = trim(line);
        char *eq;

        if (*raw == '\0' || *raw == '#' || *raw == ';') {
            continue;
        }
        if (*raw == '[') {
            char *end = strchr(raw, ']');
            if (!end) {
                close_input(&in);
                errno = EINVAL;
                return -1;
            }
            *end = '\0';
            snprintf(section, sizeof(section), "%s", raw + 1);
            current_entry = -1;
            if (strncmp(section, "entry", 5) == 0) {
                current_entry = atoi(section + 5);
                if (current_entry < 0 || current_entry >= (int)RKAF_MAX_ENTRIES) {
                    close_input(&in);
                    errno = EINVAL;
                    return -1;
                }
                if ((size_t)(current_entry + 1) > manifest->rkaf.entry_count) {
                    manifest->rkaf.entry_count = (size_t)(current_entry + 1);
                }
            }
            continue;
        }

        eq = strchr(raw, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        {
            char *key = trim(raw);
            char *value = trim(eq + 1);
            uint32_t u32 = 0;
            bool b = false;

            if (strcmp(section, "image") == 0) {
                if (strcmp(key, "format") == 0) {
                    if (strcmp(value, "RKFW") == 0) manifest->kind = IMAGE_RKFW;
                    else if (strcmp(value, "RKAF") == 0) manifest->kind = IMAGE_RKAF;
                    else {
                        close_input(&in);
                        errno = EINVAL;
                        return -1;
                    }
                } else if (manifest->kind == IMAGE_RKFW) {
                    RkfwManifest *m = &manifest->rkfw;
                    if (strcmp(key, "header_len") == 0 && parse_u32_value(value, &u32) == 0) m->header_len = (uint16_t)u32;
                    else if (strcmp(key, "version") == 0 && parse_u32_value(value, &u32) == 0) m->version = u32;
                    else if (strcmp(key, "code") == 0 && parse_u32_value(value, &u32) == 0) m->code = u32;
                    else if (strcmp(key, "year") == 0 && parse_u32_value(value, &u32) == 0) m->year = (uint16_t)u32;
                    else if (strcmp(key, "month") == 0 && parse_u32_value(value, &u32) == 0) m->month = (uint8_t)u32;
                    else if (strcmp(key, "day") == 0 && parse_u32_value(value, &u32) == 0) m->day = (uint8_t)u32;
                    else if (strcmp(key, "hour") == 0 && parse_u32_value(value, &u32) == 0) m->hour = (uint8_t)u32;
                    else if (strcmp(key, "minute") == 0 && parse_u32_value(value, &u32) == 0) m->minute = (uint8_t)u32;
                    else if (strcmp(key, "second") == 0 && parse_u32_value(value, &u32) == 0) m->second = (uint8_t)u32;
                    else if (strcmp(key, "chip_id") == 0 && parse_u32_value(value, &u32) == 0) m->chip_id = u32;
                    else if (strcmp(key, "load_off") == 0 && parse_u32_value(value, &u32) == 0) m->load_off = u32;
                    else if (strcmp(key, "load_len") == 0 && parse_u32_value(value, &u32) == 0) m->load_len = u32;
                    else if (strcmp(key, "data_off") == 0 && parse_u32_value(value, &u32) == 0) m->data_off = u32;
                    else if (strcmp(key, "data_len") == 0 && parse_u32_value(value, &u32) == 0) m->data_len = u32;
                    else if (strcmp(key, "unknown1") == 0 && parse_u32_value(value, &u32) == 0) m->unknown1 = u32;
                    else if (strcmp(key, "rkfw_type") == 0 && parse_u32_value(value, &u32) == 0) m->rkfw_type = u32;
                    else if (strcmp(key, "sysfs_type") == 0 && parse_u32_value(value, &u32) == 0) m->sysfs_type = u32;
                    else if (strcmp(key, "backup_end") == 0 && parse_u32_value(value, &u32) == 0) m->backup_end = u32;
                    else if (strcmp(key, "unknown2") == 0 && parse_u32_value(value, &u32) == 0) m->unknown2 = u32;
                    else if (strcmp(key, "append_md5") == 0 && parse_bool_value(value, &b) == 0) m->append_md5 = b;
                    else if (strcmp(key, "nested_is_rkaf") == 0 && parse_bool_value(value, &b) == 0) m->nested_is_rkaf = b;
                    else if (strcmp(key, "loader_file") == 0) snprintf(m->loader_file, sizeof(m->loader_file), "%s", value);
                    else if (strcmp(key, "update_file") == 0) snprintf(m->update_file, sizeof(m->update_file), "%s", value);
                    else if (strcmp(key, "update_dir") == 0) snprintf(m->update_dir, sizeof(m->update_dir), "%s", value);
                } else if (manifest->kind == IMAGE_RKAF) {
                    RkafManifest *m = &manifest->rkaf;
                    if (strcmp(key, "model") == 0) snprintf(m->model, sizeof(m->model), "%s", value);
                    else if (strcmp(key, "id") == 0) snprintf(m->id, sizeof(m->id), "%s", value);
                    else if (strcmp(key, "manufacturer") == 0) snprintf(m->manufacturer, sizeof(m->manufacturer), "%s", value);
                    else if (strcmp(key, "version") == 0 && parse_u32_value(value, &u32) == 0) m->version = u32;
                    else if (strcmp(key, "unknown1") == 0 && parse_u32_value(value, &u32) == 0) m->unknown1 = u32;
                    else if (strcmp(key, "header_size") == 0 && parse_u32_value(value, &u32) == 0) m->header_size = u32;
                    else if (strcmp(key, "entry_count") == 0 && parse_u32_value(value, &u32) == 0) m->entry_count = u32;
                    else if (strcmp(key, "image_size") == 0 && parse_u32_value(value, &u32) == 0) m->image_size = u32;
                    else if (strcmp(key, "stored_rkcrc") == 0 && parse_u32_value(value, &u32) == 0) m->stored_rkcrc = u32;
                }
            } else if (current_entry >= 0 && manifest->kind == IMAGE_RKAF) {
                RkafEntry *entry = &manifest->rkaf.entries[current_entry];
                if (strcmp(key, "name") == 0) snprintf(entry->name, sizeof(entry->name), "%s", value);
                else if (strcmp(key, "file_name") == 0) snprintf(entry->file_name, sizeof(entry->file_name), "%s", value);
                else if (strcmp(key, "data_file") == 0) {
                    snprintf(entry->data_file, sizeof(entry->data_file), "%s", value);
                    entry->has_data_file = value[0] != '\0';
                } else if (strcmp(key, "nand_size") == 0 && parse_u32_value(value, &u32) == 0) entry->nand_size = u32;
                else if (strcmp(key, "pos") == 0 && parse_u32_value(value, &u32) == 0) entry->pos = u32;
                else if (strcmp(key, "nand_addr") == 0 && parse_u32_value(value, &u32) == 0) entry->nand_addr = u32;
                else if (strcmp(key, "img_size") == 0 && parse_u32_value(value, &u32) == 0) entry->img_size = u32;
                else if (strcmp(key, "orig_size") == 0 && parse_u32_value(value, &u32) == 0) entry->orig_size = u32;
            }
        }
    }

    close_input(&in);
    return manifest->kind == IMAGE_UNKNOWN ? -1 : 0;
}

static void yaml_indent(FILE *fp, int indent)
{
    int i;
    for (i = 0; i < indent; i++) {
        fputc(' ', fp);
    }
}

static void yaml_print_string(FILE *fp, const char *value)
{
    size_t i;

    fputc('"', fp);
    for (i = 0; value[i] != '\0'; i++) {
        unsigned char c = (unsigned char)value[i];
        switch (c) {
        case '\\':
        case '"':
            fputc('\\', fp);
            fputc((int)c, fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (c < 0x20) {
                fprintf(fp, "\\x%02x", c);
            } else {
                fputc((int)c, fp);
            }
            break;
        }
    }
    fputc('"', fp);
}

static void yaml_kv_string(FILE *fp, int indent, const char *key, const char *value)
{
    yaml_indent(fp, indent);
    fprintf(fp, "%s: ", key);
    yaml_print_string(fp, value);
    fputc('\n', fp);
}

static void yaml_kv_hex32(FILE *fp, int indent, const char *key, uint32_t value)
{
    yaml_indent(fp, indent);
    fprintf(fp, "%s: 0x%08" PRIx32 "\n", key, value);
}

static void yaml_kv_u64(FILE *fp, int indent, const char *key, uint64_t value)
{
    yaml_indent(fp, indent);
    fprintf(fp, "%s: %" PRIu64 "\n", key, value);
}

static void yaml_kv_u32(FILE *fp, int indent, const char *key, uint32_t value)
{
    yaml_indent(fp, indent);
    fprintf(fp, "%s: %" PRIu32 "\n", key, value);
}

static void yaml_kv_bool(FILE *fp, int indent, const char *key, bool value)
{
    yaml_indent(fp, indent);
    fprintf(fp, "%s: %s\n", key, value ? "true" : "false");
}

static void yaml_key(FILE *fp, int indent, const char *key)
{
    yaml_indent(fp, indent);
    yaml_print_string(fp, key);
    fputs(":\n", fp);
}

static int emit_rkaf_yaml_blob(FILE *fp, const uint8_t *blob, size_t blob_size, int indent)
{
    uint32_t header_size;
    uint32_t entry_count;
    uint32_t image_size;
    uint32_t stored_crc;
    char tmp[128];
    size_t i;

    if (blob_size < 0x800 || memcmp(blob, "RKAF", 4) != 0) {
        errno = EINVAL;
        return -1;
    }

    header_size = read_le32(blob + 0x8c + 0x60);
    if (header_size != 0x1000u) {
        header_size = 0x800u;
    }
    image_size = read_le32(blob + 4);
    entry_count = read_le32(blob + 136);
    if (entry_count > RKAF_MAX_ENTRIES) {
        entry_count = RKAF_MAX_ENTRIES;
    }
    stored_crc = image_size + 4u <= blob_size ? read_le32(blob + image_size) : 0;

    yaml_indent(fp, indent);
    fputs("format: RKAF\n", fp);
    yaml_indent(fp, indent);
    fputs("header:\n", fp);
    copy_trimmed_string(tmp, sizeof(tmp), blob + 8, 34);
    yaml_kv_string(fp, indent + 2, "model", tmp);
    copy_trimmed_string(tmp, sizeof(tmp), blob + 42, 30);
    yaml_kv_string(fp, indent + 2, "id", tmp);
    copy_trimmed_string(tmp, sizeof(tmp), blob + 72, 56);
    yaml_kv_string(fp, indent + 2, "manufacturer", tmp);
    yaml_kv_hex32(fp, indent + 2, "version", read_le32(blob + 132));
    yaml_kv_hex32(fp, indent + 2, "unknown1", read_le32(blob + 128));
    yaml_kv_hex32(fp, indent + 2, "header_size", header_size);
    yaml_kv_u32(fp, indent + 2, "entry_count", entry_count);
    yaml_kv_hex32(fp, indent + 2, "image_size", image_size);
    yaml_kv_hex32(fp, indent + 2, "stored_rkcrc", stored_crc);

    yaml_indent(fp, indent);
    fputs("entries:\n", fp);
    for (i = 0; i < entry_count; i++) {
        const uint8_t *entry_buf = blob + 140u + i * RKAF_ENTRY_SIZE;
        char name[64];
        char file_name[128];
        uint32_t pos = read_le32(entry_buf + 96);
        uint32_t img_size = read_le32(entry_buf + 104);
        uint32_t orig_size = read_le32(entry_buf + 108);
        uint32_t nand_size = read_le32(entry_buf + 92);
        uint32_t nand_addr = read_le32(entry_buf + 100);
        const char *signed_suffix = NULL;
        const uint8_t *inner_data = NULL;
        size_t inner_size = 0;
        uint32_t stored_size = img_size < orig_size ? (img_size << 11) : img_size;

        copy_trimmed_string(name, sizeof(name), entry_buf + 0, 32);
        copy_trimmed_string(file_name, sizeof(file_name), entry_buf + 32, 60);

        yaml_key(fp, indent + 2, name);
        yaml_kv_string(fp, indent + 4, "file_name", file_name);
        yaml_kv_hex32(fp, indent + 4, "pos", pos);
        yaml_kv_hex32(fp, indent + 4, "img_size", img_size);
        yaml_kv_string(fp, indent + 4, "img_size_unit",
                       img_size < orig_size ? "0x800-byte blocks" : "bytes");
        yaml_kv_hex32(fp, indent + 4, "stored_size_bytes", stored_size);
        yaml_kv_hex32(fp, indent + 4, "orig_size", orig_size);
        yaml_kv_hex32(fp, indent + 4, "nand_size", nand_size);
        yaml_kv_hex32(fp, indent + 4, "nand_addr", nand_addr);

        if (stored_size > 0 && pos + stored_size <= blob_size - 4u &&
            unwrap_signed_blob(blob + pos, orig_size, &signed_suffix, &inner_data, &inner_size)) {
            yaml_kv_string(fp, indent + 4, "second_layer", signed_suffix[1] == 'p' ? "PARM" : "KRNL");
            yaml_kv_u64(fp, indent + 4, "decoded_size", (uint64_t)inner_size);
        }
    }

    return 0;
}

static int emit_rkfw_yaml_file(FILE *fp, const char *input_path)
{
    InputFile in;
    uint8_t header[RKFW_HEADER_SIZE];
    uint16_t header_len;
    uint32_t version;
    uint32_t code;
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint32_t chip_id;
    uint32_t load_off;
    uint32_t load_len;
    uint32_t data_off;
    uint32_t data_len;
    uint32_t unknown1;
    uint32_t rkfw_type;
    uint32_t sysfs_type;
    uint32_t backup_end;
    uint32_t unknown2;
    bool append_md5;
    uint8_t *update_blob = NULL;
    int rc = -1;

    if (open_input(&in, input_path) != 0) {
        return -1;
    }
    if (in.size < RKFW_HEADER_SIZE || fread(header, 1, sizeof(header), in.fp) != sizeof(header)) {
        close_input(&in);
        errno = EINVAL;
        return -1;
    }
    if (memcmp(header, "RKFW", 4) != 0) {
        close_input(&in);
        errno = EINVAL;
        return -1;
    }

    header_len = read_le16(header + 4);
    version = read_le32(header + 6);
    code = read_le32(header + 10);
    year = read_le16(header + 14);
    month = header[16];
    day = header[17];
    hour = header[18];
    minute = header[19];
    second = header[20];
    chip_id = read_le32(header + 21);
    load_off = read_le32(header + 25);
    load_len = read_le32(header + 29);
    data_off = read_le32(header + 33);
    data_len = read_le32(header + 37);
    unknown1 = read_le32(header + 41);
    rkfw_type = read_le32(header + 45);
    sysfs_type = read_le32(header + 49);
    backup_end = read_le32(header + 53);
    unknown2 = read_le32(header + 98);
    append_md5 = ((uint64_t)data_off + (uint64_t)data_len + 32u == in.size);

    yaml_kv_string(fp, 0, "format", "RKFW");
    yaml_kv_string(fp, 0, "path", input_path);
    yaml_indent(fp, 0);
    fputs("header:\n", fp);
    yaml_kv_hex32(fp, 2, "header_len", header_len);
    yaml_kv_hex32(fp, 2, "version", version);
    yaml_kv_hex32(fp, 2, "code", code);
    yaml_indent(fp, 2);
    fprintf(fp, "datetime: \"%04u-%02u-%02u %02u:%02u:%02u\"\n",
            (unsigned)year, (unsigned)month, (unsigned)day,
            (unsigned)hour, (unsigned)minute, (unsigned)second);
    yaml_kv_hex32(fp, 2, "chip_id", chip_id);
    yaml_kv_hex32(fp, 2, "load_off", load_off);
    yaml_kv_hex32(fp, 2, "load_len", load_len);
    yaml_kv_hex32(fp, 2, "data_off", data_off);
    yaml_kv_hex32(fp, 2, "data_len", data_len);
    yaml_kv_hex32(fp, 2, "unknown1", unknown1);
    yaml_kv_hex32(fp, 2, "rkfw_type", rkfw_type);
    yaml_kv_hex32(fp, 2, "sysfs_type", sysfs_type);
    yaml_kv_hex32(fp, 2, "backup_end", backup_end);
    yaml_kv_hex32(fp, 2, "unknown2", unknown2);
    yaml_kv_bool(fp, 2, "append_md5", append_md5);

    yaml_indent(fp, 0);
    fputs("children:\n", fp);
    yaml_key(fp, 2, "loader.bin");
    yaml_kv_string(fp, 4, "kind", "loader");
    yaml_kv_hex32(fp, 4, "offset", load_off);
    yaml_kv_u64(fp, 4, "size", load_len);

    yaml_key(fp, 2, "update.img");
    yaml_kv_string(fp, 4, "kind", "update");
    yaml_kv_hex32(fp, 4, "offset", data_off);
    yaml_kv_u64(fp, 4, "size", data_len);

    if (seek_file(in.fp, data_off) == 0) {
        update_blob = (uint8_t *)malloc(data_len);
        if (update_blob != NULL && fread(update_blob, 1, data_len, in.fp) == data_len &&
            detect_image_kind(update_blob, data_len) == IMAGE_RKAF) {
            if (emit_rkaf_yaml_blob(fp, update_blob, data_len, 4) != 0) {
                goto cleanup;
            }
        }
    }

    rc = 0;

cleanup:
    free(update_blob);
    close_input(&in);
    return rc;
}

static int emit_rkaf_yaml_file(FILE *fp, const char *input_path)
{
    uint8_t *blob = NULL;
    size_t blob_size = 0;
    int rc;

    if (slurp_file(input_path, &blob, &blob_size) != 0) {
        return -1;
    }
    yaml_kv_string(fp, 0, "path", input_path);
    rc = emit_rkaf_yaml_blob(fp, blob, blob_size, 0);
    free(blob);
    return rc;
}

static int list_image_yaml(const char *input_path)
{
    InputFile in;
    uint8_t magic[4];
    int rc;

    if (open_input(&in, input_path) != 0) {
        return -1;
    }
    if (fread(magic, 1, sizeof(magic), in.fp) != sizeof(magic)) {
        close_input(&in);
        errno = EINVAL;
        return -1;
    }
    close_input(&in);

    if (memcmp(magic, "RKFW", 4) == 0) {
        rc = emit_rkfw_yaml_file(stdout, input_path);
    } else if (memcmp(magic, "RKAF", 4) == 0) {
        rc = emit_rkaf_yaml_file(stdout, input_path);
    } else {
        errno = EINVAL;
        rc = -1;
    }

    return rc;
}

static int unpack_rkaf_file(const char *input_path, const char *out_dir, RkafManifest *manifest)
{
    uint8_t *blob = NULL;
    size_t blob_size = 0;
    uint32_t header_size;
    uint32_t crc = 0;
    size_t i;

    memset(manifest, 0, sizeof(*manifest));
    if (slurp_file(input_path, &blob, &blob_size) != 0) {
        return -1;
    }
    if (blob_size < 0x800 || memcmp(blob, "RKAF", 4) != 0) {
        free(blob);
        errno = EINVAL;
        return -1;
    }

    header_size = read_le32(blob + 0x8c + 0x60);
    if (header_size != 0x1000u) {
        header_size = 0x800u;
    }
    if (blob_size < header_size + 4u) {
        free(blob);
        errno = EINVAL;
        return -1;
    }

    manifest->image_size = read_le32(blob + 4);
    manifest->header_size = header_size;
    manifest->unknown1 = read_le32(blob + 128);
    manifest->version = read_le32(blob + 132);
    manifest->entry_count = read_le32(blob + 136);
    if (manifest->entry_count > RKAF_MAX_ENTRIES) {
        manifest->entry_count = RKAF_MAX_ENTRIES;
    }
    copy_trimmed_string(manifest->model, sizeof(manifest->model), blob + 8, 34);
    copy_trimmed_string(manifest->id, sizeof(manifest->id), blob + 42, 30);
    copy_trimmed_string(manifest->manufacturer, sizeof(manifest->manufacturer), blob + 72, 56);

    for (i = 0; i < manifest->entry_count; i++) {
        const uint8_t *entry_buf = blob + 140 + i * RKAF_ENTRY_SIZE;
        RkafEntry *entry = &manifest->entries[i];
        char data_rel[256];
        char data_path[4096];
        uint32_t stored_size;
        const char *signed_suffix = NULL;
        const uint8_t *inner_data = NULL;
        size_t inner_size = 0;

        copy_trimmed_string(entry->name, sizeof(entry->name), entry_buf + 0, 32);
        copy_trimmed_string(entry->file_name, sizeof(entry->file_name), entry_buf + 32, 60);
        entry->nand_size = read_le32(entry_buf + 92);
        entry->pos = read_le32(entry_buf + 96);
        entry->nand_addr = read_le32(entry_buf + 100);
        entry->img_size = read_le32(entry_buf + 104);
        entry->orig_size = read_le32(entry_buf + 108);
        stored_size = rkaf_entry_stored_size(entry);

        if (stored_size > 0 && entry->orig_size <= stored_size && entry->pos + stored_size <= blob_size - 4u &&
            strcmp(entry->file_name, "RESERVED") != 0 && strcmp(entry->file_name, "SELF") != 0) {
            choose_entry_output_name(manifest, i, entry, data_rel, sizeof(data_rel));
            if (unwrap_signed_blob(blob + entry->pos, entry->orig_size, &signed_suffix, &inner_data, &inner_size)) {
                char wrapped_rel[256];
                char wrapped_path[4096];

                snprintf(wrapped_rel, sizeof(wrapped_rel), "%s%s", data_rel, signed_suffix);
                path_join(wrapped_path, sizeof(wrapped_path), out_dir, wrapped_rel);
                if (write_file(wrapped_path, blob + entry->pos, entry->orig_size) != 0) {
                    free(blob);
                    return -1;
                }

                path_join(data_path, sizeof(data_path), out_dir, data_rel);
                if (write_file(data_path, inner_data, inner_size) != 0) {
                    free(blob);
                    return -1;
                }

                snprintf(entry->data_file, sizeof(entry->data_file), "%s", wrapped_rel);
                entry->has_data_file = true;
            } else {
                path_join(data_path, sizeof(data_path), out_dir, data_rel);
                if (write_file(data_path, blob + entry->pos, entry->orig_size) != 0) {
                    free(blob);
                    return -1;
                }
                snprintf(entry->data_file, sizeof(entry->data_file), "%s", data_rel);
                entry->has_data_file = true;
            }
        }
    }

    crc = rkcrc32_update(0, blob, manifest->image_size);
    manifest->stored_rkcrc = read_le32(blob + manifest->image_size);
    if (crc != manifest->stored_rkcrc) {
        warnx("RKAF CRC mismatch for %s (stored 0x%08" PRIx32 ", calculated 0x%08" PRIx32 ")",
              input_path, manifest->stored_rkcrc, crc);
    }

    if (write_rkaf_manifest(out_dir, manifest) != 0) {
        free(blob);
        return -1;
    }

    free(blob);
    return 0;
}

static int unpack_rkfw_file(const char *input_path, const char *out_dir, RkfwManifest *manifest)
{
    InputFile in;
    uint8_t header[RKFW_HEADER_SIZE];
    char path[4096];
    uint64_t expected_no_md5;
    Md5Ctx md5;
    uint8_t digest[16];
    char digest_hex[33];

    memset(manifest, 0, sizeof(*manifest));
    if (open_input(&in, input_path) != 0) {
        return -1;
    }
    if (in.size < RKFW_HEADER_SIZE || fread(header, 1, sizeof(header), in.fp) != sizeof(header)) {
        close_input(&in);
        errno = EINVAL;
        return -1;
    }
    if (memcmp(header, "RKFW", 4) != 0) {
        close_input(&in);
        errno = EINVAL;
        return -1;
    }

    manifest->header_len = read_le16(header + 4);
    manifest->version = read_le32(header + 6);
    manifest->code = read_le32(header + 10);
    manifest->year = read_le16(header + 14);
    manifest->month = header[16];
    manifest->day = header[17];
    manifest->hour = header[18];
    manifest->minute = header[19];
    manifest->second = header[20];
    manifest->chip_id = read_le32(header + 21);
    manifest->load_off = read_le32(header + 25);
    manifest->load_len = read_le32(header + 29);
    manifest->data_off = read_le32(header + 33);
    manifest->data_len = read_le32(header + 37);
    manifest->unknown1 = read_le32(header + 41);
    manifest->rkfw_type = read_le32(header + 45);
    manifest->sysfs_type = read_le32(header + 49);
    manifest->backup_end = read_le32(header + 53);
    manifest->unknown2 = read_le32(header + 98);
    snprintf(manifest->loader_file, sizeof(manifest->loader_file), "loader.bin");
    snprintf(manifest->update_file, sizeof(manifest->update_file), "update.img");
    snprintf(manifest->update_dir, sizeof(manifest->update_dir), "update");

    expected_no_md5 = (uint64_t)manifest->data_off + (uint64_t)manifest->data_len;
    manifest->append_md5 = (expected_no_md5 + 32u == in.size);
    if (!manifest->append_md5 && expected_no_md5 != in.size) {
        warnx("RKFW size mismatch for %s (header expects %" PRIu64 " bytes without md5, file is %" PRIu64 ")",
              input_path, expected_no_md5, in.size);
    }

    path_join(path, sizeof(path), out_dir, manifest->loader_file);
    if (ensure_parent_dir(path) != 0) {
        close_input(&in);
        return -1;
    }
    {
        OutputFile out;
        uint8_t buf[1 << 16];
        uint64_t remaining = manifest->load_len;
        if (open_output(&out, path) != 0) {
            close_input(&in);
            return -1;
        }
        if (seek_file(in.fp, manifest->load_off) != 0) {
            close_output(&out);
            close_input(&in);
            return -1;
        }
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
            if (fread(buf, 1, chunk, in.fp) != chunk || fwrite(buf, 1, chunk, out.fp) != chunk) {
                close_output(&out);
                close_input(&in);
                return -1;
            }
            remaining -= chunk;
        }
        close_output(&out);
    }

    path_join(path, sizeof(path), out_dir, manifest->update_file);
    {
        OutputFile out;
        uint8_t buf[1 << 16];
        uint64_t remaining = manifest->data_len;
        if (open_output(&out, path) != 0) {
            close_input(&in);
            return -1;
        }
        if (seek_file(in.fp, manifest->data_off) != 0) {
            close_output(&out);
            close_input(&in);
            return -1;
        }
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
            if (fread(buf, 1, chunk, in.fp) != chunk || fwrite(buf, 1, chunk, out.fp) != chunk) {
                close_output(&out);
                close_input(&in);
                return -1;
            }
            remaining -= chunk;
        }
        close_output(&out);
    }

    md5_init(&md5);
    md5_update(&md5, header, sizeof(header));
    if (seek_file(in.fp, manifest->load_off) == 0) {
        uint8_t buf[1 << 16];
        uint64_t remaining = manifest->load_len + manifest->data_len;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
            if (fread(buf, 1, chunk, in.fp) != chunk) {
                break;
            }
            md5_update(&md5, buf, chunk);
            remaining -= chunk;
        }
    }
    md5_final(&md5, digest);
    digest_to_hex(digest, digest_hex);

    if (manifest->append_md5) {
        uint8_t md5_tail[32];
        char stored_hex[33];
        if (seek_file(in.fp, expected_no_md5) == 0 &&
            fread(md5_tail, 1, sizeof(md5_tail), in.fp) == sizeof(md5_tail)) {
            memcpy(stored_hex, md5_tail, 32);
            stored_hex[32] = '\0';
            if (strcmp(stored_hex, digest_hex) != 0) {
                warnx("RKFW MD5 mismatch for %s (stored %s, calculated %s)", input_path, stored_hex, digest_hex);
            }
        }
    }

    close_input(&in);

    path_join(path, sizeof(path), out_dir, manifest->update_file);
    {
        uint8_t *update_blob = NULL;
        size_t update_size = 0;
        if (slurp_file(path, &update_blob, &update_size) == 0) {
            if (detect_image_kind(update_blob, update_size) == IMAGE_RKAF) {
                char nested_dir[4096];
                RkafManifest nested;
                manifest->nested_is_rkaf = true;
                path_join(nested_dir, sizeof(nested_dir), out_dir, manifest->update_dir);
                if (mkdir_p(nested_dir) != 0 && errno != EEXIST) {
                    free(update_blob);
                    return -1;
                }
                if (unpack_rkaf_file(path, nested_dir, &nested) != 0) {
                    free(update_blob);
                    return -1;
                }
            }
            free(update_blob);
        }
    }

    return write_rkfw_manifest(out_dir, manifest);
}

static int unpack_image(const char *input_path, const char *out_dir)
{
    uint8_t magic[4];
    InputFile in;

    if (mkdir_p(out_dir) != 0 && errno != EEXIST) {
        return -1;
    }
    if (open_input(&in, input_path) != 0) {
        return -1;
    }
    if (fread(magic, 1, sizeof(magic), in.fp) != sizeof(magic)) {
        close_input(&in);
        errno = EINVAL;
        return -1;
    }
    close_input(&in);

    if (memcmp(magic, "RKFW", 4) == 0) {
        RkfwManifest manifest;
        return unpack_rkfw_file(input_path, out_dir, &manifest);
    }
    if (memcmp(magic, "RKAF", 4) == 0) {
        RkafManifest manifest;
        return unpack_rkaf_file(input_path, out_dir, &manifest);
    }

    errno = EINVAL;
    return -1;
}

static void rkfw_apply_defaults(RkfwManifest *manifest)
{
    struct tm tm_now;

    memset(manifest, 0, sizeof(*manifest));
    manifest->header_len = RKFW_HEADER_SIZE;
    manifest->code = DEFAULT_CODE;
    manifest->chip_id = DEFAULT_CHIP_ID;
    manifest->load_off = RKFW_HEADER_SIZE;
    manifest->append_md5 = true;

    fill_local_time(&tm_now);
    manifest->year = (uint16_t)(tm_now.tm_year + 1900);
    manifest->month = (uint8_t)(tm_now.tm_mon + 1);
    manifest->day = (uint8_t)tm_now.tm_mday;
    manifest->hour = (uint8_t)tm_now.tm_hour;
    manifest->minute = (uint8_t)tm_now.tm_min;
    manifest->second = (uint8_t)tm_now.tm_sec;
}

static int pack_rkaf_dir(const char *dir, const Manifest *manifest, const char *output_path)
{
    const RkafManifest *rkaf = &manifest->rkaf;
    bool uses_block_units = rkaf_manifest_uses_block_units(rkaf);
    uint32_t header_size;
    uint32_t image_size;
    uint8_t *blob;
    size_t blob_size;
    size_t i;
    uint32_t offset;
    uint32_t crc;

    if (rkaf->entry_count > RKAF_MAX_ENTRIES) {
        errno = EINVAL;
        return -1;
    }

    header_size = rkaf->header_size ? rkaf->header_size : 0x800u;
    if (header_size < 140u + (uint32_t)rkaf->entry_count * RKAF_ENTRY_SIZE) {
        header_size = align_up_u32(140u + (uint32_t)rkaf->entry_count * RKAF_ENTRY_SIZE, 0x800u);
    }
    if (header_size != 0x800u && header_size != 0x1000u) {
        header_size = align_up_u32(header_size, 0x800u);
    }

    offset = header_size;
    for (i = 0; i < rkaf->entry_count; i++) {
        const RkafEntry *entry = &rkaf->entries[i];
        uint8_t *data;
        size_t data_size;
        char data_path[4096];
        uint32_t stored_size;

        if (strcmp(entry->file_name, "SELF") == 0) {
            errno = ENOTSUP;
            warnx("SELF entries are not supported by the minimal packer");
            return -1;
        }

        if (strcmp(entry->file_name, "RESERVED") == 0 || !entry->has_data_file) {
            continue;
        }

        path_join(data_path, sizeof(data_path), dir, entry->data_file);
        if (slurp_file(data_path, &data, &data_size) != 0) {
            return -1;
        }
        free(data);

        stored_size = uses_block_units ? align_up_u32((uint32_t)data_size, 0x800u) : (uint32_t)data_size;
        offset = align_up_u32(offset, uses_block_units ? 0x800u : 4u);
        offset += stored_size;
    }

    image_size = offset;
    blob_size = (size_t)image_size + 4u;
    blob = calloc(1, blob_size);
    if (blob == NULL) {
        return -1;
    }

    memcpy(blob, "RKAF", 4);
    write_le32(blob + 4, image_size);
    copy_padded_string(blob + 8, 34, rkaf->model);
    copy_padded_string(blob + 42, 30, rkaf->id);
    copy_padded_string(blob + 72, 56, rkaf->manufacturer);
    write_le32(blob + 128, rkaf->unknown1);
    write_le32(blob + 132, rkaf->version);
    write_le32(blob + 136, (uint32_t)rkaf->entry_count);

    offset = header_size;
    for (i = 0; i < rkaf->entry_count; i++) {
        const RkafEntry *src = &rkaf->entries[i];
        uint8_t *entry_buf = blob + 140u + i * RKAF_ENTRY_SIZE;
        uint8_t *data;
        size_t data_size = 0;
        char data_path[4096];
        uint32_t pos = src->pos;
        uint32_t img_size_field = src->img_size;
        uint32_t orig_size = src->orig_size;
        uint32_t stored_size = rkaf_entry_stored_size(src);

        copy_padded_string(entry_buf + 0, 32, src->name);
        copy_padded_string(entry_buf + 32, 60, src->file_name);
        write_le32(entry_buf + 92, src->nand_size);
        write_le32(entry_buf + 100, src->nand_addr);

        if (strcmp(src->file_name, "RESERVED") == 0 || !src->has_data_file) {
            write_le32(entry_buf + 96, pos);
            write_le32(entry_buf + 104, img_size_field);
            write_le32(entry_buf + 108, orig_size);
            continue;
        }

        path_join(data_path, sizeof(data_path), dir, src->data_file);
        if (slurp_file(data_path, &data, &data_size) != 0) {
            free(blob);
            return -1;
        }

        offset = align_up_u32(offset, uses_block_units ? 0x800u : 4u);
        pos = src->pos ? src->pos : offset;
        if (pos != offset) {
            warnx("entry %s requested pos 0x%08" PRIx32 " but minimal packer uses packed layout 0x%08" PRIx32,
                  src->file_name[0] ? src->file_name : src->name, pos, offset);
            pos = offset;
        }

        orig_size = (uint32_t)data_size;
        stored_size = uses_block_units ? align_up_u32(orig_size, 0x800u) : orig_size;
        img_size_field = uses_block_units ? (stored_size >> 11) : stored_size;
        memcpy(blob + pos, data, data_size);
        free(data);

        write_le32(entry_buf + 96, pos);
        write_le32(entry_buf + 104, img_size_field);
        write_le32(entry_buf + 108, orig_size);

        offset = pos + stored_size;
    }

    crc = rkcrc32_update(0, blob, image_size);
    write_le32(blob + image_size, crc);

    if (write_file(output_path, blob, blob_size) != 0) {
        free(blob);
        return -1;
    }

    free(blob);
    return 0;
}

static int pack_rkfw_dir(const char *dir, const Manifest *manifest, const char *output_path)
{
    const RkfwManifest *rkfw = &manifest->rkfw;
    Manifest nested_manifest;
    uint8_t *loader = NULL;
    uint8_t *update = NULL;
    size_t loader_size = 0;
    size_t update_size = 0;
    bool built_nested = false;
    char loader_path[4096];
    char update_path[4096];
    char nested_dir[4096];
    char nested_tmp[4096];
    uint8_t header[RKFW_HEADER_SIZE];
    OutputFile out;
    Md5Ctx md5;
    uint8_t digest[16];
    char digest_hex[33];
    int rc = -1;

    if (rkfw->loader_file[0] == '\0' || rkfw->update_file[0] == '\0') {
        errno = EINVAL;
        warnx("RKFW manifest requires loader_file and update_file");
        return -1;
    }

    path_join(loader_path, sizeof(loader_path), dir, rkfw->loader_file);
    if (slurp_file(loader_path, &loader, &loader_size) != 0) {
        return -1;
    }

    if (rkfw->nested_is_rkaf && rkfw->update_dir[0] != '\0') {
        path_join(nested_dir, sizeof(nested_dir), dir, rkfw->update_dir);
        memset(&nested_manifest, 0, sizeof(nested_manifest));
        if (load_manifest(nested_dir, &nested_manifest) != 0) {
            goto cleanup;
        }
        if (nested_manifest.kind != IMAGE_RKAF) {
            errno = EINVAL;
            warnx("nested manifest in %s is not RKAF", nested_dir);
            goto cleanup;
        }
        snprintf(nested_tmp, sizeof(nested_tmp), "%s/.update.img.tmp", dir);
        if (pack_rkaf_dir(nested_dir, &nested_manifest, nested_tmp) != 0) {
            goto cleanup;
        }
        built_nested = true;
        if (slurp_file(nested_tmp, &update, &update_size) != 0) {
            goto cleanup;
        }
    } else {
        path_join(update_path, sizeof(update_path), dir, rkfw->update_file);
        if (slurp_file(update_path, &update, &update_size) != 0) {
            goto cleanup;
        }
    }

    memset(header, 0, sizeof(header));
    memcpy(header, "RKFW", 4);
    write_le16(header + 4, rkfw->header_len ? rkfw->header_len : RKFW_HEADER_SIZE);
    write_le32(header + 6, rkfw->version);
    write_le32(header + 10, rkfw->code ? rkfw->code : DEFAULT_CODE);
    write_le16(header + 14, rkfw->year);
    header[16] = rkfw->month;
    header[17] = rkfw->day;
    header[18] = rkfw->hour;
    header[19] = rkfw->minute;
    header[20] = rkfw->second;
    write_le32(header + 21, rkfw->chip_id ? rkfw->chip_id : DEFAULT_CHIP_ID);
    write_le32(header + 25, rkfw->load_off ? rkfw->load_off : RKFW_HEADER_SIZE);
    write_le32(header + 29, (uint32_t)loader_size);
    write_le32(header + 33, rkfw->data_off ? rkfw->data_off : (uint32_t)(RKFW_HEADER_SIZE + loader_size));
    write_le32(header + 37, (uint32_t)update_size);
    write_le32(header + 41, rkfw->unknown1);
    write_le32(header + 45, rkfw->rkfw_type);
    write_le32(header + 49, rkfw->sysfs_type);
    write_le32(header + 53, rkfw->backup_end);
    write_le32(header + 98, rkfw->unknown2);

    if (open_output(&out, output_path) != 0) {
        goto cleanup;
    }
    if (fwrite(header, 1, sizeof(header), out.fp) != sizeof(header) ||
        fwrite(loader, 1, loader_size, out.fp) != loader_size ||
        fwrite(update, 1, update_size, out.fp) != update_size) {
        close_output(&out);
        goto cleanup;
    }

    if (rkfw->append_md5) {
        md5_init(&md5);
        md5_update(&md5, header, sizeof(header));
        md5_update(&md5, loader, loader_size);
        md5_update(&md5, update, update_size);
        md5_final(&md5, digest);
        digest_to_hex(digest, digest_hex);
        if (fwrite(digest_hex, 1, 32, out.fp) != 32) {
            close_output(&out);
            goto cleanup;
        }
    }

    if (close_output(&out) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (built_nested) {
        remove(nested_tmp);
    }
    free(loader);
    free(update);
    return rc;
}

static int pack_image(const char *input_dir, const char *output_path)
{
    Manifest manifest;

    memset(&manifest, 0, sizeof(manifest));
    if (load_manifest(input_dir, &manifest) != 0) {
        return -1;
    }

    switch (manifest.kind) {
    case IMAGE_RKAF:
        return pack_rkaf_dir(input_dir, &manifest, output_path);
    case IMAGE_RKFW:
        if (manifest.rkfw.header_len == 0 || manifest.rkfw.code == 0 || manifest.rkfw.chip_id == 0) {
            RkfwManifest defaults;
            rkfw_apply_defaults(&defaults);
            if (manifest.rkfw.header_len == 0) {
                manifest.rkfw.header_len = defaults.header_len;
            }
            if (manifest.rkfw.code == 0) {
                manifest.rkfw.code = defaults.code;
            }
            if (manifest.rkfw.chip_id == 0) {
                manifest.rkfw.chip_id = defaults.chip_id;
            }
            if (manifest.rkfw.load_off == 0) {
                manifest.rkfw.load_off = defaults.load_off;
            }
            if (manifest.rkfw.year == 0) {
                manifest.rkfw.year = defaults.year;
                manifest.rkfw.month = defaults.month;
                manifest.rkfw.day = defaults.day;
                manifest.rkfw.hour = defaults.hour;
                manifest.rkfw.minute = defaults.minute;
                manifest.rkfw.second = defaults.second;
            }
        }
        return pack_rkfw_dir(input_dir, &manifest, output_path);
    default:
        errno = EINVAL;
        warnx("unsupported manifest format");
        return -1;
    }
}

static void usage(FILE *fp, const char *argv0)
{
    fprintf(fp,
            "Usage:\n"
            "  %s unpack <input.img> <output-dir>\n"
            "  %s pack <input-dir> <output.img>\n"
            "  %s list <input.img>\n\n"
            "Supported formats: RKFW and RKAF.\n",
            argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "list") == 0) {
        if (list_image_yaml(argv[2]) != 0) {
            fprintf(stderr, "list failed: %s\n", strerror(errno));
            return 1;
        }
        return 0;
    }

    if (argc == 4 && strcmp(argv[1], "unpack") == 0) {
        if (unpack_image(argv[2], argv[3]) != 0) {
            fprintf(stderr, "unpack failed: %s\n", strerror(errno));
            return 1;
        }
        return 0;
    }

    if (argc == 4 && strcmp(argv[1], "pack") == 0) {
        if (pack_image(argv[2], argv[3]) != 0) {
            fprintf(stderr, "pack failed: %s\n", strerror(errno));
            return 1;
        }
        return 0;
    }

    usage(stderr, argv[0]);
    return 2;
}
