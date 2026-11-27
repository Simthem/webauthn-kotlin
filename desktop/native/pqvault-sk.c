/* OpenSSH security key provider (sk-api 10) for PQ Vault. It only relays bytes to the helper. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SK_API __attribute__((visibility("default")))

#define SSH_SK_VERSION_MAJOR		0x000a0000
#define SSH_SK_ECDSA			0x00
#define SSH_SK_ED25519			0x01
#define SSH_SK_ERR_GENERAL		-1
#define SSH_SK_ERR_UNSUPPORTED		-2
#define SSH_SK_ERR_CREDENTIAL_EXISTS	-5

struct sk_enroll_response {
	uint8_t flags;
	uint8_t *public_key;
	size_t public_key_len;
	uint8_t *key_handle;
	size_t key_handle_len;
	uint8_t *signature;
	size_t signature_len;
	uint8_t *attestation_cert;
	size_t attestation_cert_len;
	uint8_t *authdata;
	size_t authdata_len;
};

struct sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	size_t sig_r_len;
	uint8_t *sig_s;
	size_t sig_s_len;
};

struct sk_resident_key {
	uint32_t alg;
	size_t slot;
	char *application;
	struct sk_enroll_response key;
	uint8_t flags;
	uint8_t *user_id;
	size_t user_id_len;
};

struct sk_option {
	char *name;
	char *value;
	uint8_t required;
};

SK_API uint32_t sk_api_version(void);
SK_API int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response);
SK_API int sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response);
SK_API int sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rks, size_t *nrks);

#define OP_ENROLL	1
#define OP_SIGN		2
#define OP_LIST		3
#define MAX_KEYS	256
#define MAX_APPLICATION	256
#define MAX_MESSAGE	(1 << 20)
#define MAX_HANDLE	1024
#define MAX_REPLY	(64 * 1024)
#define USER_ID_MAX	31

extern char **environ;

struct buffer {
	uint8_t *data;
	size_t len;
	size_t cap;
};

static int
put(struct buffer *b, const void *data, size_t len)
{
	if (len > SIZE_MAX - b->len)
		return -1;
	if (b->len + len > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		uint8_t *grown;
		while (cap < b->len + len)
			cap *= 2;
		if ((grown = realloc(b->data, cap)) == NULL)
			return -1;
		b->data = grown;
		b->cap = cap;
	}
	if (len > 0)
		memcpy(b->data + b->len, data, len);
	b->len += len;
	return 0;
}

static int
put_u8(struct buffer *b, uint8_t v)
{
	return put(b, &v, 1);
}

static int
put_u32(struct buffer *b, uint32_t v)
{
	uint8_t be[4] = {
		(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v
	};
	return put(b, be, 4);
}

static int
put_field(struct buffer *b, const void *data, size_t len)
{
	if (len > UINT32_MAX || put_u32(b, (uint32_t)len) != 0)
		return -1;
	return put(b, data, len);
}

struct reader {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static int
get(struct reader *r, void *out, size_t len)
{
	if (len > r->len - r->pos)
		return -1;
	memcpy(out, r->data + r->pos, len);
	r->pos += len;
	return 0;
}

static int
get_u8(struct reader *r, uint8_t *v)
{
	return get(r, v, 1);
}

static int
get_u32(struct reader *r, uint32_t *v)
{
	uint8_t be[4];
	if (get(r, be, 4) != 0)
		return -1;
	*v = (uint32_t)be[0] << 24 | (uint32_t)be[1] << 16 | (uint32_t)be[2] << 8 | be[3];
	return 0;
}

/* A length-prefixed field, copied. An empty field gives NULL. */
static int
get_field(struct reader *r, uint8_t **out, size_t *out_len)
{
	uint32_t len;
	*out = NULL;
	*out_len = 0;
	if (get_u32(r, &len) != 0 || len > r->len - r->pos)
		return -1;
	if (len == 0)
		return 0;
	if ((*out = malloc(len)) == NULL)
		return -1;
	memcpy(*out, r->data + r->pos, len);
	r->pos += len;
	*out_len = len;
	return 0;
}

/* The helper given by PQVAULT_SK_HELPER, or the one installed next to this library. */
static char *
helper_path(void)
{
	const char *configured = getenv("PQVAULT_SK_HELPER");
	Dl_info info;
	const char *slash;
	char *path;
	size_t dir_len;
	static const char suffix[] = "/helper/bin/pqvault-ssh-helper";

	if (configured != NULL && configured[0] != '\0')
		return configured[0] == '/' ? strdup(configured) : NULL;
	if (dladdr((void *)helper_path, &info) == 0 || info.dli_fname == NULL ||
	    info.dli_fname[0] != '/' || (slash = strrchr(info.dli_fname, '/')) == NULL)
		return NULL;
	dir_len = (size_t)(slash - info.dli_fname);
	if ((path = malloc(dir_len + sizeof(suffix))) == NULL)
		return NULL;
	memcpy(path, info.dli_fname, dir_len);
	memcpy(path + dir_len, suffix, sizeof(suffix));
	return path;
}

static int
send_all(int fd, const uint8_t *data, size_t len)
{
	while (len > 0) {
		ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		data += n;
		len -= (size_t)n;
	}
	return 0;
}

/* Runs the helper on one request and returns its complete answer. */
static int
exchange(const struct buffer *request, struct buffer *reply)
{
	char *path = helper_path();
	char *argv[2];
	int pair[2] = { -1, -1 };
	posix_spawn_file_actions_t actions;
	pid_t pid = -1, waited;
	int status = 0, ret = -1;
	uint8_t chunk[4096];

	if (path == NULL)
		return -1;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
		free(path);
		return -1;
	}
	argv[0] = path;
	argv[1] = NULL;
	if (posix_spawn_file_actions_init(&actions) != 0)
		goto out;
	if (posix_spawn_file_actions_adddup2(&actions, pair[1], STDIN_FILENO) != 0 ||
	    posix_spawn_file_actions_adddup2(&actions, pair[1], STDOUT_FILENO) != 0 ||
	    posix_spawn(&pid, path, &actions, NULL, argv, environ) != 0) {
		posix_spawn_file_actions_destroy(&actions);
		pid = -1;
		goto out;
	}
	posix_spawn_file_actions_destroy(&actions);
	close(pair[1]);
	pair[1] = -1;

	if (send_all(pair[0], request->data, request->len) != 0)
		goto out;
	shutdown(pair[0], SHUT_WR);
	for (;;) {
		ssize_t n = recv(pair[0], chunk, sizeof(chunk), 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			goto out;
		if (n == 0)
			break;
		if (reply->len + (size_t)n > MAX_REPLY || put(reply, chunk, (size_t)n) != 0)
			goto out;
	}
	ret = 0;
 out:
	if (pair[0] >= 0)
		close(pair[0]);
	if (pair[1] >= 0)
		close(pair[1]);
	if (pid > 0) {
		do {
			waited = waitpid(pid, &status, 0);
		} while (waited < 0 && errno == EINTR);
		if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			ret = -1;
	}
	free(path);
	return ret;
}

static int
build_request(struct buffer *b, uint8_t op, uint32_t alg, uint8_t flags,
    const char *application, const uint8_t *message, size_t message_len,
    const uint8_t *handle, size_t handle_len)
{
	size_t app_len;

	if (application == NULL || (app_len = strlen(application)) >= MAX_APPLICATION ||
	    message_len > MAX_MESSAGE || handle_len > MAX_HANDLE)
		return -1;
	if (put(b, "PQSK", 4) != 0 || put_u8(b, 1) != 0 || put_u8(b, op) != 0 ||
	    put_u32(b, alg) != 0 || put_u8(b, flags) != 0 ||
	    put_field(b, application, app_len) != 0 ||
	    put_field(b, message, message_len) != 0 ||
	    put_field(b, handle, handle_len) != 0)
		return -1;
	return 0;
}

/* Reads the reply header. Returns 0 on success, an SSH_SK_ERR_* code otherwise. */
static int
read_header(struct reader *r, uint8_t expected_op)
{
	uint8_t magic[4], version, op;
	uint32_t status;

	if (get(r, magic, 4) != 0 || memcmp(magic, "PQSK", 4) != 0 ||
	    get_u8(r, &version) != 0 || version != 1 || get_u32(r, &status) != 0)
		return SSH_SK_ERR_GENERAL;
	if (status != 0) {
		int32_t code = (int32_t)status;
		return code <= SSH_SK_ERR_GENERAL && code >= SSH_SK_ERR_CREDENTIAL_EXISTS ?
		    code : SSH_SK_ERR_GENERAL;
	}
	if (get_u8(r, &op) != 0 || op != expected_op)
		return SSH_SK_ERR_GENERAL;
	return 0;
}

static int
check_options(struct sk_option **options, uint8_t *user_id, size_t *user_id_len)
{
	size_t i;

	if (options == NULL)
		return 0;
	for (i = 0; options[i] != NULL; i++) {
		if (strcmp(options[i]->name, "user") == 0 && user_id != NULL) {
			size_t len = strlen(options[i]->value);
			if (len > USER_ID_MAX)
				return -1;
			memcpy(user_id, options[i]->value, len);
			*user_id_len = len;
		} else if (strcmp(options[i]->name, "device") != 0 && options[i]->required) {
			return -1;
		}
	}
	return 0;
}

SK_API uint32_t
sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

SK_API int
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	struct buffer request = { 0 }, reply = { 0 };
	struct reader r;
	struct sk_enroll_response *response = NULL;
	uint8_t user_id[USER_ID_MAX] = { 0 };
	size_t user_id_len = 0;
	uint8_t *attestation_cert = NULL;
	size_t attestation_cert_len = 0;
	int ret = SSH_SK_ERR_GENERAL;

	(void)pin;
	if (enroll_response == NULL)
		return SSH_SK_ERR_GENERAL;
	*enroll_response = NULL;
	if (alg != SSH_SK_ECDSA && alg != SSH_SK_ED25519)
		return SSH_SK_ERR_UNSUPPORTED;
	if (check_options(options, user_id, &user_id_len) != 0)
		return SSH_SK_ERR_GENERAL;
	if (build_request(&request, OP_ENROLL, alg, flags, application,
	    challenge, challenge_len, user_id, user_id_len) != 0 ||
	    exchange(&request, &reply) != 0)
		goto out;

	r.data = reply.data;
	r.len = reply.len;
	r.pos = 0;
	if ((ret = read_header(&r, OP_ENROLL)) != 0)
		goto out;
	ret = SSH_SK_ERR_GENERAL;
	if ((response = calloc(1, sizeof(*response))) == NULL ||
	    get_u8(&r, &response->flags) != 0 ||
	    get_field(&r, &response->public_key, &response->public_key_len) != 0 ||
	    get_field(&r, &response->key_handle, &response->key_handle_len) != 0 ||
	    get_field(&r, &response->signature, &response->signature_len) != 0 ||
	    get_field(&r, &attestation_cert, &attestation_cert_len) != 0 ||
	    get_field(&r, &response->authdata, &response->authdata_len) != 0 ||
	    r.pos != r.len || response->public_key == NULL || response->key_handle == NULL)
		goto out;
	response->attestation_cert = attestation_cert;
	response->attestation_cert_len = attestation_cert_len;
	attestation_cert = NULL;
	*enroll_response = response;
	response = NULL;
	ret = 0;
 out:
	free(attestation_cert);
	if (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response->authdata);
		free(response);
	}
	free(request.data);
	free(reply.data);
	return ret;
}

SK_API int
sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response)
{
	struct buffer request = { 0 }, reply = { 0 };
	struct reader r;
	struct sk_sign_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL;

	(void)pin;
	if (sign_response == NULL)
		return SSH_SK_ERR_GENERAL;
	*sign_response = NULL;
	if (alg != SSH_SK_ECDSA && alg != SSH_SK_ED25519)
		return SSH_SK_ERR_UNSUPPORTED;
	if (key_handle == NULL || key_handle_len == 0 ||
	    check_options(options, NULL, NULL) != 0)
		return SSH_SK_ERR_GENERAL;
	if (build_request(&request, OP_SIGN, alg, flags, application,
	    data, data_len, key_handle, key_handle_len) != 0 ||
	    exchange(&request, &reply) != 0)
		goto out;

	r.data = reply.data;
	r.len = reply.len;
	r.pos = 0;
	if ((ret = read_header(&r, OP_SIGN)) != 0)
		goto out;
	ret = SSH_SK_ERR_GENERAL;
	if ((response = calloc(1, sizeof(*response))) == NULL ||
	    get_u8(&r, &response->flags) != 0 ||
	    get_u32(&r, &response->counter) != 0 ||
	    get_field(&r, &response->sig_r, &response->sig_r_len) != 0 ||
	    get_field(&r, &response->sig_s, &response->sig_s_len) != 0 ||
	    r.pos != r.len || response->sig_r == NULL ||
	    (alg == SSH_SK_ECDSA && response->sig_s == NULL))
		goto out;
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	if (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	free(request.data);
	free(reply.data);
	return ret;
}

static void
free_resident_keys(struct sk_resident_key **rks, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (rks[i] == NULL)
			continue;
		free(rks[i]->application);
		free(rks[i]->key.public_key);
		free(rks[i]->key.key_handle);
		free(rks[i]->user_id);
		free(rks[i]);
	}
	free(rks);
}

/* Reads one listed key into rk. Returns 0 on success. */
static int
read_resident_key(struct reader *r, struct sk_resident_key *rk)
{
	uint8_t *application = NULL;
	size_t application_len;

	if (get_u32(r, &rk->alg) != 0 ||
	    (rk->alg != SSH_SK_ECDSA && rk->alg != SSH_SK_ED25519) ||
	    get_field(r, &application, &application_len) != 0)
		goto fail;
	if (application == NULL || application_len >= MAX_APPLICATION ||
	    memchr(application, '\0', application_len) != NULL ||
	    (rk->application = malloc(application_len + 1)) == NULL)
		goto fail;
	memcpy(rk->application, application, application_len);
	rk->application[application_len] = '\0';
	free(application);
	if (get_u8(r, &rk->flags) != 0 ||
	    get_field(r, &rk->key.public_key, &rk->key.public_key_len) != 0 ||
	    get_field(r, &rk->key.key_handle, &rk->key.key_handle_len) != 0 ||
	    get_field(r, &rk->user_id, &rk->user_id_len) != 0 ||
	    rk->key.public_key == NULL || rk->key.key_handle == NULL)
		return -1;
	rk->key.flags = rk->flags;
	return 0;
 fail:
	free(application);
	return -1;
}

/* The resident SSH keys of the vault, sent by the phone after user verification. */
SK_API int
sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rksp, size_t *nrksp)
{
	struct buffer request = { 0 }, reply = { 0 };
	struct reader r;
	struct sk_resident_key **rks = NULL;
	size_t n = 0;
	uint32_t count, i;
	int ret = SSH_SK_ERR_GENERAL;

	(void)pin;
	if (rksp == NULL || nrksp == NULL)
		return SSH_SK_ERR_GENERAL;
	*rksp = NULL;
	*nrksp = 0;
	if (check_options(options, NULL, NULL) != 0)
		return SSH_SK_ERR_GENERAL;
	if (build_request(&request, OP_LIST, SSH_SK_ECDSA, 0, "ssh:", NULL, 0, NULL, 0) != 0 ||
	    exchange(&request, &reply) != 0)
		goto out;

	r.data = reply.data;
	r.len = reply.len;
	r.pos = 0;
	if ((ret = read_header(&r, OP_LIST)) != 0)
		goto out;
	ret = SSH_SK_ERR_GENERAL;
	if (get_u32(&r, &count) != 0 || count > MAX_KEYS)
		goto out;
	if (count > 0 && (rks = calloc(count, sizeof(*rks))) == NULL)
		goto out;
	for (i = 0; i < count; i++) {
		if ((rks[n] = calloc(1, sizeof(*rks[n]))) == NULL)
			goto out;
		rks[n]->slot = i;
		if (read_resident_key(&r, rks[n++]) != 0)
			goto out;
	}
	if (r.pos != r.len)
		goto out;
	*rksp = rks;
	*nrksp = n;
	rks = NULL;
	ret = 0;
 out:
	if (rks != NULL)
		free_resident_keys(rks, n);
	free(request.data);
	free(reply.data);
	return ret;
}
