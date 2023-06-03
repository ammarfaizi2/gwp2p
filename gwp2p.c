// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwp2p - GNU/Weeb behind NAT Peer-to-Peer implementation.
 *
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Thanks to Matthew Patrick <ThePhoenix576@gnuweeb.org> for the idea.
 *
 * Link: https://t.me/GNUWeeb/782010
 * Link: https://tailscale.com/blog/how-nat-traversal-works
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <poll.h>
#include <stdint.h>

#define GWP2P_DEBUG

#ifdef GWP2P_DEBUG
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug(...) do { } while (0)
#endif

#ifndef __maybe_unused
#define __maybe_unused	__attribute__((__unused__))
#endif

#ifndef __packed
#define __packed	__attribute__((__packed__))
#endif

#ifdef __CHECKER__
#define __bitwise	__attribute__((bitwise))
#define __must_hold(x)	__attribute__((__context__(x,1,1)))
#define __acquires(x)	__attribute__((__context__(x,0,1)))
#define __releases(x)	__attribute__((__context__(x,1,0)))
#else /* #ifdef __CHECKER__ */
#define __bitwise
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#endif /* #ifdef __CHECKER__ */

#define BIND_ADDR	"::"
#define BIND_PORT	8000
#define POLL_TIMEOUT	1000

typedef uint16_t __be16 __bitwise;
typedef uint32_t __be32 __bitwise;

/*
 * Possible client packet types:
 */
enum {
	CL_PKT_PING		= 0,
	CL_PKT_CONNECT		= 1,
	CL_PKT_GET_PEER_LIST	= 2,
	CL_PKT_CLOSE		= 3,
};

/*
 * Possible server packet types:
 */
enum {
	SR_PKT_PING		= 0,
	SR_PKT_SESSION		= 1,
	SR_PKT_NR_PEER_LIST	= 2,
	SR_PKT_PEER_LIST	= 3,
};

struct ip_pkt {
	uint8_t		family;
	uint8_t		__pad;
	__be16		port;
	union {
		uint8_t	ip6[16];
		uint8_t	ip4[4];
		uint8_t ip[16];
	};
} __packed;

struct peer {
	struct ip_pkt	ip;
	char		sess_id[32];
} __packed;

struct cl_pkt_connect {
	struct ip_pkt	local_ip;
	char		sess_id[32];
} __packed;

struct sr_pkt_session {
	struct ip_pkt	public_ip;
	char		sess_id[32];
} __packed;

struct sr_pkt_peer_list {
	uint8_t		nr_peers;
	uint8_t		__pad[3];
	struct peer	peers[];
} __packed;

/*
 * Client packet structure. The packet header is 4 bytes long.
 */
struct cl_pkt {
	uint8_t		type;
	uint8_t		__pad;
	__be16		len;
	union {
		struct cl_pkt_connect	connect;
		char			sess_id[32];
		uint8_t			__raw[2048];
	};
} __packed;

/*
 * Server packet structure. The packet header is 4 bytes long too. 
 */
struct sr_pkt {
	uint8_t		type;
	uint8_t		__pad;
	__be16		len;
	union {
		struct sr_pkt_session	session;
		struct sr_pkt_peer_list	peer_list;
		uint8_t			__raw[2048];
	};
} __packed;

#define CL_PKT_HDR_LEN	4
#define SR_PKT_HDR_LEN	4

struct client {
	bool				is_used;
	struct sockaddr_storage		addr;
	char				sess_id[32];
	struct timespec			last_action;
};

struct server_ctx {
	volatile bool			stop;
	int				udp_fd;
	struct sockaddr_storage		last_src;
	struct client			*clients;
	size_t				clients_len;

	/*
	 * Protected by @clients_lock.
	 */
	uint16_t			nr_online_clients;

	pthread_mutex_t			clients_lock;
	uint16_t			rpkt_len;
	union {
		struct cl_pkt		rpkt;
		uint8_t			__rraw[sizeof(struct cl_pkt)];
	};
	union {
		struct sr_pkt		spkt;
		uint8_t			__sraw[sizeof(struct sr_pkt)];
	};
};

struct client_ctx {
	volatile bool			stop;
	bool				is_connected;
	int				udp_fd;
	struct sockaddr_storage		server_addr;
	struct sockaddr_storage		peer_addr;
	struct sockaddr_storage		local_src;
	struct sockaddr_storage		public_src;
	char				sess_id[32];
	char				cmd_buf[2048];
	uint16_t			rpkt_len;
	struct peer			*peers;
	uint8_t				nr_peers;
	union {
		struct sr_pkt		rpkt;
		uint8_t			__rraw[sizeof(struct sr_pkt)];
	};
	union {
		struct cl_pkt		spkt;
		uint8_t			__sraw[sizeof(struct cl_pkt)];
	};
};

static struct server_ctx *g_server_ctx;
static struct client_ctx *g_client_ctx;

static inline size_t sr_prep_pkt_session(struct sr_pkt *pkt, uint8_t family,
					 uint8_t *public_ip, __be16 public_sport,
					 char sess_id[32])
{
	pkt->type = SR_PKT_SESSION;
	pkt->len = htons(sizeof(pkt->session));
	pkt->__pad = 0;

	pkt->session.public_ip.family = family;
	pkt->session.public_ip.port = public_sport;
	pkt->session.public_ip.__pad = 0;

	memset(pkt->session.public_ip.ip, 0, sizeof(pkt->session.public_ip.ip));
	if (family == 4)
		memcpy(pkt->session.public_ip.ip4, public_ip, 4);
	else
		memcpy(pkt->session.public_ip.ip6, public_ip, 16);

	memcpy(pkt->session.sess_id, sess_id, 32);
	return CL_PKT_HDR_LEN + sizeof(pkt->session);
}

static inline size_t sr_prep_pkt_peer_list(struct sr_pkt *pkt, uint8_t nr_peers,
					   struct peer *peers)
{
	size_t i;

	for (i = 0; i < nr_peers; i++) {
		if ((uintptr_t)&pkt->peer_list.peers[i + 2] >= (uintptr_t)&pkt[1]) {
			nr_peers = (uint8_t)i;
			break;
		}
		pkt->peer_list.peers[i] = peers[i];
	}

	pkt->type = SR_PKT_PEER_LIST;
	pkt->len = htons(sizeof(pkt->peer_list) + nr_peers * sizeof(struct peer));
	pkt->__pad = 0;

	pkt->peer_list.nr_peers = nr_peers;
	return CL_PKT_HDR_LEN + sizeof(pkt->peer_list) + nr_peers * sizeof(struct peer);
}

static inline size_t cl_prep_pkt_connect(struct cl_pkt *pkt, uint8_t family,
					 uint8_t *local_ip, __be16 local_sport,
					 char sess_id[32])
{
	pkt->type = CL_PKT_CONNECT;
	pkt->len = htons(sizeof(pkt->connect));
	pkt->__pad = 0;

	pkt->connect.local_ip.family = family;
	pkt->connect.local_ip.port = local_sport;
	pkt->connect.local_ip.__pad = 0;

	memset(pkt->connect.local_ip.ip, 0, sizeof(pkt->connect.local_ip.ip));
	if (family == 4)
		memcpy(pkt->connect.local_ip.ip4, local_ip, 4);
	else
		memcpy(pkt->connect.local_ip.ip6, local_ip, 16);

	memcpy(pkt->connect.sess_id, sess_id, 32);
	return CL_PKT_HDR_LEN + sizeof(pkt->connect);
}

static inline size_t cl_prep_pkt_get_peers(struct cl_pkt *pkt,
					   const char sess_id[32])
{
	pkt->type = CL_PKT_GET_PEER_LIST;
	pkt->len = htons(32u);
	pkt->__pad = 0;

	memcpy(pkt->sess_id, sess_id, 32);
	return CL_PKT_HDR_LEN + 32u;
}

static inline size_t cl_prep_pkt_close(struct cl_pkt *pkt)
{
	pkt->type = CL_PKT_CLOSE;
	pkt->len = htons(0);
	pkt->__pad = 0;
	return CL_PKT_HDR_LEN;
}

static bool ss_addr_eq(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET) {
		struct sockaddr_in *in_a = (void *)a;
		struct sockaddr_in *in_b = (void *)b;
		return in_a->sin_port == in_b->sin_port &&
		       !memcmp(&in_a->sin_addr, &in_b->sin_addr, 4);
	} else {
		struct sockaddr_in6 *in6_a = (void *)a;
		struct sockaddr_in6 *in6_b = (void *)b;
		return in6_a->sin6_port == in6_b->sin6_port &&
		       !memcmp(&in6_a->sin6_addr, &in6_b->sin6_addr, 16);
	}
}

static int create_udp_socket(int family, struct sockaddr_storage *bind_addr)
{
	socklen_t addrlen;
	int ret, fd;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	if (bind_addr && bind_addr->ss_family != family)
		return -EINVAL;

	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	if (!bind_addr)
		return fd;

	if (family == AF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else
		addrlen = sizeof(struct sockaddr_in);

	ret = bind(fd, (struct sockaddr *)bind_addr, addrlen);
	if (ret < 0) {
		ret = -errno;
		perror("bind");
		close(fd);
		return ret;
	}

	return fd;
}

static int fill_addr_storage(struct sockaddr_storage *ss, const char *addr,
			     uint16_t port)
{
	struct sockaddr_in6 *in6 = (void *)ss;
	struct sockaddr_in *in = (void *)ss;

	memset(ss, 0, sizeof(*ss));

	if (inet_pton(AF_INET6, addr, &in6->sin6_addr) == 1) {
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
	} else if (inet_pton(AF_INET, addr, &in->sin_addr) == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
	} else {
		return -EINVAL;
	}

	return 0;
}

__maybe_unused
static const char *get_addr_str(struct sockaddr_storage *addr)
{
	static __thread char buf_ret[8][INET6_ADDRSTRLEN + 16];
	static __thread char buf_arr[8][INET6_ADDRSTRLEN];
	static __thread uint8_t buf_idx;

	struct sockaddr_in6 *in6 = (void *)addr;
	struct sockaddr_in *in = (void *)addr;
	char *buf, *ret;

	buf = buf_arr[buf_idx % 8];
	ret = buf_ret[buf_idx % 8];

	if (addr->ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &in6->sin6_addr, buf, INET6_ADDRSTRLEN);
		snprintf(ret, sizeof(buf_ret[0]), "[%s]:%hu", buf, ntohs(in6->sin6_port));
	} else if (addr->ss_family == AF_INET) {
		inet_ntop(AF_INET, &in->sin_addr, buf, INET_ADDRSTRLEN);
		snprintf(ret, sizeof(buf_ret[0]), "%s:%hu", buf, ntohs(in->sin_port));
	} else {
		return NULL;
	}

	buf_idx++;
	return ret;
}

__maybe_unused
static const char *get_ip_pkt_str(struct ip_pkt *ip)
{
	struct sockaddr_storage addr;

	memset(&addr, 0, sizeof(addr));
	if (ip->family == 4) {
		struct sockaddr_in *in = (void *)&addr;
		in->sin_family = AF_INET;
		in->sin_port = ip->port;
		memcpy(&in->sin_addr, ip->ip4, 4);
	} else {
		struct sockaddr_in6 *in6 = (void *)&addr;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = ip->port;
		memcpy(&in6->sin6_addr, ip->ip6, 16);
	}

	return get_addr_str(&addr);
}

static void server_signal_handler(int sig)
{
	putchar('\n');
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		g_server_ctx->stop = true;
		break;
	case SIGHUP:
		break;
	}
}

static int server_install_signal_handlers(struct server_ctx *ctx)
{
	struct sigaction sa = { .sa_handler = server_signal_handler };
	int ret;

	g_server_ctx = ctx;

	ret = sigaction(SIGINT, &sa, NULL);
	if (ret < 0)
		goto err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret < 0)
		goto err;
	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret < 0)
		goto err;

	/*
	 * Ignore SIGPIPE.
	 */
	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto err;

	return 0;
err:
	ret = -errno;
	g_server_ctx = NULL;
	perror("sigaction");
	return ret;
}

static int server_init_client_slots(struct server_ctx *ctx)
{
	ctx->clients_len = 1024;
	ctx->clients = calloc(ctx->clients_len, sizeof(struct client));
	if (!ctx->clients) {
		perror("calloc");
		return -ENOMEM;
	}

	return 0;
}

static int server_init_udp_socket(struct server_ctx *ctx)
{
	struct sockaddr_storage bind_addr;
	int ret;

	ret = fill_addr_storage(&bind_addr, BIND_ADDR, BIND_PORT);
	if (ret < 0)
		return ret;

	ret = create_udp_socket(bind_addr.ss_family, &bind_addr);
	if (ret < 0)
		return ret;

	ctx->udp_fd = ret;
	return 0;
}

static int poll_fd(int fd, short events, int timeout)
{
	struct pollfd fds = { .fd = fd, .events = events };
	int ret;

	ret = poll(&fds, 1, timeout);
	if (ret < 0) {
		ret = -errno;
		perror("poll");
		return ret;
	}

	return ret;
}

static int server_poll_udp(struct server_ctx *ctx)
{
	int ret;

	ret = poll_fd(ctx->udp_fd, POLLIN, POLL_TIMEOUT);
	if (ret < 0)
		return ret;

	if (ret == 0)
		return 0;

	return 1;
}

static int server_recv_udp(struct server_ctx *ctx)
{
	struct sockaddr *addr = (void *)&ctx->last_src;
	socklen_t addr_len = sizeof(ctx->last_src);
	int fd = ctx->udp_fd;
	ssize_t ret;

	memset(addr, 0, sizeof(ctx->last_src));
	ret = recvfrom(fd, &ctx->rpkt, sizeof(ctx->rpkt), 0, addr, &addr_len);
	if (ret < 0) {
		ret = -errno;
		perror("recvfrom");
		return ret;
	}

	ctx->rpkt_len = (uint16_t)ret;
	return 0;
}

static struct client *__server_get_client_by_sess_id(struct server_ctx *ctx,
						     char sess_id[32])
	__must_hold(&ctx->clients_lock)
{
	size_t i;

	for (i = 0; i < ctx->clients_len; i++) {
		if (!ctx->clients[i].is_used)
			continue;

		if (!memcmp(ctx->clients[i].sess_id, sess_id, 32))
			return &ctx->clients[i];
	}

	return NULL;
}

static struct client *server_get_client_by_sess_id(struct server_ctx *ctx,
						   char sess_id[32])
{
	struct client *cl;

	pthread_mutex_lock(&ctx->clients_lock);
	cl = __server_get_client_by_sess_id(ctx, sess_id);
	pthread_mutex_unlock(&ctx->clients_lock);
	return cl;
}

static struct client *__server_get_client_by_src(struct server_ctx *ctx,
						 struct sockaddr_storage *addr)
	__must_hold(&ctx->clients_lock)
{
	size_t i;

	for (i = 0; i < ctx->clients_len; i++) {
		if (!ctx->clients[i].is_used)
			continue;

		if (!memcmp(&ctx->clients[i].addr, addr, sizeof(*addr)))
			return &ctx->clients[i];
	}

	return NULL;
}

static int server_validate_pkt_connect(struct server_ctx *ctx)
{
	if (ctx->rpkt_len != CL_PKT_HDR_LEN + sizeof(struct cl_pkt_connect)) {
		printf("Invalid connect packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->last_src));
		return -EINVAL;
	}

	if (ctx->rpkt.len != sizeof(struct cl_pkt_connect)) {
		printf("Invalid connect packet length: %hu from %s (2)\n", ctx->rpkt.len, get_addr_str(&ctx->last_src));
		return -EINVAL;
	}

	return 0;
}

/*
 * Check whether the connect session is duplicate.
 */
static int server_connect_has_dup(struct server_ctx *ctx)
	__must_hold(&ctx->clients_lock)
{
	struct client *cl;

	cl = __server_get_client_by_sess_id(ctx, ctx->rpkt.connect.sess_id);
	if (cl) {
		printf("Session ID collision: %s (request from %s; used by %s)\n", ctx->rpkt.connect.sess_id, get_addr_str(&ctx->last_src), get_addr_str(&cl->addr));
		return -EEXIST;
	}

	cl = __server_get_client_by_src(ctx, &ctx->last_src);
	if (cl) {
		printf("Client already connected: %s (request from %s)\n", get_addr_str(&cl->addr), get_addr_str(&ctx->last_src));
		return -EEXIST;
	}

	return 0;
}

static struct client *__server_get_free_client_slot(struct server_ctx *ctx)
	__must_hold(&ctx->clients_lock)
{
	size_t i;

	for (i = 0; i < ctx->clients_len; i++) {
		if (!ctx->clients[i].is_used)
			return &ctx->clients[i];
	}

	return NULL;
}

static int server_send_pkt_session(struct server_ctx *ctx, struct client *cl)
{
	uint8_t src_ip[16] = { 0 };
	__be16 src_port = 0;
	uint8_t family;
	ssize_t ret;
	size_t len;

	if (cl->addr.ss_family == AF_INET) {
		struct sockaddr_in *in = (void *)&cl->addr;
		family = 4;
		src_port = in->sin_port;
		memcpy(src_ip, &in->sin_addr, 4);
	} else {
		struct sockaddr_in6 *in6 = (void *)&cl->addr;

		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			family = 4;
			memcpy(src_ip, &in6->sin6_addr.s6_addr[12], 4);
		} else {
			family = 6;
			memcpy(src_ip, &in6->sin6_addr, 16);
		}

		src_port = in6->sin6_port;
	}

	len = sr_prep_pkt_session(&ctx->spkt, family, src_ip, src_port, cl->sess_id);
	ret = sendto(ctx->udp_fd, &ctx->spkt, len, 0, (struct sockaddr *)&cl->addr, sizeof(cl->addr));
	if (ret < 0) {
		ret = errno;
		printf("Error sendto %s: %s\n", get_addr_str(&cl->addr), strerror(ret));
		return 0;
	}

	return 0;
}

static int server_handle_pkt_connect(struct server_ctx *ctx)
{
	struct client *cl;
	int ret = 0;

	if (server_validate_pkt_connect(ctx) < 0)
		return 0;

	pthread_mutex_lock(&ctx->clients_lock);

	ret = server_connect_has_dup(ctx);
	if (ret < 0)
		goto out;

	cl = __server_get_free_client_slot(ctx);
	if (!cl) {
		printf("Client slot is full: %s\n", get_addr_str(&ctx->last_src));
		goto out;
	}

	cl->is_used = true;
	cl->addr = ctx->last_src;
	memcpy(cl->sess_id, ctx->rpkt.connect.sess_id, 32);
	clock_gettime(CLOCK_MONOTONIC, &cl->last_action);
	printf("Client connected: %s (sess_id=%s)\n", get_addr_str(&cl->addr), cl->sess_id);
	ctx->nr_online_clients++;
out:
	pthread_mutex_unlock(&ctx->clients_lock);

	if (ret == 0)
		return server_send_pkt_session(ctx, cl);
	
	return 0;
}

static size_t server_construct_peer_list(struct server_ctx *ctx,
					 struct client *cl,
					 struct peer *peers)
	__must_hold(&ctx->clients_lock)
{
	uint16_t nr_online = ctx->nr_online_clients;
	size_t i, j;

	for (i = 0, j = 0; i < ctx->clients_len; i++) {
		if (!ctx->clients[i].is_used)
			continue;

		if (j >= nr_online)
			break;

		/*
		 * Skip the client itself.
		 */
		if (ss_addr_eq(&ctx->clients[i].addr, &cl->addr))
			continue;

		if (ctx->clients[i].addr.ss_family == AF_INET) {
			struct sockaddr_in *in = (void *)&ctx->clients[i].addr;
			peers[j].ip.family = 4;
			peers[j].ip.port = in->sin_port;
			peers[j].ip.__pad = 0;
			memcpy(peers[j].ip.ip4, &in->sin_addr, 4);
		} else {
			struct sockaddr_in6 *in6 = (void *)&ctx->clients[i].addr;
			if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
				peers[j].ip.family = 4;
				memcpy(peers[j].ip.ip4, &in6->sin6_addr.s6_addr[12], 4);
			} else {
				peers[j].ip.family = 6;
				memcpy(peers[j].ip.ip6, &in6->sin6_addr, 16);
			}

			peers[j].ip.port = in6->sin6_port;
			peers[j].ip.__pad = 0;
		}

		memcpy(peers[j].sess_id, ctx->clients[i].sess_id, 32);
		j++;
	}

	return j;
}

static int server_send_peer_list(struct server_ctx *ctx, struct client *cl)
{
	uint16_t nr_online;
	struct peer *peers;
	ssize_t ret;
	size_t len;

	pthread_mutex_lock(&ctx->clients_lock);
	nr_online = ctx->nr_online_clients;
	peers = calloc(nr_online, sizeof(struct peer));
	if (!peers) {
		perror("calloc");
		pthread_mutex_unlock(&ctx->clients_lock);
		return 0;
	}
	len = server_construct_peer_list(ctx, cl, peers);
	pthread_mutex_unlock(&ctx->clients_lock);

	len = sr_prep_pkt_peer_list(&ctx->spkt, len, peers);
	ret = sendto(ctx->udp_fd, &ctx->spkt, len, 0, (struct sockaddr *)&cl->addr, sizeof(cl->addr));
	if (ret < 0) {
		ret = errno;
		printf("Error sendto %s: %s\n", get_addr_str(&cl->addr), strerror(ret));
	}

	free(peers);
	return 0;
}

static int server_handle_pkt_get_peers(struct server_ctx *ctx)
{
	struct client *cl;

	if (ctx->rpkt_len != CL_PKT_HDR_LEN + 32u) {
		printf("Invalid get_peers packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->last_src));
		return 0;
	}

	cl = server_get_client_by_sess_id(ctx, ctx->rpkt.sess_id);
	if (!cl) {
		printf("Invalid sess_id in a get_peers packet: %s (from %s)\n", ctx->rpkt.sess_id, get_addr_str(&ctx->last_src));
		return 0;
	}

	if (!ss_addr_eq(&cl->addr, &ctx->last_src)) {
		printf("Invalid source address in a get_peers packet: %s (from %s)\n", get_addr_str(&ctx->last_src), get_addr_str(&cl->addr));
		return 0;
	}

	return server_send_peer_list(ctx, cl);
}

static int server_handle_pkt_close(struct server_ctx *ctx)
{
	struct client *cl;

	if (ctx->rpkt_len != CL_PKT_HDR_LEN) {
		printf("Invalid close packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->last_src));
		return 0;
	}

	pthread_mutex_lock(&ctx->clients_lock);
	cl = __server_get_client_by_src(ctx, &ctx->last_src);
	if (!cl) {
		pthread_mutex_unlock(&ctx->clients_lock);
		return 0;
	}

	printf("Client disconnected: %s (sess_id=%s)\n", get_addr_str(&cl->addr), cl->sess_id);

	cl->is_used = false;
	ctx->nr_online_clients--;
	pthread_mutex_unlock(&ctx->clients_lock);
	return 0;
}

static int server_handle_pkt(struct server_ctx *ctx)
{
	/*
	 * The packet size must be at least CL_PKT_HDR_LEN bytes in length.
	 */
	if (ctx->rpkt_len < CL_PKT_HDR_LEN) {
		printf("Invalid packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->last_src));
		return 0;
	}

	/*
	 * Convert the packet length to host byte order.
	 */
	ctx->rpkt.len = ntohs(ctx->rpkt.len);

	switch (ctx->rpkt.type) {
	case CL_PKT_CONNECT:
		printf("Received connect packet from %s\n", get_addr_str(&ctx->last_src));
		return server_handle_pkt_connect(ctx);
	case CL_PKT_GET_PEER_LIST:
		printf("Received get_peers packet from %s\n", get_addr_str(&ctx->last_src));
		return server_handle_pkt_get_peers(ctx);
	case CL_PKT_CLOSE:
		printf("Received close packet from %s\n", get_addr_str(&ctx->last_src));
		return server_handle_pkt_close(ctx);
	default:
		printf("Unknown packet type %hhu from %s\n", ctx->rpkt.type, get_addr_str(&ctx->last_src));
		return 0;
	}

	return 0;
}

static int server_handle_events(struct server_ctx *ctx)
{
	int ret;

	/*
	 * server_poll_udp() returns 0 if it times out.
	 */
	ret = server_poll_udp(ctx);
	if (ret <= 0)
		return ret;

	ret = server_recv_udp(ctx);
	if (ret < 0)
		return ret;

	return server_handle_pkt(ctx);
}

static int server_run_event_loop(struct server_ctx *ctx)
{
	int ret;

	while (!ctx->stop) {
		ret = server_handle_events(ctx);
		if (ret < 0) {
			ctx->stop = true;
			break;
		}
	}

	return 0;
}

static void server_destroy_ctx(struct server_ctx *ctx)
{
	if (ctx->udp_fd >= 0)
		close(ctx->udp_fd);

	free(ctx->clients);
	pthread_mutex_destroy(&ctx->clients_lock);
}

static int run_server(int argc, char *argv[])
{
	struct server_ctx *ctx;
	int ret;

	(void)argc;
	(void)argv;

	ctx = calloc(1u, sizeof(struct server_ctx));
	if (!ctx) {
		perror("calloc");
		return -ENOMEM;
	}

	ret = pthread_mutex_init(&ctx->clients_lock, NULL);
	if (ret < 0) {
		errno = ret;
		perror("pthread_mutex_init");
		free(ctx);
		return -ret;
	}

	ctx->udp_fd = -1;
	ret = server_install_signal_handlers(ctx);
	if (ret < 0)
		goto out;

	ret = server_init_client_slots(ctx);
	if (ret < 0)
		goto out;

	ret = server_init_udp_socket(ctx);
	if (ret < 0)
		goto out;

	ret = server_run_event_loop(ctx);

out:
	server_destroy_ctx(ctx);
	free(ctx);
	return ret;
}

static void client_signal_handler(int sig)
{
	putchar('\n');
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		g_client_ctx->stop = true;
		break;
	case SIGHUP:
		break;
	}
}

static int client_install_signal_handlers(struct client_ctx *ctx)
{
	struct sigaction sa = { .sa_handler = client_signal_handler };
	int ret;

	g_client_ctx = ctx;

	ret = sigaction(SIGINT, &sa, NULL);
	if (ret < 0)
		goto err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret < 0)
		goto err;
	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret < 0)
		goto err;

	/*
	 * Ignore SIGPIPE.
	 */
	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto err;

	return 0;
err:
	ret = -errno;
	g_client_ctx = NULL;
	perror("sigaction");
	return ret;
}

static int client_init_udp_socket(struct client_ctx *ctx,
				  const char *server_addr,
				  const char *server_port)
{
	struct sockaddr_storage *addr = &ctx->server_addr;
	int ret;

	ret = fill_addr_storage(addr, server_addr, atoi(server_port));
	if (ret < 0)
		return ret;

	ret = create_udp_socket(addr->ss_family, NULL);
	if (ret < 0)
		return ret;

	ctx->udp_fd = ret;
	return 0;
}

static char *trim(char *str)
{
	char *end;

	while (*str == ' ' || *str == '\t')
		str++;

	end = str + strlen(str) - 1;
	while (end > str && (*end == ' ' || *end == '\t'))
		end--;

	*(end + 1) = '\0';
	return str;
}

static int client_handle_cmd_help(struct client_ctx *ctx)
{
	(void)ctx;

	printf("\n");
	printf("   connect                 Connect to the server\n");
	printf("   pconnect [sess_id]      Connect to the peer with a specific session ID\n");
	printf("   help                    Show this help\n");
	printf("   exit                    Exit the program\n");
	printf("   status                  Show the current status\n");
	printf("   get_peers               Get available peers\n");
	printf("\n");
	return 0;
}

static int client_handle_cmd_status(struct client_ctx *ctx)
{
	const char *tmp;

	printf("ctx->udp_fd       = %d\n", ctx->udp_fd);
	printf("ctx->is_connected = %s\n", ctx->is_connected ? "true" : "false");
	tmp = get_addr_str(&ctx->server_addr);
	printf("ctx->server_addr  = %s\n", tmp ? tmp : "(null)");
	tmp = get_addr_str(&ctx->local_src);
	printf("ctx->local_src    = %s\n", tmp ? tmp : "(null)");
	tmp = get_addr_str(&ctx->public_src);
	printf("ctx->public_src   = %s\n", tmp ? tmp : "(null)");
	tmp = get_addr_str(&ctx->peer_addr);
	printf("ctx->peer_addr    = %s\n", tmp ? tmp : "(null)");
	printf("ctx->sess_id      = %s\n", ctx->sess_id[0] ? ctx->sess_id : "(null)");
	return 0;
}

static int client_get_self_src(struct client_ctx *ctx, uint8_t *family,
			       uint8_t *ip, __be16 *port)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	int ret;

	memset(&addr, 0, sizeof(addr));
	ret = getsockname(ctx->udp_fd, (struct sockaddr *)&addr, &addrlen);
	if (ret < 0) {
		ret = -errno;
		perror("getsockname");
		return ret;
	}

	if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (void *)&addr;
		*port = in6->sin6_port;
		*family = 6;
		memcpy(ip, &in6->sin6_addr, 16);
	} else {
		struct sockaddr_in *in = (void *)&addr;
		*port = in->sin_port;
		*family = 4;
		memcpy(ip, &in->sin_addr, 4);
	}

	ctx->local_src = addr;
	return 0;
}

static void gen_rand_uid(char *sess_id, size_t len)
{
	static const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ___...";
	size_t i;

	for (i = 0; i < len - 1; i++)
		sess_id[i] = chars[rand() % (sizeof(chars) - 1)];

	sess_id[len - 1] = '\0';
}

static int client_recv_pkt(struct client_ctx *ctx, int timeout)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	ssize_t ret;

	ret = poll_fd(ctx->udp_fd, POLLIN, timeout);
	if (ret < 0)
		return ret;

	if (ret == 0)
		return -ETIMEDOUT;

	do {
		ret = recvfrom(ctx->udp_fd, &ctx->rpkt, sizeof(ctx->rpkt), 0, (struct sockaddr *)&addr, &addrlen);
		if (ret < 0) {
			ret = -errno;
			perror("recv");
			return ret;
		}
	} while (!ss_addr_eq(&addr, &ctx->server_addr));

	ctx->rpkt_len = (uint16_t)ret;
	if (ctx->rpkt_len < SR_PKT_HDR_LEN) {
		printf("Invalid packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->server_addr));
		return -EINVAL;
	}

	ctx->rpkt.len = ntohs(ctx->rpkt.len);
	return 0;
}

static int client_validate_pkt_sess(struct client_ctx *ctx)
{
	if (ctx->rpkt_len != SR_PKT_HDR_LEN + sizeof(struct sr_pkt_session)) {
		printf("Invalid session packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->server_addr));
		return -EINVAL;
	}

	if (ctx->rpkt.len != sizeof(struct sr_pkt_session)) {
		printf("Invalid session packet length: %hu from %s (2)\n", ctx->rpkt.len, get_addr_str(&ctx->server_addr));
		return -EINVAL;
	}

	return 0;
}

static int client_wait_for_sess_pkt(struct client_ctx *ctx)
{
	int ret;

	ret = client_recv_pkt(ctx, POLL_TIMEOUT);
	if (ret < 0)
		return ret;

	ret = client_validate_pkt_sess(ctx);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			printf("Timed out waiting for session packet\n");
		return ret;
	}

	if (ctx->rpkt.session.public_ip.family == 4) {
		struct sockaddr_in *in = (void *)&ctx->public_src;
		in->sin_family = AF_INET;
		in->sin_port = ctx->rpkt.session.public_ip.port;
		memcpy(&in->sin_addr, ctx->rpkt.session.public_ip.ip4, 4);
	} else {
		struct sockaddr_in6 *in6 = (void *)&ctx->public_src;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = ctx->rpkt.session.public_ip.port;
		memcpy(&in6->sin6_addr, ctx->rpkt.session.public_ip.ip6, 16);
	}

	printf("Connected to the server!\n");
	printf("Your local source is  : %s\n", get_addr_str(&ctx->local_src));
	printf("Your public source is : %s\n", get_addr_str(&ctx->public_src));
	printf("Your session ID is    : %s\n", ctx->sess_id);
	if (ss_addr_eq(&ctx->local_src, &ctx->public_src))
		printf("You're not behind a NAT\n");
	else
		printf("You're behind a NAT\n");

	ctx->is_connected = true;
	return 0;
}

static int client_handle_cmd_connect(struct client_ctx *ctx)
{
	uint8_t family = 0, local_ip[16] = { 0 };
	__be16 local_sport = 0;
	ssize_t ret;
	size_t len;

	if (ctx->is_connected) {
		printf("Already connected!\n");
		return 0;
	}

	printf("Connecting to %s...\n", get_addr_str(&ctx->server_addr));
	ret = client_get_self_src(ctx, &family, local_ip, &local_sport);
	if (ret < 0)
		return ret;

	gen_rand_uid(ctx->sess_id, sizeof(ctx->sess_id));
	len = cl_prep_pkt_connect(&ctx->spkt, family, local_ip, local_sport, ctx->sess_id);
	ret = sendto(ctx->udp_fd, &ctx->spkt, len, 0, (struct sockaddr *)&ctx->server_addr, sizeof(ctx->server_addr));
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	ret = client_get_self_src(ctx, &family, local_ip, &local_sport);
	if (ret < 0)
		return ret;

	ret = client_wait_for_sess_pkt(ctx);
	if (ret < 0)
		return ret;

	return 0;
}

static struct peer *client_get_peer_by_sess_id(struct client_ctx *ctx,
					       const char sess_id[32])
{
	uint8_t i;

	for (i = 0; i < ctx->nr_peers; i++) {
		if (!strncmp(ctx->peers[i].sess_id, sess_id, 32))
			return &ctx->peers[i];
	}

	return NULL;
}

static int client_connect_peer(struct client_ctx *ctx, const char sess_id[32])
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct peer *peer;
	ssize_t ret;

	peer = client_get_peer_by_sess_id(ctx, sess_id);
	if (!peer) {
		printf("Cannot find peer with sess_id: %s\n", sess_id);
		printf("Type \"get_peers\" to get available peers\n");
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	if (peer->ip.family == 4) {
		struct sockaddr_in *in = (void *)&addr;
		in->sin_family = AF_INET;
		in->sin_port = peer->ip.port;
		memcpy(&in->sin_addr, peer->ip.ip4, 4);
		addrlen = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *in6 = (void *)&addr;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = peer->ip.port;
		memcpy(&in6->sin6_addr, peer->ip.ip6, 16);
		addrlen = sizeof(struct sockaddr_in6);
	}

	while (1) {
		do {
			printf("Sending initial packet to %s...\n", get_addr_str(&addr));
			ret = sendto(ctx->udp_fd, &ctx->spkt, sizeof(ctx->spkt), 0, (struct sockaddr *)&addr, addrlen);
			if (ret < 0) {
				ret = -errno;
				perror("sendto");
				return ret;
			}

			printf("Waiting for response from %s...\n", get_addr_str(&addr));
			ret = poll_fd(ctx->udp_fd, POLLIN, 2000);
		} while (ret == 0);

		if (ret < 0)
			return 0;

		memset(&addr, 0, sizeof(addr));
		ret = recvfrom(ctx->udp_fd, &ctx->rpkt, sizeof(ctx->rpkt), 0, (struct sockaddr *)&addr, &addrlen);
		if (ret < 0) {
			ret = -errno;
			perror("recvfrom");
			return ret;
		}
	}

	printf("Received response from %s\n", get_addr_str(&addr));
	ctx->peer_addr = addr;
	return 0;
}

static int client_handle_cmd_pconnect(struct client_ctx *ctx)
{
	/*
	 * Expected pattern is:
	 * pconnect [sess_id]
	 */
	char *cmd = ctx->cmd_buf;
	char *sess_id;

	if (!ctx->is_connected) {
		printf("Not connected, please connect first!\n");
		return 0;
	}

	sess_id = trim(cmd + strlen("pconnect"));
	if (!sess_id[0]) {
		printf("Usage: pconnect [sess_id]\n");
		return 0;
	}

	return client_connect_peer(ctx, sess_id);
}

static int client_wait_for_peer_list_pkt(struct client_ctx *ctx)
{
	struct peer *peers;
	uint8_t i;
	int ret;

	ret = client_recv_pkt(ctx, POLL_TIMEOUT);
	if (ret < 0) {
		if (ret == -ETIMEDOUT) {
			printf("Timed out waiting for peer list packet\n");
			return 0;
		}
		return ret;
	}

	if (ctx->rpkt.type != SR_PKT_PEER_LIST) {
		printf("Invalid packet type: %hhu from %s\n", ctx->rpkt.type, get_addr_str(&ctx->server_addr));
		return -EINVAL;
	}

	if (ctx->rpkt_len < SR_PKT_HDR_LEN + sizeof(struct sr_pkt_peer_list)) {
		printf("Invalid peer list packet length: %hu from %s\n", ctx->rpkt_len, get_addr_str(&ctx->server_addr));
		return -EINVAL;
	}

	if (ctx->rpkt.len != sizeof(struct sr_pkt_peer_list) + ctx->rpkt.peer_list.nr_peers * sizeof(struct peer)) {
		printf("Invalid peer list packet length: %hu from %s (2)\n", ctx->rpkt.len, get_addr_str(&ctx->server_addr));
		return -EINVAL;
	}

	if (ctx->rpkt.peer_list.nr_peers > 0) {
		peers = realloc(ctx->peers, ctx->rpkt.peer_list.nr_peers * sizeof(struct peer));
		if (!peers) {
			perror("realloc");
			return 0;
		}
		ctx->peers = peers;
	}

	ctx->nr_peers = ctx->rpkt.peer_list.nr_peers;
	printf("Available peers: %hhu\n", ctx->nr_peers);
	for (i = 0; i < ctx->nr_peers; i++) {
		ctx->peers[i] = ctx->rpkt.peer_list.peers[i];
		printf("Peer %hhu: %s (sess_id: %s)\n", i, get_ip_pkt_str(&ctx->peers[i].ip), ctx->peers[i].sess_id);
	}

	return 0;
}

static int client_handle_cmd_get_peers(struct client_ctx *ctx)
{
	ssize_t ret;
	size_t len;

	if (!ctx->is_connected) {
		printf("Not connected, please connect first!\n");
		return 0;
	}

	len = cl_prep_pkt_get_peers(&ctx->spkt, ctx->sess_id);
	ret = sendto(ctx->udp_fd, &ctx->spkt, len, 0, (struct sockaddr *)&ctx->server_addr, sizeof(ctx->server_addr));
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	ret = client_wait_for_peer_list_pkt(ctx);
	if (ret < 0)
		return ret;

	return 0;
}

static int client_handle_cmd(struct client_ctx *ctx)
{
	char *cmd = trim(ctx->cmd_buf);

	if (!strcmp(cmd, "exit")) {
		/*
		 * TODO(ammarfaizi2):
		 * Send a close packet if the session is connection.
		 */
		ctx->stop = true;
		return 0;
	}

	if (!strcmp(cmd, "help"))
		return client_handle_cmd_help(ctx);

	if (!strcmp(cmd, "status"))
		return client_handle_cmd_status(ctx);

	if (!strcmp(cmd, "connect"))
		return client_handle_cmd_connect(ctx);

	if (!strncmp(cmd, "pconnect", strlen("pconnect")))
		return client_handle_cmd_pconnect(ctx);

	if (!strcmp(cmd, "get_peers"))
		return client_handle_cmd_get_peers(ctx);

	printf("Unknown command: %s\n", cmd);
	printf("Type \"help\" for help\n");
	return 0;
}

static int client_handle_events(struct client_ctx *ctx)
{
	size_t len;
	char *ret;

	printf("gwp2p> ");
	ret = fgets(ctx->cmd_buf, sizeof(ctx->cmd_buf), stdin);
	if (!ret) {
		ctx->stop = true;
		return 0;
	}

	len = strlen(ctx->cmd_buf);
	if (len == 0)
		return 0;

	if (ctx->cmd_buf[len - 1] == '\n') {
		ctx->cmd_buf[len - 1] = '\0';
		len--;
	}

	if (len == 0)
		return 0;

	return client_handle_cmd(ctx);
}

static int client_run_event_loop(struct client_ctx *ctx)
{
	int ret;

	printf("Welcome to gwp2p shell!\n");
	while (!ctx->stop) {
		ret = client_handle_events(ctx);
		if (ret < 0) {
			ctx->stop = true;
			break;
		}
	}

	return 0;
}

static void client_destroy_ctx(struct client_ctx *ctx)
{
	if (ctx->is_connected) {
		ssize_t ret;
		size_t len;

		printf("Disconnecting from the server...\n");
		len = cl_prep_pkt_close(&ctx->spkt);
		ret = sendto(ctx->udp_fd, &ctx->spkt, len, 0, (struct sockaddr *)&ctx->server_addr, sizeof(ctx->server_addr));
		if (ret < 0) {
			ret = -errno;
			perror("send");
		}
	}


	if (ctx->udp_fd >= 0)
		close(ctx->udp_fd);
}

static int run_client(int argc, char *argv[])
{
	struct client_ctx *ctx;
	int ret;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s client <server_addr> <server_port>\n", argv[0]);
		return -EINVAL;
	}

	ctx = calloc(1u, sizeof(struct client_ctx));
	if (!ctx) {
		perror("calloc");
		return -ENOMEM;
	}

	ctx->udp_fd = -1;
	ret = client_install_signal_handlers(ctx);
	if (ret < 0)
		goto out;

	ret = client_init_udp_socket(ctx, argv[2], argv[3]);
	if (ret < 0)
		goto out;

	ret = client_run_event_loop(ctx);

out:
	client_destroy_ctx(ctx);
	free(ctx);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [server|client]\n", argv[0]);
		return 0;
	}

	srand(time(NULL));

	if (!strcmp(argv[1], "server")) {
		ret = -run_server(argc, argv);
	} else if (!strcmp(argv[1], "client")) {
		ret = -run_client(argc, argv);
	} else {
		fprintf(stderr, "Invalid argument: %s\n", argv[1]);
		fprintf(stderr, "Usage: %s [server|client]\n", argv[0]);
		ret = EINVAL;
	}

	return ret;
}
