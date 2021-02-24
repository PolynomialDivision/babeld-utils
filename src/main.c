#include <getopt.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <owipcalc.h>

static struct blob_buf b;
static struct ubus_context *ctx;

int refmetric = 0;

struct ids_list_entry {
  struct list_head list;
  char *id;
};

enum {
  ROUTE_TABLE_IPV4,
  ROUTE_TABLE_IPV6,
  __ROUTE_TABLE_MAX,
};

static const struct blobmsg_policy babeld_policy[__ROUTE_TABLE_MAX] = {
    [ROUTE_TABLE_IPV4] = {.name = "IPv4", .type = BLOBMSG_TYPE_TABLE},
    [ROUTE_TABLE_IPV6] = {.name = "IPv6", .type = BLOBMSG_TYPE_TABLE},
};

enum {
  ROUTE_SRC_PREFIX,
  ROUTE_ROUTE_METRIC,
  ROUTE_ID,
  __ROUTE_MAX,
};

static const struct blobmsg_policy route_policy[__ROUTE_MAX] = {
    [ROUTE_SRC_PREFIX] = {.name = "src-prefix", .type = BLOBMSG_TYPE_STRING},
    [ROUTE_ROUTE_METRIC] = {.name = "route_metric",
                            .type = BLOBMSG_TYPE_STRING},
    [ROUTE_ID] = {.name = "id", .type = BLOBMSG_TYPE_STRING},
};

static void exit_utils() {
  uloop_done();
  exit(0);
}

static void ubus_get_routes_cb(struct ubus_request *req, int type,
                               struct blob_attr *msg) {
  struct blob_attr *tb[__ROUTE_TABLE_MAX];
  LIST_HEAD(idlist);

  blobmsg_parse(babeld_policy, __ROUTE_TABLE_MAX, tb, blob_data(msg),
                blob_len(msg));

  if (!tb[ROUTE_TABLE_IPV6]) {
    return;
  }

  struct blob_attr *attr;
  struct blobmsg_hdr *hdr;
  int len = blobmsg_data_len(tb[ROUTE_TABLE_IPV6]);
  __blob_for_each_attr(attr, blobmsg_data(tb[ROUTE_TABLE_IPV6]), len) {
    hdr = blob_data(attr);
    char *dst_prefix = (char *)hdr->name;

    if (!strncmp(dst_prefix, "::/0", 4)) {
      printf("Gateway Announcent!\n");
    } else {
      printf("No Gateway!\n");
    }

    printf("Dst Prefix: %s\n", dst_prefix);
    // struct cidr *b;
    // b = cidr_parse6(dst_prefix);

    struct blob_attr *tb_route[__ROUTE_MAX];
    blobmsg_parse(route_policy, __ROUTE_MAX, tb_route, blobmsg_data(attr),
                  blobmsg_data_len(attr));
    int metric = blobmsg_get_u32(tb_route[ROUTE_ROUTE_METRIC]);
    if (metric < refmetric) {
      struct ids_list_entry *id = calloc(1, sizeof(struct ids_list_entry));
      printf("id: %s\n", blobmsg_get_string(tb_route[ROUTE_ID]));
      id->id = blobmsg_get_string(tb_route[ROUTE_ID]);
      list_add(&id->list, &idlist);
    }
  }

  exit_utils();
}

static int handle_routes() {
  u_int32_t id;
  int ret;
  int timeout = 1;

  if (ubus_lookup_id(ctx, "babeld", &id)) {
    fprintf(stderr, "Failed to look up test object for %s\n", "babeld");
    return -1;
  }

  blob_buf_init(&b, 0);
  ret = ubus_invoke(ctx, id, "get_routes", b.head, ubus_get_routes_cb, NULL,
                    timeout * 1000);
  if (ret)
    fprintf(stderr, "Failed to invoke: %s\n", ubus_strerror(ret));

  return ret;
}

static int init_ubus() {
  const char *ubus_socket = NULL;

  uloop_init();

  ctx = ubus_connect(ubus_socket);
  if (!ctx) {
    fprintf(stderr, "Failed to connect to ubus\n");
    return -1;
  }

  ubus_add_uloop(ctx);

  return 0;
}

int main(int argc, char **argv) {
  int opt;
  enum opt {
    OPT_GATEWAYS,
  };
  static const struct option longopts[] = {
      {.name = "gateways", .has_arg = required_argument, .val = OPT_GATEWAYS},
      {},
  };

  init_ubus();

  int option_index = 0;
  while ((opt = getopt_long(argc, argv, "f", longopts, &option_index)) != -1) {
    switch (opt) {
    case OPT_GATEWAYS:
      refmetric = atoi(optarg);
      handle_routes();
    default:
      return 1;
    }
  }

  uloop_run();

  ubus_free(ctx);

  return 0;
}
