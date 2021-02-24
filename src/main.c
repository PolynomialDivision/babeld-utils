#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <owipcalc.h>

// static struct blob_buf b;
static struct ubus_context *ctx;

enum {
  ROUTE_IPV4,
  ROUTE_IPV6,
  __ROUTE_MAX,
};

static const struct blobmsg_policy babeld_policy[__ROUTE_MAX] = {
    [ROUTE_IPV4] = {.name = "IPv4", .type = BLOBMSG_TYPE_TABLE},
    [ROUTE_IPV6] = {.name = "IPv6", .type = BLOBMSG_TYPE_TABLE},
};

static void exit_utils() {
  ubus_free(ctx);
  uloop_done();
}

static void ubus_get_routes_cb(struct ubus_request *req, int type,
                               struct blob_attr *msg) {
  struct blob_attr *tb[__ROUTE_MAX];

  blobmsg_parse(babeld_policy, __ROUTE_MAX, tb, blob_data(msg), blob_len(msg));
  if (!tb[ROUTE_IPV6])
    return;

  struct blob_attr *attr;
  struct blobmsg_hdr *hdr;
  int len;
  __blob_for_each_attr(attr, blobmsg_data(tb[ROUTE_IPV6]), len) {
    hdr = blob_data(attr);
    char *dst_prefix = (char *)hdr->name;

    printf("Dst Prefix: %s\n", dst_prefix);

    //struct cidr *b;
    //b = cidr_parse6(dst_prefix);
  }

  exit_utils();
}

static int handle_routes() {
  int ret;  

  u_int32_t id;
  if (ubus_lookup_id(ctx, "babeld", &id)) {
    fprintf(stderr, "Failed to look up test object for %s\n", "babeld");
    return -1;
  }

  int timeout = 1;
  ret = ubus_invoke(ctx, id, "get_routes", NULL, ubus_get_routes_cb, NULL,
                    timeout * 1000);
  if (ret)
    fprintf(stderr, "Failed to invoke: %s\n", ubus_strerror(ret));

  return ret;
}

int main(int argc, char **argv) {
  const char *ubus_socket = NULL;

  uloop_init();

  ctx = ubus_connect(ubus_socket);
  if (!ctx) {
    fprintf(stderr, "Failed to connect to ubus\n");
    return -1;
  }

  handle_routes();

  uloop_run();

  return 0;
}
