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

//static struct blob_buf b;
static struct ubus_context *ctx;

/*
enum {
  __ROUTE_MAX,
};

static const struct blobmsg_policy babeld_policy[__ROUTE_MAX] = {
    // [ROUTE_IPV6] = {.name = "IPv6", .type = BLOBMSG_TYPE_STRING},
};
*/

static void exit_utils() {
  ubus_free(ctx);
  uloop_done();
}

static void ubus_get_routes_cb(struct ubus_request *req, int type,
                               struct blob_attr *msg) {
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
