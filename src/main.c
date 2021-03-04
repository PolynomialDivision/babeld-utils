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

#define MAX_IPS 30

struct ids_list_entry {
  struct list_head list;
  char *id;
  char *gw_a;
  char *ips[MAX_IPS];
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
    [ROUTE_ROUTE_METRIC] = {.name = "route_metric", .type = BLOBMSG_TYPE_INT32},
    [ROUTE_ID] = {.name = "id", .type = BLOBMSG_TYPE_STRING},
};

static void exit_utils() {
  ubus_free(ctx);
  exit(0);
}

static void clean_idlist(struct list_head *head) {
  struct ids_list_entry *listentry, *tmp;
  list_for_each_entry_safe(listentry, tmp, head, list) { free(listentry); }
}

static void print_idlist(struct list_head *head) {
  struct ids_list_entry *listentry;
  list_for_each_entry(listentry, head, list) {
    printf("ID: %s IPs:", listentry->id);
    for (int i = 0; i < MAX_IPS; i++) {
      if (listentry->ips[i]) {
        printf(" %s", listentry->ips[i]);
      }
    }
    printf("\n");
  }
}

static int id_in_idlist(struct list_head *head, char *id) {
  struct ids_list_entry *listentry;
  list_for_each_entry(listentry, head, list) {
    if (!strcmp(listentry->id, id)) {
      return 1;
    }
  }

  return 0;
}

static int add_ip_to_idlist(struct list_head *head, char *id, char *ip) {
  struct ids_list_entry *listentry;
  list_for_each_entry(listentry, head, list) {
    if (!strcmp(listentry->id, id)) {
      for (int i = 0; i < MAX_IPS; i++) {
        if (listentry->ips[i] == NULL) {
          listentry->ips[i] = ip;
          return 1;
        }
      }
    }
  }

  return 0;
}

static void ubus_get_gateways_cb(struct ubus_request *req, int type,
                                 struct blob_attr *msg) {
  struct blob_attr *tb[__ROUTE_TABLE_MAX];
  struct blob_attr *attr;
  struct blobmsg_hdr *hdr;
  int len;

  LIST_HEAD(idlist);

  blobmsg_parse(babeld_policy, __ROUTE_TABLE_MAX, tb, blob_data(msg),
                blob_len(msg));

  if (!tb[ROUTE_TABLE_IPV6]) {
    return;
  }

  // search for ids that announce a gateway
  len = blobmsg_data_len(tb[ROUTE_TABLE_IPV6]);
  __blob_for_each_attr(attr, blobmsg_data(tb[ROUTE_TABLE_IPV6]), len) {
    hdr = blob_data(attr);
    char *dst_prefix = (char *)hdr->name;

    if (!strncmp(dst_prefix, "::/0", 4)) { // for now we only search for ipv6
      struct blob_attr *tb_route[__ROUTE_MAX];
      blobmsg_parse(route_policy, __ROUTE_MAX, tb_route, blobmsg_data(attr),
                    blobmsg_data_len(attr));

      int metric = 0;
      if (tb_route[ROUTE_ROUTE_METRIC]) {
        metric = blobmsg_get_u32(tb_route[ROUTE_ROUTE_METRIC]);
      }

      if (metric < refmetric) {
        char *id_string = blobmsg_get_string(tb_route[ROUTE_ID]);
        if (!id_in_idlist(&idlist, id_string)) {
          struct ids_list_entry *id = calloc(1, sizeof(struct ids_list_entry));
          id->id = id_string;
          list_add(&id->list, &idlist);
        }
      }
    }
  }

  // search for ips assigned to a gateway id
  len = blobmsg_data_len(tb[ROUTE_TABLE_IPV6]);
  __blob_for_each_attr(attr, blobmsg_data(tb[ROUTE_TABLE_IPV6]), len) {
    struct blob_attr *tb_route[__ROUTE_MAX];
    blobmsg_parse(route_policy, __ROUTE_MAX, tb_route, blobmsg_data(attr),
                  blobmsg_data_len(attr));
    hdr = blob_data(attr);
    char *dst_prefix = (char *)hdr->name;
    if (strncmp(dst_prefix, "::/0", 4)) {
      char *id_string = blobmsg_get_string(tb_route[ROUTE_ID]);
      int metric = blobmsg_get_u32(tb_route[ROUTE_ROUTE_METRIC]);
      if (metric < refmetric) {
        if (id_in_idlist(&idlist, id_string)) {
          add_ip_to_idlist(&idlist, id_string, dst_prefix);
        }
      }
    }
  }

  // output
  print_idlist(&idlist);

  // cleanup
  clean_idlist(&idlist);

  exit_utils();
}

static int handle_gateways() {
  u_int32_t id;
  int ret;
  int timeout = 1;

  if (ubus_lookup_id(ctx, "babeld", &id)) {
    fprintf(stderr, "Failed to look up test object for %s\n", "babeld");
    return -1;
  }

  blob_buf_init(&b, 0);
  ret = ubus_invoke(ctx, id, "get_routes", b.head, ubus_get_gateways_cb, NULL,
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

static void print_help() {
  printf("Usage: babeld-utils [CMD]\n");
  printf("\t\t--gateways [metric]\tsearch for gateway ips\n");
  exit_utils();
}

int main(int argc, char **argv) {
  int opt;
  enum opt {
    OPT_GATEWAYS,
  };
  static const struct option longopts[] = {
      {.name = "gateways", .has_arg = required_argument, .val = OPT_GATEWAYS},
  };

  init_ubus();

  int option_index = 0;
  while ((opt = getopt_long(argc, argv, "f", longopts, &option_index)) != -1) {
    switch (opt) {
    case OPT_GATEWAYS:
      refmetric = atoi(optarg);
      handle_gateways();
    default:
      print_help();
    }
  }

  return 0;
}
