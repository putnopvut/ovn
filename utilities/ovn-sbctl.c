/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "colors.h"
#include "command-line.h"
#include "compiler.h"
#include "db-ctl-base.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/shash.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "ovsdb-data.h"
#include "ovsdb-idl.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "sset.h"
#include "stream-ssl.h"
#include "stream.h"
#include "table.h"
#include "timeval.h"
#include "util.h"
#include "svec.h"
#include "ovn/actions.h"

VLOG_DEFINE_THIS_MODULE(sbctl);

struct sbctl_context;

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* --timeout: Time to wait for a connection to 'db'. */
static unsigned int timeout;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* The IDL we're using and the current transaction, if any.
 * This is for use by sbctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;
OVS_NO_RETURN static void sbctl_exit(int status);

/* --leader-only, --no-leader-only: Only accept the leader in a cluster. */
static int leader_only = true;

static void sbctl_cmd_init(void);
OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[], struct shash *local_options);
static void run_prerequisites(struct ctl_command[], size_t n_commands,
                              struct ovsdb_idl *);
static bool do_sbctl(const char *args, struct ctl_command *, size_t n,
                     struct ovsdb_idl *);

int
main(int argc, char *argv[])
{
    struct ovsdb_idl *idl;
    struct ctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;

    ovn_set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:warn");

    sbctl_cmd_init();

    /* Check if options are set via env var. */
    char **argv_ = ovs_cmdl_env_parse_all(&argc, argv,
                                          getenv("OVN_SBCTL_OPTIONS"));

    /* Parse command line. */
    char *args = process_escape_args(argv_);
    shash_init(&local_options);
    parse_options(argc, argv_, &local_options);
    char *error = ctl_parse_commands(argc - optind, argv_ + optind,
                                     &local_options, &commands, &n_commands);
    if (error) {
        ctl_fatal("%s", error);
    }
    VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
         "Called as %s", args);

    ctl_timeout_setup(timeout);

    /* Initialize IDL. */
    idl = the_idl = ovsdb_idl_create(db, &sbrec_idl_class, false, true);
    ovsdb_idl_set_leader_only(idl, leader_only);
    run_prerequisites(commands, n_commands, idl);

    /* Execute the commands.
     *
     * 'seqno' is the database sequence number for which we last tried to
     * execute our transaction.  There's no point in trying to commit more than
     * once for any given sequence number, because if the transaction fails
     * it's because the database changed and we need to obtain an up-to-date
     * view of the database before we try the transaction again. */
    seqno = ovsdb_idl_get_seqno(idl);
    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                        db, ovs_retval_to_string(retval));
        }

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            if (do_sbctl(args, commands, n_commands, idl)) {
                break;
            }
        }

        if (seqno == ovsdb_idl_get_seqno(idl)) {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }

    for (int i = 0; i < argc; i++) {
        free(argv_[i]);
    }
    free(argv_);
    free(args);
    exit(EXIT_SUCCESS);
}

static void
parse_options(int argc, char *argv[], struct shash *local_options)
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_ONELINE,
        OPT_NO_SYSLOG,
        OPT_DRY_RUN,
        OPT_LOCAL,
        OPT_COMMANDS,
        OPT_OPTIONS,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        TABLE_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option global_long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"no-syslog", no_argument, NULL, OPT_NO_SYSLOG},
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},
        {"oneline", no_argument, NULL, OPT_ONELINE},
        {"timeout", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"commands", no_argument, NULL, OPT_COMMANDS},
        {"options", no_argument, NULL, OPT_OPTIONS},
        {"leader-only", no_argument, &leader_only, true},
        {"no-leader-only", no_argument, &leader_only, false},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    const int n_global_long_options = ARRAY_SIZE(global_long_options) - 1;
    char *tmp, *short_options;

    struct option *options;
    size_t allocated_options;
    size_t n_options;
    size_t i;

    tmp = ovs_cmdl_long_options_to_short_options(global_long_options);
    short_options = xasprintf("+%s", tmp);
    free(tmp);

    /* We want to parse both global and command-specific options here, but
     * getopt_long() isn't too convenient for the job.  We copy our global
     * options into a dynamic array, then append all of the command-specific
     * options. */
    options = xmemdup(global_long_options, sizeof global_long_options);
    allocated_options = ARRAY_SIZE(global_long_options);
    n_options = n_global_long_options;
    ctl_add_cmd_options(&options, &n_options, &allocated_options, OPT_LOCAL);

    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, options, &idx);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DB:
            db = optarg;
            break;

        case OPT_ONELINE:
            oneline = true;
            break;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_DRY_RUN:
            dry_run = true;
            break;

        case OPT_LOCAL:
            if (shash_find(local_options, options[idx].name)) {
                ctl_fatal("'%s' option specified multiple times",
                            options[idx].name);
            }
            shash_add_nocopy(local_options,
                             xasprintf("--%s", options[idx].name),
                             nullable_xstrdup(optarg));
            break;

        case 'h':
            usage();

        case OPT_COMMANDS:
            ctl_print_commands();
            /* fall through */

        case OPT_OPTIONS:
            ctl_print_options(global_long_options);
            /* fall through */

        case 'V':
            ovn_print_version(0, 0);
            printf("DB Schema %s\n", sbrec_get_db_version());
            exit(EXIT_SUCCESS);

        case 't':
            if (!str_to_uint(optarg, 10, &timeout) || !timeout) {
                ctl_fatal("value %s on -t or --timeout is invalid", optarg);
            }
            break;

        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();

        case 0:
            break;
        }
    }
    free(short_options);

    if (!db) {
        db = default_sb_db();
    }

    for (i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
}

static void
usage(void)
{
    printf("\
%s: OVN southbound DB management utility\n\
\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  show                        print overview of database contents\n\
\n\
Chassis commands:\n\
  chassis-add CHASSIS ENCAP-TYPE ENCAP-IP  create a new chassis named\n\
                                           CHASSIS with ENCAP-TYPE tunnels\n\
                                           and ENCAP-IP\n\
  chassis-del CHASSIS         delete CHASSIS and all of its encaps\n\
                              and gateway_ports\n\
\n\
Port binding commands:\n\
  lsp-bind PORT CHASSIS       bind logical port PORT to CHASSIS\n\
  lsp-unbind PORT             reset the port binding of logical port PORT\n\
\n\
Logical flow commands:\n\
  lflow-list [DATAPATH] [LFLOW...] List logical flows for DATAPATH\n\
  dump-flows [DATAPATH] [LFLOW...] Alias for lflow-list\n\
\n\
Connection commands:\n\
  get-connection             print the connections\n\
  del-connection             delete the connections\n\
  [--inactivity-probe=MSECS]\n\
  set-connection TARGET...   set the list of connections to TARGET...\n\
\n\
SSL commands:\n\
  get-ssl                     print the SSL configuration\n\
  del-ssl                     delete the SSL configuration\n\
  set-ssl PRIV-KEY CERT CA-CERT [SSL-PROTOS [SSL-CIPHERS]] \
set the SSL configuration\n\
\n\
%s\
%s\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  --no-leader-only            accept any cluster member, not just the leader\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, ctl_get_db_cmd_usage(),
           ctl_list_db_tables_usage(), default_sb_db());
    table_usage();
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=sbctl:syslog:warn\n");
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    stream_usage("database", true, true, true);
    exit(EXIT_SUCCESS);
}


/* ovs-sbctl specific context.  Inherits the 'struct ctl_context' as base. */
struct sbctl_context {
    struct ctl_context base;

    /* A cache of the contents of the database.
     *
     * A command that needs to use any of this information must first call
     * sbctl_context_populate_cache().  A command that changes anything that
     * could invalidate the cache must either call
     * sbctl_context_invalidate_cache() or manually update the cache to
     * maintain its correctness. */
    bool cache_valid;
    /* Maps from chassis name to struct sbctl_chassis. */
    struct shash chassis;
    /* Maps from lport name to struct sbctl_port_binding. */
    struct shash port_bindings;
};

/* Casts 'base' into 'struct sbctl_context'. */
static struct sbctl_context *
sbctl_context_cast(struct ctl_context *base)
{
    return CONTAINER_OF(base, struct sbctl_context, base);
}

struct sbctl_chassis {
    const struct sbrec_chassis *ch_cfg;
};

struct sbctl_port_binding {
    const struct sbrec_port_binding *bd_cfg;
};

static void
sbctl_context_invalidate_cache(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);

    if (!sbctl_ctx->cache_valid) {
        return;
    }
    sbctl_ctx->cache_valid = false;
    shash_destroy_free_data(&sbctl_ctx->chassis);
    shash_destroy_free_data(&sbctl_ctx->port_bindings);
}

static void
sbctl_context_populate_cache(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding *port_binding_rec;
    struct sset chassis, port_bindings;

    if (sbctl_ctx->cache_valid) {
        /* Cache is already populated. */
        return;
    }
    sbctl_ctx->cache_valid = true;
    shash_init(&sbctl_ctx->chassis);
    shash_init(&sbctl_ctx->port_bindings);
    sset_init(&chassis);
    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->idl) {
        struct sbctl_chassis *ch;

        if (!sset_add(&chassis, chassis_rec->name)) {
            VLOG_WARN("database contains duplicate chassis name (%s)",
                      chassis_rec->name);
            continue;
        }

        ch = xmalloc(sizeof *ch);
        ch->ch_cfg = chassis_rec;
        shash_add(&sbctl_ctx->chassis, chassis_rec->name, ch);
    }
    sset_destroy(&chassis);

    sset_init(&port_bindings);
    SBREC_PORT_BINDING_FOR_EACH(port_binding_rec, ctx->idl) {
        struct sbctl_port_binding *bd;

        if (!sset_add(&port_bindings, port_binding_rec->logical_port)) {
            VLOG_WARN("database contains duplicate port binding for logical "
                      "port (%s)",
                      port_binding_rec->logical_port);
            continue;
        }

        bd = xmalloc(sizeof *bd);
        bd->bd_cfg = port_binding_rec;
        shash_add(&sbctl_ctx->port_bindings, port_binding_rec->logical_port,
                  bd);
    }
    sset_destroy(&port_bindings);
}

static void
check_conflicts(struct sbctl_context *sbctl_ctx, const char *name,
                char *msg)
{
    if (shash_find(&sbctl_ctx->chassis, name)) {
        ctl_fatal("%s because a chassis named %s already exists",
                    msg, name);
    }
    free(msg);
}

static struct sbctl_chassis *
find_chassis(struct sbctl_context *sbctl_ctx, const char *name,
             bool must_exist)
{
    struct sbctl_chassis *sbctl_ch;

    ovs_assert(sbctl_ctx->cache_valid);

    sbctl_ch = shash_find_data(&sbctl_ctx->chassis, name);
    if (must_exist && !sbctl_ch) {
        ctl_fatal("no chassis named %s", name);
    }

    return sbctl_ch;
}

static struct sbctl_port_binding *
find_port_binding(struct sbctl_context *sbctl_ctx, const char *name,
                  bool must_exist)
{
    struct sbctl_port_binding *bd;

    ovs_assert(sbctl_ctx->cache_valid);

    bd = shash_find_data(&sbctl_ctx->port_bindings, name);
    if (must_exist && !bd) {
        ctl_fatal("no port named %s", name);
    }

    return bd;
}

static void
pre_get_info(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_chassis_col_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_chassis_col_encaps);

    ovsdb_idl_add_column(ctx->idl, &sbrec_encap_col_type);
    ovsdb_idl_add_column(ctx->idl, &sbrec_encap_col_ip);

    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_logical_port);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_tunnel_key);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_chassis);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_datapath);

    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_logical_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_logical_dp_group);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_pipeline);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_actions);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_priority);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_table_id);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_match);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_external_ids);

    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_dp_group_col_datapaths);

    ovsdb_idl_add_column(ctx->idl, &sbrec_datapath_binding_col_external_ids);

    ovsdb_idl_add_column(ctx->idl, &sbrec_ip_multicast_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ip_multicast_col_seq_no);

    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_tunnel_key);
    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_ports);

    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_logical_port);
    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_ip);
    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_mac);

    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_datapaths);
    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_vips);
    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_protocol);
}

static struct cmd_show_table cmd_show_tables[] = {
    {&sbrec_table_chassis,
     &sbrec_chassis_col_name,
     {&sbrec_chassis_col_hostname,
      &sbrec_chassis_col_encaps,
      NULL},
     {&sbrec_table_port_binding,
      &sbrec_port_binding_col_logical_port,
      &sbrec_port_binding_col_chassis}},

    {&sbrec_table_encap,
     &sbrec_encap_col_type,
     {&sbrec_encap_col_ip,
      &sbrec_encap_col_options,
      NULL},
     {NULL, NULL, NULL}},

    {NULL, NULL, {NULL, NULL, NULL}, {NULL, NULL, NULL}},
};

static void
sbctl_init(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
cmd_chassis_add(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    const char *ch_name, *encap_types, *encap_ip;

    ch_name = ctx->argv[1];
    encap_types = ctx->argv[2];
    encap_ip = ctx->argv[3];

    sbctl_context_populate_cache(ctx);
    if (may_exist) {
        struct sbctl_chassis *sbctl_ch;

        sbctl_ch = find_chassis(sbctl_ctx, ch_name, false);
        if (sbctl_ch) {
            return;
        }
    }
    check_conflicts(sbctl_ctx, ch_name,
                    xasprintf("cannot create a chassis named %s", ch_name));

    struct sset encap_set;
    sset_from_delimited_string(&encap_set, encap_types, ",");

    size_t n_encaps = sset_count(&encap_set);
    struct sbrec_encap **encaps = xmalloc(n_encaps * sizeof *encaps);
    const struct smap options = SMAP_CONST1(&options, "csum", "true");
    const char *encap_type;
    int i = 0;
    SSET_FOR_EACH (encap_type, &encap_set){
        encaps[i] = sbrec_encap_insert(ctx->txn);

        sbrec_encap_set_type(encaps[i], encap_type);
        sbrec_encap_set_ip(encaps[i], encap_ip);
        sbrec_encap_set_options(encaps[i], &options);
        sbrec_encap_set_chassis_name(encaps[i], ch_name);
        i++;
    }
    sset_destroy(&encap_set);

    struct sbrec_chassis *ch = sbrec_chassis_insert(ctx->txn);
    sbrec_chassis_set_name(ch, ch_name);
    sbrec_chassis_set_encaps(ch, encaps, n_encaps);
    free(encaps);

    sbctl_context_invalidate_cache(ctx);
}

static void
cmd_chassis_del(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct sbctl_chassis *sbctl_ch;

    sbctl_context_populate_cache(ctx);
    sbctl_ch = find_chassis(sbctl_ctx, ctx->argv[1], must_exist);
    if (sbctl_ch) {
        if (sbctl_ch->ch_cfg) {
            size_t i;

            for (i = 0; i < sbctl_ch->ch_cfg->n_encaps; i++) {
                sbrec_encap_delete(sbctl_ch->ch_cfg->encaps[i]);
            }
            sbrec_chassis_delete(sbctl_ch->ch_cfg);
        }
        shash_find_and_delete(&sbctl_ctx->chassis, ctx->argv[1]);
        free(sbctl_ch);
    }
}

static void
cmd_lsp_bind(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct sbctl_chassis *sbctl_ch;
    struct sbctl_port_binding *sbctl_bd;
    char *lport_name, *ch_name;

    /* port_binding must exist, chassis must exist! */
    lport_name = ctx->argv[1];
    ch_name = ctx->argv[2];

    sbctl_context_populate_cache(ctx);
    sbctl_bd = find_port_binding(sbctl_ctx, lport_name, true);
    sbctl_ch = find_chassis(sbctl_ctx, ch_name, true);

    if (sbctl_bd->bd_cfg->chassis) {
        if (may_exist && sbctl_bd->bd_cfg->chassis == sbctl_ch->ch_cfg) {
            return;
        } else {
            ctl_fatal("lport (%s) has already been binded to chassis (%s)",
                      lport_name, sbctl_bd->bd_cfg->chassis->name);
        }
    }
    sbrec_port_binding_set_chassis(sbctl_bd->bd_cfg, sbctl_ch->ch_cfg);
    sbctl_context_invalidate_cache(ctx);
}

static void
cmd_lsp_unbind(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct sbctl_port_binding *sbctl_bd;
    char *lport_name;

    lport_name = ctx->argv[1];
    sbctl_context_populate_cache(ctx);
    sbctl_bd = find_port_binding(sbctl_ctx, lport_name, must_exist);
    if (sbctl_bd) {
        sbrec_port_binding_set_chassis(sbctl_bd->bd_cfg, NULL);
    }
}

enum {
    PL_INGRESS,
    PL_EGRESS,
};

/* Help ensure we catch any future pipeline values */
static int
pipeline_encode(const char *pl)
{
    if (!strcmp(pl, "ingress")) {
        return PL_INGRESS;
    } else if (!strcmp(pl, "egress")) {
        return PL_EGRESS;
    }

    OVS_NOT_REACHED();
}

struct sbctl_lflow {
    const struct sbrec_logical_flow *lflow;
    const struct sbrec_datapath_binding *dp;
};

static int
sbctl_lflow_cmp(const void *a_, const void *b_)
{
    const struct sbctl_lflow *a_ctl_lflow = a_;
    const struct sbctl_lflow *b_ctl_lflow = b_;

    const struct sbrec_logical_flow *a = a_ctl_lflow->lflow;
    const struct sbrec_logical_flow *b = b_ctl_lflow->lflow;

    const struct sbrec_datapath_binding *adb = a_ctl_lflow->dp;
    const struct sbrec_datapath_binding *bdb = b_ctl_lflow->dp;
    const char *a_name = smap_get_def(&adb->external_ids, "name", "");
    const char *b_name = smap_get_def(&bdb->external_ids, "name", "");
    int cmp = strcmp(a_name, b_name);
    if (cmp) {
        return cmp;
    }

    cmp = uuid_compare_3way(&adb->header_.uuid, &bdb->header_.uuid);
    if (cmp) {
        return cmp;
    }

    int a_pipeline = pipeline_encode(a->pipeline);
    int b_pipeline = pipeline_encode(b->pipeline);
    return (a_pipeline > b_pipeline ? 1
            : a_pipeline < b_pipeline ? -1
            : a->table_id > b->table_id ? 1
            : a->table_id < b->table_id ? -1
            : a->priority > b->priority ? -1
            : a->priority < b->priority ? 1
            : strcmp(a->match, b->match));
}

static char *
parse_partial_uuid(char *s)
{
    /* Accept a full or partial UUID. */
    if (uuid_is_partial_string(s)) {
        return s;
    }

    /* Accept a full or partial UUID prefixed by 0x, since "ovs-ofctl
     * dump-flows" prints cookies prefixed by 0x. */
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
        && uuid_is_partial_string(s + 2)) {
        return s + 2;
    }

    /* Not a (partial) UUID. */
    return NULL;
}

static const char *
strip_leading_zero(const char *s)
{
    return s + strspn(s, "0");
}

static bool
is_partial_uuid_match(const struct uuid *uuid, const char *match)
{
    char uuid_s[UUID_LEN + 1];
    snprintf(uuid_s, sizeof uuid_s, UUID_FMT, UUID_ARGS(uuid));

    /* We strip leading zeros because we want to accept cookie values derived
     * from UUIDs, and cookie values are printed without leading zeros because
     * they're just numbers. */
    const char *s1 = strip_leading_zero(uuid_s);
    const char *s2 = strip_leading_zero(match);

    return !strncmp(s1, s2, strlen(s2));
}

static char *
default_ovs(void)
{
    return xasprintf("unix:%s/br-int.mgmt", ovs_rundir());
}

static struct vconn *
sbctl_open_vconn(struct shash *options)
{
    struct shash_node *ovs = shash_find(options, "--ovs");
    if (!ovs) {
        return NULL;
    }

    char *remote = ovs->data ? xstrdup(ovs->data) : default_ovs();
    struct vconn *vconn;
    int retval = vconn_open_block(remote, 1 << OFP15_VERSION, 0, -1, &vconn);
    if (retval) {
        VLOG_WARN("%s: connection failed (%s)", remote, ovs_strerror(retval));
    }
    free(remote);
    return vconn;
}

static void
sbctl_dump_openflow(struct vconn *vconn, const struct uuid *uuid, bool stats)
{
    struct ofputil_flow_stats_request fsr = {
        .cookie = htonll(uuid->parts[0]),
        .cookie_mask = OVS_BE64_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
        .table_id = OFPTT_ALL,
    };

    struct ofputil_flow_stats *fses;
    size_t n_fses;
    int error = vconn_dump_flows(vconn, &fsr, OFPUTIL_P_OF15_OXM,
                                 &fses, &n_fses);
    if (error) {
        VLOG_WARN("%s: error obtaining flow stats (%s)",
                  vconn_get_name(vconn), ovs_strerror(error));
        return;
    }

    if (n_fses) {
        struct ds s = DS_EMPTY_INITIALIZER;
        for (size_t i = 0; i < n_fses; i++) {
            const struct ofputil_flow_stats *fs = &fses[i];

            ds_clear(&s);
            if (stats) {
                ofputil_flow_stats_format(&s, fs, NULL, NULL, true);
            } else {
                ds_put_format(&s, "%stable=%s%"PRIu8" ",
                              colors.special, colors.end, fs->table_id);
                match_format(&fs->match, NULL, &s, OFP_DEFAULT_PRIORITY);
                if (ds_last(&s) != ' ') {
                    ds_put_char(&s, ' ');
                }

                ds_put_format(&s, "%sactions=%s", colors.actions, colors.end);
                struct ofpact_format_params fp = { .s = &s };
                ofpacts_format(fs->ofpacts, fs->ofpacts_len, &fp);
            }
            printf("    %s\n", ds_cstr(&s));
        }
        ds_destroy(&s);
    }

    for (size_t i = 0; i < n_fses; i++) {
        free(CONST_CAST(struct ofpact *, fses[i].ofpacts));
    }
    free(fses);
}

static void
print_datapath_name(const struct sbrec_datapath_binding *dp)
{
    const struct smap *ids = &dp->external_ids;
    const char *name = smap_get(ids, "name");
    const char *name2 = smap_get(ids, "name2");
    if (name && name2) {
        printf("\"%s\" aka \"%s\"", name, name2);
    } else if (name || name2) {
        printf("\"%s\"", name ? name : name2);
    }
}

static void
print_vflow_datapath_name(const struct sbrec_datapath_binding *dp,
                          bool do_print)
{
    if (!do_print) {
        return;
    }
    printf("datapath=");
    print_datapath_name(dp);
    printf(", ");
}

static void
print_uuid_part(const struct uuid *uuid, bool do_print)
{
    if (!do_print) {
        return;
    }
    printf("uuid=0x%08"PRIx32", ", uuid->parts[0]);
}

static void
cmd_lflow_list_port_bindings(struct ctl_context *ctx, struct vconn *vconn,
                             const struct sbrec_datapath_binding *datapath,
                             bool stats, bool print_uuid)
{
    const struct sbrec_port_binding *pb;
    const struct sbrec_port_binding *pb_prev = NULL;
    SBREC_PORT_BINDING_FOR_EACH (pb, ctx->idl) {

        if (datapath && pb->datapath != datapath) {
            continue;
        }

        if (!pb_prev) {
            printf("\nPort Bindings:\n");
        }

        printf("  ");
        print_uuid_part(&pb->header_.uuid, print_uuid);
        print_vflow_datapath_name(pb->datapath, !datapath);
        printf("logical_port=%s, tunnel_key=%-5"PRId64"\n",
               pb->logical_port, pb->tunnel_key);
        if (vconn) {
            sbctl_dump_openflow(vconn, &pb->header_.uuid, stats);
        }

        pb_prev = pb;
    }
}

static void
cmd_lflow_list_mac_bindings(struct ctl_context *ctx, struct vconn *vconn,
                            const struct sbrec_datapath_binding *datapath,
                            bool stats, bool print_uuid)
{
    const struct sbrec_mac_binding *mb;
    const struct sbrec_mac_binding *mb_prev = NULL;
    SBREC_MAC_BINDING_FOR_EACH (mb, ctx->idl) {
        if (datapath && mb->datapath != datapath) {
            continue;
        }

        if (!mb_prev) {
            printf("\nMAC Bindings:\n");
        }

        printf("  ");
        print_uuid_part(&mb->header_.uuid, print_uuid);
        print_vflow_datapath_name(mb->datapath, !datapath);

        printf("logical_port=%s, ip=%s, mac=%s\n",
               mb->logical_port, mb->ip, mb->mac);
        if (vconn) {
            sbctl_dump_openflow(vconn, &mb->header_.uuid, stats);
        }

        mb_prev = mb;
    }
}

static void
cmd_lflow_list_mc_groups(struct ctl_context *ctx, struct vconn *vconn,
                         const struct sbrec_datapath_binding *datapath,
                         bool stats, bool print_uuid)
{
    const struct sbrec_multicast_group *mc;
    const struct sbrec_multicast_group *mc_prev = NULL;
    SBREC_MULTICAST_GROUP_FOR_EACH (mc, ctx->idl) {
        if (datapath && mc->datapath != datapath) {
            continue;
        }

        if (!mc_prev) {
            printf("\nMC Groups:\n");
        }

        printf("  ");
        print_uuid_part(&mc->header_.uuid, print_uuid);
        print_vflow_datapath_name(mc->datapath, !datapath);

        printf("name=%s, tunnel_key=%-5"PRId64", ports=(",
               mc->name, mc->tunnel_key);
        for (size_t i = 0; i < mc->n_ports; i++) {
            printf("%s", mc->ports[i]->logical_port);
            if (i != mc->n_ports - 1) {
                printf(", ");
            }
        }
        printf(")\n");

        if (vconn) {
            sbctl_dump_openflow(vconn, &mc->header_.uuid, stats);
        }

        mc_prev = mc;
    }
}

static void
cmd_lflow_list_chassis(struct ctl_context *ctx, struct vconn *vconn,
                       bool stats, bool print_uuid)
{
    const struct sbrec_chassis *chassis;
    const struct sbrec_chassis *chassis_prev = NULL;
    SBREC_CHASSIS_FOR_EACH (chassis, ctx->idl) {
        if (!chassis_prev) {
            printf("\nChassis:\n");
        }

        printf("  ");
        print_uuid_part(&chassis->header_.uuid, print_uuid);

        printf("name=%s\n", chassis->name);
        if (vconn) {
            sbctl_dump_openflow(vconn, &chassis->header_.uuid, stats);
        }

        chassis_prev = chassis;
    }
}

static void
cmd_lflow_list_load_balancers(struct ctl_context *ctx, struct vconn *vconn,
                              const struct sbrec_datapath_binding *datapath,
                              bool stats, bool print_uuid)
{
    const struct sbrec_load_balancer *lb;
    const struct sbrec_load_balancer *lb_prev = NULL;
    SBREC_LOAD_BALANCER_FOR_EACH (lb, ctx->idl) {
        bool dp_found = false;
        if (datapath) {
            size_t i;
            for (i = 0; i < lb->n_datapaths; i++) {
                if (datapath == lb->datapaths[i]) {
                    dp_found = true;
                    break;
                }
            }
            if (!dp_found) {
                continue;
            }
        }

        if (!lb_prev) {
            printf("\nLoad Balancers:\n");
        }

        printf("  ");
        print_uuid_part(&lb->header_.uuid, print_uuid);
        printf("name=\"%s\", protocol=\"%s\", ", lb->name, lb->protocol);
        if (!dp_found) {
            for (size_t i = 0; i < lb->n_datapaths; i++) {
                print_vflow_datapath_name(lb->datapaths[i], true);
            }
        }

        printf("\n  vips:\n");
        struct smap_node *node;
        SMAP_FOR_EACH (node, &lb->vips) {
            printf("    %s = %s\n", node->key, node->value);
        }
        printf("\n");

        if (vconn) {
            sbctl_dump_openflow(vconn, &lb->header_.uuid, stats);
        }

        lb_prev = lb;
    }
}

static bool
datapath_group_contains_datapath(const struct sbrec_logical_dp_group *g,
                                 const struct sbrec_datapath_binding *dp)
{
    if (!g || !dp) {
        return false;
    }
    for (size_t i = 0; i < g->n_datapaths; i++) {
        if (g->datapaths[i] == dp) {
            return true;
        }
    }
    return false;
}

static void
sbctl_lflow_add(struct sbctl_lflow **lflows,
                size_t *n_flows, size_t *n_capacity,
                const struct sbrec_logical_flow *lflow,
                const struct sbrec_datapath_binding *dp)
{
    if (*n_flows == *n_capacity) {
        *lflows = x2nrealloc(*lflows, n_capacity, sizeof **lflows);
    }
    (*lflows)[*n_flows].lflow = lflow;
    (*lflows)[*n_flows].dp = dp;
    (*n_flows)++;
}

static void
cmd_lflow_list(struct ctl_context *ctx)
{
    const struct sbrec_datapath_binding *datapath = NULL;
    if (ctx->argc > 1) {
        const struct ovsdb_idl_row *row;
        char *error = ctl_get_row(ctx, &sbrec_table_datapath_binding,
                                  ctx->argv[1], false, &row);
        if (error) {
            ctl_fatal("%s", error);
        }

        datapath = (const struct sbrec_datapath_binding *)row;
        if (datapath) {
            ctx->argc--;
            ctx->argv++;
        }
    }

    for (size_t i = 1; i < ctx->argc; i++) {
        char *s = parse_partial_uuid(ctx->argv[i]);
        if (!s) {
            ctl_fatal("%s is not a UUID or the beginning of a UUID",
                      ctx->argv[i]);
        }
        ctx->argv[i] = s;
    }

    struct vconn *vconn = sbctl_open_vconn(&ctx->options);
    bool stats = shash_find(&ctx->options, "--stats") != NULL;

    struct sbctl_lflow *lflows = NULL;
    size_t n_flows = 0;
    size_t n_capacity = 0;
    const struct sbrec_logical_flow *lflow;
    const struct sbrec_logical_dp_group *dp_group;
    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->idl) {
        if (datapath
            && lflow->logical_datapath != datapath
            && !datapath_group_contains_datapath(lflow->logical_dp_group,
                                                 datapath)) {
            continue;
        }
        if (datapath) {
            sbctl_lflow_add(&lflows, &n_flows, &n_capacity, lflow, datapath);
            continue;
        }
        if (lflow->logical_datapath) {
            sbctl_lflow_add(&lflows, &n_flows, &n_capacity,
                            lflow, lflow->logical_datapath);
        }
        dp_group = lflow->logical_dp_group;
        for (size_t i = 0; dp_group && i < dp_group->n_datapaths; i++) {
            sbctl_lflow_add(&lflows, &n_flows, &n_capacity,
                            lflow, dp_group->datapaths[i]);
        }
    }

    if (n_flows) {
        qsort(lflows, n_flows, sizeof *lflows, sbctl_lflow_cmp);
    }

    bool print_uuid = shash_find(&ctx->options, "--uuid") != NULL;

    const struct sbctl_lflow *curr, *prev = NULL;
    for (size_t i = 0; i < n_flows; i++) {
        curr = &lflows[i];

        /* Figure out whether to print this particular flow.  By default, we
         * print all flows, but if any UUIDs were listed on the command line
         * then we only print the matching ones. */
        bool include;
        if (ctx->argc > 1) {
            include = false;
            for (size_t j = 1; j < ctx->argc; j++) {
                if (is_partial_uuid_match(&curr->lflow->header_.uuid,
                                          ctx->argv[j])) {
                    include = true;
                    break;
                }
            }
        } else {
            include = true;
        }
        if (!include) {
            continue;
        }

        /* Print a header line for this datapath or pipeline, if we haven't
         * already done so. */
        if (!prev
            || prev->dp != curr->dp
            || strcmp(prev->lflow->pipeline, curr->lflow->pipeline)) {
            printf("Datapath: ");
            print_datapath_name(curr->dp);
            printf(" ("UUID_FMT")  Pipeline: %s\n",
                   UUID_ARGS(&curr->dp->header_.uuid),
                   curr->lflow->pipeline);
        }

        /* Print the flow. */
        printf("  ");
        print_uuid_part(&curr->lflow->header_.uuid, print_uuid);
        printf("table=%-2"PRId64"(%-19s), priority=%-5"PRId64
               ", match=(%s), action=(%s)\n",
               curr->lflow->table_id,
               smap_get_def(&curr->lflow->external_ids, "stage-name", ""),
               curr->lflow->priority, curr->lflow->match,
               curr->lflow->actions);
        if (vconn) {
            sbctl_dump_openflow(vconn, &curr->lflow->header_.uuid, stats);
        }
        prev = curr;
    }

    bool vflows = shash_find(&ctx->options, "--vflows") != NULL;
    if (vflows) {
        cmd_lflow_list_port_bindings(ctx, vconn, datapath, stats, print_uuid);
        cmd_lflow_list_mac_bindings(ctx, vconn, datapath, stats, print_uuid);
        cmd_lflow_list_mc_groups(ctx, vconn, datapath, stats, print_uuid);
        cmd_lflow_list_chassis(ctx, vconn, stats, print_uuid);
        cmd_lflow_list_load_balancers(ctx, vconn, datapath, stats, print_uuid);
    }

    vconn_close(vconn);
    free(lflows);
}

static void
sbctl_ip_mcast_flush_switch(struct ctl_context *ctx,
                            const struct sbrec_datapath_binding *dp)
{
    const struct sbrec_ip_multicast *ip_mcast;

    /* Lookup the corresponding IP_Multicast entry. */
    SBREC_IP_MULTICAST_FOR_EACH (ip_mcast, ctx->idl) {
        if (ip_mcast->datapath != dp) {
            continue;
        }

        sbrec_ip_multicast_set_seq_no(ip_mcast, ip_mcast->seq_no + 1);
    }
}

static void
sbctl_ip_mcast_flush(struct ctl_context *ctx)
{
    const struct sbrec_datapath_binding *dp;

    if (ctx->argc > 2) {
        return;
    }

    if (ctx->argc == 2) {
        const struct ovsdb_idl_row *row;
        char *error = ctl_get_row(ctx, &sbrec_table_datapath_binding,
                                  ctx->argv[1], false, &row);
        if (error) {
            ctl_fatal("%s", error);
        }

        dp = (const struct sbrec_datapath_binding *)row;
        if (!dp) {
            ctl_fatal("%s is not a valid datapath", ctx->argv[1]);
        }

        sbctl_ip_mcast_flush_switch(ctx, dp);
    } else {
        SBREC_DATAPATH_BINDING_FOR_EACH (dp, ctx->idl) {
            sbctl_ip_mcast_flush_switch(ctx, dp);
        }
    }
}

static void
verify_connections(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_connection *conn;

    sbrec_sb_global_verify_connections(sb_global);

    SBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        sbrec_connection_verify_target(conn);
    }
}

static void
pre_connection(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_connections);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_target);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_read_only);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_role);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_inactivity_probe);
}

static void
cmd_get_connection(struct ctl_context *ctx)
{
    const struct sbrec_connection *conn;
    struct svec targets;
    size_t i;

    verify_connections(ctx);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    SBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        char *s;

        s = xasprintf("%s role=\"%s\" %s",
                      conn->read_only ? "read-only" : "read-write",
                      conn->role,
                      conn->target);
        svec_add(&targets, s);
        free(s);
    }

    svec_sort_unique(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_connections(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_connection *conn, *next;

    /* Delete Manager rows pointed to by 'connection_options' column. */
    SBREC_CONNECTION_FOR_EACH_SAFE(conn, next, ctx->idl) {
        sbrec_connection_delete(conn);
    }

    /* Delete 'Manager' row refs in 'manager_options' column. */
    sbrec_sb_global_set_connections(sb_global, NULL, 0);
}

static void
cmd_del_connection(struct ctl_context *ctx)
{
    verify_connections(ctx);
    delete_connections(ctx);
}

static void
insert_connections(struct ctl_context *ctx, char *targets[], size_t n)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    struct sbrec_connection **connections;
    size_t i, conns=0;
    bool read_only = false;
    char *role = "";
    const char *inactivity_probe = shash_find_data(&ctx->options,
                                                   "--inactivity-probe");

    /* Insert each connection in a new row in Connection table. */
    connections = xmalloc(n * sizeof *connections);
    for (i = 0; i < n; i++) {
        if (!strcmp(targets[i], "read-only")) {
            read_only = true;
            continue;
        } else if (!strcmp(targets[i], "read-write")) {
            read_only = false;
            continue;
        } else if (!strncmp(targets[i], "role=", 5)) {
            role = targets[i] + 5;
            continue;
        } else if (stream_verify_name(targets[i]) &&
                   pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }

        connections[conns] = sbrec_connection_insert(ctx->txn);
        sbrec_connection_set_target(connections[conns], targets[i]);
        sbrec_connection_set_read_only(connections[conns], read_only);
        sbrec_connection_set_role(connections[conns], role);
        if (inactivity_probe) {
            int64_t msecs = atoll(inactivity_probe);
            sbrec_connection_set_inactivity_probe(connections[conns],
                                                  &msecs, 1);
        }
        conns++;
    }

    /* Store uuids of new connection rows in 'connection' column. */
    sbrec_sb_global_set_connections(sb_global, connections, conns);
    free(connections);
}

static void
cmd_set_connection(struct ctl_context *ctx)
{
    const size_t n = ctx->argc - 1;

    verify_connections(ctx);
    delete_connections(ctx);
    insert_connections(ctx, &ctx->argv[1], n);
}

static void
pre_cmd_get_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_ssl);

    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_private_key);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_certificate);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_bootstrap_ca_cert);
}

static void
cmd_get_ssl(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_ssl *ssl = sbrec_ssl_first(ctx->idl);

    sbrec_sb_global_verify_ssl(sb_global);
    if (ssl) {
        sbrec_ssl_verify_private_key(ssl);
        sbrec_ssl_verify_certificate(ssl);
        sbrec_ssl_verify_ca_cert(ssl);
        sbrec_ssl_verify_bootstrap_ca_cert(ssl);

        ds_put_format(&ctx->output, "Private key: %s\n", ssl->private_key);
        ds_put_format(&ctx->output, "Certificate: %s\n", ssl->certificate);
        ds_put_format(&ctx->output, "CA Certificate: %s\n", ssl->ca_cert);
        ds_put_format(&ctx->output, "Bootstrap: %s\n",
                ssl->bootstrap_ca_cert ? "true" : "false");
    }
}

static void
pre_cmd_del_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_ssl);
}

static void
cmd_del_ssl(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_ssl *ssl = sbrec_ssl_first(ctx->idl);

    if (ssl) {
        sbrec_sb_global_verify_ssl(sb_global);
        sbrec_ssl_delete(ssl);
        sbrec_sb_global_set_ssl(sb_global, NULL);
    }
}

static void
pre_cmd_set_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_ssl);
}

static void
cmd_set_ssl(struct ctl_context *ctx)
{
    bool bootstrap = shash_find(&ctx->options, "--bootstrap");
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_ssl *ssl = sbrec_ssl_first(ctx->idl);

    sbrec_sb_global_verify_ssl(sb_global);
    if (ssl) {
        sbrec_ssl_delete(ssl);
    }
    ssl = sbrec_ssl_insert(ctx->txn);

    sbrec_ssl_set_private_key(ssl, ctx->argv[1]);
    sbrec_ssl_set_certificate(ssl, ctx->argv[2]);
    sbrec_ssl_set_ca_cert(ssl, ctx->argv[3]);

    sbrec_ssl_set_bootstrap_ca_cert(ssl, bootstrap);

    if (ctx->argc == 5) {
        sbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
    } else if (ctx->argc == 6) {
        sbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
        sbrec_ssl_set_ssl_ciphers(ssl, ctx->argv[5]);
    }

    sbrec_sb_global_set_ssl(sb_global, ssl);
}

static void
pre_cmd_print_port_statistics(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_statistics);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_logical_port);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_chassis);

    ovsdb_idl_add_column(ctx->idl, &sbrec_chassis_col_name);

    ovsdb_idl_add_column(ctx->idl, &sbrec_datapath_binding_col_external_ids);

    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_statistics_col_chassis_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_statistics_col_pinctrl_ops);
}

static void
cmd_print_port_statistics(struct ctl_context *ctx)
{
    struct ovsdb_idl *ovnsb_idl = ctx->idl;

    const struct sbrec_port_binding *pb;
    struct shash dps = SHASH_INITIALIZER(&dps);

    struct pb_list_node {
        const struct sbrec_port_binding *pb;
        struct ovs_list list;
    };

    /* Organize stats by datapath */
    SBREC_PORT_BINDING_FOR_EACH (pb, ovnsb_idl) {
        if (!pb->n_statistics || !pb->datapath) {
            continue;
        }
        const char *dp_name = smap_get_def(&pb->datapath->external_ids, "name",
                                           "(none)");
        struct ovs_list *pb_list;
        pb_list = shash_find_data(&dps, dp_name);
        if (!pb_list) {
            pb_list = xmalloc(sizeof *pb_list);
            ovs_list_init(pb_list);
            shash_add(&dps, dp_name, pb_list);
        }
        struct pb_list_node *node = xzalloc(sizeof *node);
        node->pb = pb;
        ovs_list_push_back(pb_list, &node->list);
    }

    struct shash_node *node;
    SHASH_FOR_EACH (node, &dps) {
        const char *dp_name = node->name;
        struct ovs_list *pb_list = node->data;
        ds_put_format(&ctx->output, "%s\n", dp_name);
        struct pb_list_node *pb_node;
        LIST_FOR_EACH_POP (pb_node, list, pb_list) {
            pb = pb_node->pb;
            ds_put_format(&ctx->output, "  %s\n", pb->logical_port);
            for (int i = 0; i < pb->n_statistics; i++) {
                const struct sbrec_port_binding_statistics *stats;
                stats = pb->statistics[i];
                ds_put_format(&ctx->output, "    %s\n", stats->chassis_name);
                for (int j = 0; j < stats->n_pinctrl_ops; j++) {
                    ds_put_format(&ctx->output, "      %s: %" PRId64 "\n",
                                  stats->key_pinctrl_ops[j],
                                  stats->value_pinctrl_ops[j]);
                }
            }
            free(pb_node);
        }
    }

    shash_destroy_free_data(&dps);
}
static void
pre_cmd_clear_port_statistics(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_statistics);
}

static void
cmd_clear_port_statistics(struct ctl_context *ctx)
{
    struct ovsdb_idl *ovnsb_idl = ctx->idl;
    const struct sbrec_port_binding *pb;

    SBREC_PORT_BINDING_FOR_EACH (pb, ovnsb_idl) {
        sbrec_port_binding_set_statistics(pb, NULL, 0);
    }
}

static const struct ctl_table_class tables[SBREC_N_TABLES] = {
    [SBREC_TABLE_CHASSIS].row_ids[0] = {&sbrec_chassis_col_name, NULL, NULL},

    [SBREC_TABLE_CHASSIS_PRIVATE].row_ids[0]
    = {&sbrec_chassis_private_col_name, NULL, NULL},

    [SBREC_TABLE_DATAPATH_BINDING].row_ids
     = {{&sbrec_datapath_binding_col_external_ids, "name", NULL},
        {&sbrec_datapath_binding_col_external_ids, "name2", NULL},
        {&sbrec_datapath_binding_col_external_ids, "logical-switch", NULL},
        {&sbrec_datapath_binding_col_external_ids, "logical-router", NULL}},

    [SBREC_TABLE_PORT_BINDING].row_ids
     = {{&sbrec_port_binding_col_logical_port, NULL, NULL},
        {&sbrec_port_binding_col_external_ids, "name", NULL}},

    [SBREC_TABLE_MAC_BINDING].row_ids[0] =
    {&sbrec_mac_binding_col_logical_port, NULL, NULL},

    [SBREC_TABLE_ADDRESS_SET].row_ids[0]
    = {&sbrec_address_set_col_name, NULL, NULL},

    [SBREC_TABLE_PORT_GROUP].row_ids[0]
    = {&sbrec_port_group_col_name, NULL, NULL},

    [SBREC_TABLE_HA_CHASSIS_GROUP].row_ids[0]
    = {&sbrec_ha_chassis_group_col_name, NULL, NULL},

    [SBREC_TABLE_HA_CHASSIS].row_ids[0]
    = {&sbrec_ha_chassis_col_chassis, NULL, NULL},

    [SBREC_TABLE_METER].row_ids[0]
    = {&sbrec_meter_col_name, NULL, NULL},

    [SBREC_TABLE_SERVICE_MONITOR].row_ids[0]
    = {&sbrec_service_monitor_col_logical_port, NULL, NULL},

    [SBREC_TABLE_DHCP_OPTIONS].row_ids[0]
    = {&sbrec_dhcp_options_col_name, NULL, NULL},

    [SBREC_TABLE_DHCPV6_OPTIONS].row_ids[0]
    = {&sbrec_dhcpv6_options_col_name, NULL, NULL},

    [SBREC_TABLE_CONNECTION].row_ids[0]
    = {&sbrec_connection_col_target, NULL, NULL},

    [SBREC_TABLE_RBAC_ROLE].row_ids[0]
    = {&sbrec_rbac_role_col_name, NULL, NULL},

    [SBREC_TABLE_RBAC_PERMISSION].row_ids[0]
    = {&sbrec_rbac_permission_col_table, NULL, NULL},

    [SBREC_TABLE_GATEWAY_CHASSIS].row_ids[0]
    = {&sbrec_gateway_chassis_col_name, NULL, NULL},

    [SBREC_TABLE_LOAD_BALANCER].row_ids[0]
    = {&sbrec_load_balancer_col_name, NULL, NULL},
};


static void
sbctl_context_init_command(struct sbctl_context *sbctl_ctx,
                           struct ctl_command *command)
{
    ctl_context_init_command(&sbctl_ctx->base, command);
}

static void
sbctl_context_init(struct sbctl_context *sbctl_ctx,
                   struct ctl_command *command, struct ovsdb_idl *idl,
                   struct ovsdb_idl_txn *txn,
                   struct ovsdb_symbol_table *symtab)
{
    ctl_context_init(&sbctl_ctx->base, command, idl, txn, symtab,
                     sbctl_context_invalidate_cache);
    sbctl_ctx->cache_valid = false;
}

static void
sbctl_context_done_command(struct sbctl_context *sbctl_ctx,
                           struct ctl_command *command)
{
    ctl_context_done_command(&sbctl_ctx->base, command);
}

static void
sbctl_context_done(struct sbctl_context *sbctl_ctx,
                   struct ctl_command *command)
{
    ctl_context_done(&sbctl_ctx->base, command);
}

static void
run_prerequisites(struct ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    ovsdb_idl_add_table(idl, &sbrec_table_sb_global);

    for (struct ctl_command *c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct sbctl_context sbctl_ctx;

            ds_init(&c->output);
            c->table = NULL;

            sbctl_context_init(&sbctl_ctx, c, idl, NULL, NULL);
            (c->syntax->prerequisites)(&sbctl_ctx.base);
            if (sbctl_ctx.base.error) {
                ctl_fatal("%s", sbctl_ctx.base.error);
            }
            sbctl_context_done(&sbctl_ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }
}

static bool
do_sbctl(const char *args, struct ctl_command *commands, size_t n_commands,
         struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct sbctl_context sbctl_ctx;
    struct ctl_command *c;
    struct shash_node *node;

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "ovs-sbctl: %s", args);

    const struct sbrec_sb_global *sb = sbrec_sb_global_first(idl);
    if (!sb) {
        /* XXX add verification that table is empty */
        sbrec_sb_global_insert(txn);
    }

    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    sbctl_context_init(&sbctl_ctx, NULL, idl, txn, symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        sbctl_context_init_command(&sbctl_ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&sbctl_ctx.base);
        }
        if (sbctl_ctx.base.error) {
            ctl_fatal("%s", sbctl_ctx.base.error);
        }
        sbctl_context_done_command(&sbctl_ctx, c);

        if (sbctl_ctx.base.try_again) {
            sbctl_context_done(&sbctl_ctx, NULL);
            goto try_again;
        }
    }
    sbctl_context_done(&sbctl_ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            ctl_fatal("row id \"%s\" is referenced but never created (e.g. "
                      "with \"-- --id=%s create ...\")",
                      node->name, node->name);
        }
        if (!symbol->strong_ref) {
            if (!symbol->weak_ref) {
                VLOG_WARN("row id \"%s\" was created but no reference to it "
                          "was inserted, so it will not actually appear in "
                          "the database", node->name);
            } else {
                VLOG_WARN("row id \"%s\" was created but only a weak "
                          "reference to it was inserted, so it will not "
                          "actually appear in the database", node->name);
            }
        }
    }

    status = ovsdb_idl_txn_commit_block(txn);
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                sbctl_context_init(&sbctl_ctx, c, idl, txn, symtab);
                (c->syntax->postprocess)(&sbctl_ctx.base);
                if (sbctl_ctx.base.error) {
                    ctl_fatal("%s", sbctl_ctx.base.error);
                }
                sbctl_context_done(&sbctl_ctx, c);
            }
        }
    }

    switch (status) {
    case TXN_UNCOMMITTED:
    case TXN_INCOMPLETE:
        OVS_NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        ctl_fatal("transaction aborted");

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        ctl_fatal("transaction error: %s", ovsdb_idl_txn_get_error(txn));

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        ctl_fatal("database not locked");

    default:
        OVS_NOT_REACHED();
    }

    ovsdb_symbol_table_destroy(symtab);

    for (c = commands; c < &commands[n_commands]; c++) {
        struct ds *ds = &c->output;

        if (c->table) {
            table_print(c->table, &table_style);
        } else if (oneline) {
            size_t j;

            ds_chomp(ds, '\n');
            for (j = 0; j < ds->length; j++) {
                int ch = ds->string[j];
                switch (ch) {
                case '\n':
                    fputs("\\n", stdout);
                    break;

                case '\\':
                    fputs("\\\\", stdout);
                    break;

                default:
                    putchar(ch);
                }
            }
            putchar('\n');
        } else {
            fputs(ds_cstr(ds), stdout);
        }
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);

        shash_destroy_free_data(&c->options);
    }
    free(commands);
    ovsdb_idl_txn_destroy(txn);
    ovsdb_idl_destroy(idl);

    return true;

try_again:
    /* Our transaction needs to be rerun, or a prerequisite was not met.  Free
     * resources and return so that the caller can try again. */
    ovsdb_idl_txn_abort(txn);
    ovsdb_idl_txn_destroy(txn);
    the_idl_txn = NULL;

    ovsdb_symbol_table_destroy(symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
    }
    return false;
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
sbctl_exit(int status)
{
    if (the_idl_txn) {
        ovsdb_idl_txn_abort(the_idl_txn);
        ovsdb_idl_txn_destroy(the_idl_txn);
    }
    ovsdb_idl_destroy(the_idl);
    exit(status);
}

static const struct ctl_command_syntax sbctl_commands[] = {
    { "init", 0, 0, "", NULL, sbctl_init, NULL, "", RW },

    /* Chassis commands. */
    {"chassis-add", 3, 3, "CHASSIS ENCAP-TYPE ENCAP-IP", pre_get_info,
     cmd_chassis_add, NULL, "--may-exist", RW},
    {"chassis-del", 1, 1, "CHASSIS", pre_get_info, cmd_chassis_del, NULL,
     "--if-exists", RW},

    /* Port binding commands. */
    {"lsp-bind", 2, 2, "PORT CHASSIS", pre_get_info, cmd_lsp_bind, NULL,
     "--may-exist", RW},
    {"lsp-unbind", 1, 1, "PORT", pre_get_info, cmd_lsp_unbind, NULL,
     "--if-exists", RW},

    /* Logical flow commands */
    {"lflow-list", 0, INT_MAX, "[DATAPATH] [LFLOW...]",
     pre_get_info, cmd_lflow_list, NULL,
     "--uuid,--ovs?,--stats,--vflows?", RO},
    {"dump-flows", 0, INT_MAX, "[DATAPATH] [LFLOW...]",
     pre_get_info, cmd_lflow_list, NULL,
     "--uuid,--ovs?,--stats,--vflows?",
     RO}, /* Friendly alias for lflow-list */

    /* IP multicast commands. */
    {"ip-multicast-flush", 0, 1, "SWITCH",
     pre_get_info, sbctl_ip_mcast_flush, NULL, "", RW },

    /* Connection commands. */
    {"get-connection", 0, 0, "", pre_connection, cmd_get_connection, NULL, "", RO},
    {"del-connection", 0, 0, "", pre_connection, cmd_del_connection, NULL, "", RW},
    {"set-connection", 1, INT_MAX, "TARGET...", pre_connection, cmd_set_connection,
     NULL, "--inactivity-probe=", RW},

    /* SSL commands. */
    {"get-ssl", 0, 0, "", pre_cmd_get_ssl, cmd_get_ssl, NULL, "", RO},
    {"del-ssl", 0, 0, "", pre_cmd_del_ssl, cmd_del_ssl, NULL, "", RW},
    {"set-ssl", 3, 5,
        "PRIVATE-KEY CERTIFICATE CA-CERT [SSL-PROTOS [SSL-CIPHERS]]",
        pre_cmd_set_ssl, cmd_set_ssl, NULL, "--bootstrap", RW},
    {"print-port-statistics", 0, 0, "", pre_cmd_print_port_statistics, cmd_print_port_statistics, NULL, "", RO},
    {"clear-port-statistics", 0, 0, "", pre_cmd_clear_port_statistics, cmd_clear_port_statistics, NULL, "", RW},

    {NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, RO},
};

/* Registers sbctl and common db commands. */
static void
sbctl_cmd_init(void)
{
    ctl_init(&sbrec_idl_class, sbrec_table_classes, tables,
             cmd_show_tables, sbctl_exit);
    ctl_register_commands(sbctl_commands);
}
