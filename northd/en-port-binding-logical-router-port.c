/*
 * Copyright (c) 2025, Red Hat, Inc.
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

#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "util.h"

#include "inc-proc-eng.h"
#include "ovn-nb-idl.h"
#include "port-binding-pair.h"
#include "en-datapath-logical-router.h"
#include "en-port-binding-logical-router-port.h"

VLOG_DEFINE_THIS_MODULE(en_port_binding_logical_router_port);

struct logical_router_port_cookie {
    const struct nbrec_logical_router_port *nbrp;
    const struct ovn_synced_logical_router *router;
};

static struct logical_router_port_cookie *
logical_router_port_cookie_alloc(const struct nbrec_logical_router_port *nbrp,
                                 const struct ovn_synced_logical_router *lr)
{
    struct logical_router_port_cookie *cookie = xmalloc(sizeof *cookie);
    *cookie = (struct logical_router_port_cookie) {
        .nbrp = nbrp,
        .router = lr,
    };
    return cookie;
}

static void
logical_router_port_cookie_free(void *cookie)
{
    struct logical_router_port_cookie *lrp_cookie = cookie;
    free(lrp_cookie);
}

static struct ovn_unpaired_port_binding_map_callbacks router_port_callbacks = {
    .sb_is_valid = default_sb_is_valid,
    .free_cookie = logical_router_port_cookie_free,
};

void *
en_port_binding_logical_router_port_init(struct engine_node *node OVS_UNUSED,
                                         struct engine_arg *args OVS_UNUSED)
{
    struct ovn_unpaired_port_binding_map *map = xmalloc(sizeof *map);
    ovn_unpaired_port_binding_map_init(map, &router_port_callbacks);
    return map;
}

enum engine_node_state
en_port_binding_logical_router_port_run(struct engine_node *node, void *data)
{
    const struct ovn_synced_logical_router_map *lr_map =
        engine_get_input_data("datapath_synced_logical_router", node);

    struct ovn_unpaired_port_binding_map *map = data;

    ovn_unpaired_port_binding_map_destroy(map);
    ovn_unpaired_port_binding_map_init(map, &router_port_callbacks);

    const struct ovn_synced_logical_router *paired_lr;
    HMAP_FOR_EACH (paired_lr, hmap_node, &lr_map->synced_routers) {
        const struct nbrec_logical_router_port *nbrp;
        for (size_t i = 0; i < paired_lr->nb->n_ports; i++) {
            nbrp = paired_lr->nb->ports[i];
            uint32_t requested_tunnel_key = smap_get_int(&nbrp->options,
                                                         "requested-tnl-key",
                                                         0);
            struct logical_router_port_cookie *cookie =
                logical_router_port_cookie_alloc(nbrp, paired_lr);
            struct ovn_unpaired_port_binding *upb;
            upb = ovn_unpaired_port_binding_alloc(requested_tunnel_key,
                                                  nbrp->name,
                                                  PB_ROUTER_PORT,
                                                  cookie,
                                                  paired_lr->sb);
            smap_clone(&upb->external_ids, &nbrp->external_ids);
            if (!shash_add_once(&map->ports, nbrp->name, upb)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "duplicate logical router port %s",
                             nbrp->name);
            }
        }
    }

    return EN_UPDATED;
}

void
en_port_binding_logical_router_port_cleanup(void *data)
{
    struct ovn_unpaired_port_binding_map *map = data;
    ovn_unpaired_port_binding_map_destroy(map);
}

static void
paired_logical_router_port_map_init(
    struct ovn_paired_logical_router_port_map *router_port_map)
{
    *router_port_map = (struct ovn_paired_logical_router_port_map) {
        .paired_router_ports =
            SHASH_INITIALIZER(&router_port_map->paired_router_ports),
    };
}

static void
paired_logical_router_port_map_destroy(
    struct ovn_paired_logical_router_port_map *router_port_map)
{
    shash_destroy_free_data(&router_port_map->paired_router_ports);
}

void *
en_port_binding_paired_logical_router_port_init(
    struct engine_node *node OVS_UNUSED, struct engine_arg *args OVS_UNUSED)
{
    struct ovn_paired_logical_router_port_map *router_port_map =
        xmalloc(sizeof *router_port_map);
    paired_logical_router_port_map_init(router_port_map);

    return router_port_map;
}

enum engine_node_state
en_port_binding_paired_logical_router_port_run(struct engine_node *node,
                                               void *data)
{
    const struct ovn_paired_port_bindings *pbs =
        engine_get_input_data("port_binding_pair", node);
    struct ovn_paired_logical_router_port_map *router_port_map = data;

    paired_logical_router_port_map_destroy(router_port_map);
    paired_logical_router_port_map_init(router_port_map);

    struct ovn_paired_port_binding *spb;
    LIST_FOR_EACH (spb, list_node, &pbs->paired_pbs) {
        if (spb->type != PB_ROUTER_PORT) {
            continue;
        }
        const struct logical_router_port_cookie *cookie = spb->cookie;
        struct ovn_paired_logical_router_port *lrp = xmalloc(sizeof *lrp);
        *lrp = (struct ovn_paired_logical_router_port) {
            .nb = cookie->nbrp,
            .router = cookie->router,
            .sb = spb->sb_pb,
        };
        shash_add(&router_port_map->paired_router_ports, lrp->nb->name, lrp);
    }

    return EN_UPDATED;
}

void en_port_binding_paired_logical_router_port_cleanup(void *data)
{
    struct ovn_paired_logical_router_port_map *map = data;
    paired_logical_router_port_map_destroy(map);
}
