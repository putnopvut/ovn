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

#include "inc-proc-eng.h"
#include "ovn-nb-idl.h"
#include "en-datapath-logical-router.h"
#include "en-datapath-logical-switch.h"
#include "en-port-binding-chassisredirect.h"
#include "port-binding-pair.h"
#include "ovn-util.h"
#include "vec.h"

#include "openvswitch/vlog.h"

#include "hmapx.h"

VLOG_DEFINE_THIS_MODULE(en_port_binding_chassisredirect_port);

struct router_dgps {
    const struct ovn_synced_logical_router *lr;
    struct vector dgps;
};

static struct router_dgps *
router_dgps_alloc(const struct ovn_synced_logical_router *lr)
{
    struct router_dgps *rdgps = xmalloc(sizeof *rdgps);
    *rdgps = (struct router_dgps) {
        .lr = lr,
        .dgps =
            VECTOR_EMPTY_INITIALIZER(const struct sbrec_logical_router_port *),
    };
    return rdgps;
}

static void
router_dgps_free(struct router_dgps *rdgps)
{
    vector_destroy(&rdgps->dgps);
    free(rdgps);
}

struct switch_localnets {
    const struct ovn_synced_logical_switch *ls;
    size_t n_localnet_ports;
};

struct port_router_dgps {
    const struct nbrec_logical_router_port *nbrp;
    struct router_dgps *r;
};

static struct port_router_dgps *
port_router_dgps_alloc(const struct nbrec_logical_router_port *nbrp,
                       struct router_dgps *r)
{
    struct port_router_dgps *p_dgps = xmalloc(sizeof *p_dgps);
    *p_dgps = (struct port_router_dgps) {
        .nbrp = nbrp,
        .r = r,
    };

    return p_dgps;
}

struct chassisredirect_port {
    char *name;
    union {
        const struct nbrec_logical_router_port *nbrp;
        const struct nbrec_logical_switch_port *nbsp;
    };
    enum ovn_datapath_type dp_type;
};

static struct chassisredirect_port *
chassisredirect_router_port_alloc(const struct nbrec_logical_router_port *nbrp)
{
    struct chassisredirect_port *crp = xmalloc(sizeof *crp);
    *crp = (struct chassisredirect_port) {
        .name = ovn_chassis_redirect_name(nbrp->name),
        .nbrp = nbrp,
        .dp_type = DP_ROUTER,
    };

    return crp;
}

static struct chassisredirect_port *
chassisredirect_switch_port_alloc(const struct nbrec_logical_switch_port *nbsp)
{
    struct chassisredirect_port *crp = xmalloc(sizeof *crp);
    *crp = (struct chassisredirect_port) {
        .name = ovn_chassis_redirect_name(nbsp->name),
        .nbsp = nbsp,
        .dp_type = DP_SWITCH,
    };

    return crp;
}

static void
chassisredirect_port_free(void *cookie)
{
    struct chassisredirect_port *crp = cookie;
    free(crp->name);
    free(crp);
}

static struct ovn_unpaired_port_binding_map_callbacks cr_callbacks = {
    .sb_is_valid = default_sb_is_valid,
    .free_cookie = chassisredirect_port_free,
};

void *
en_port_binding_chassisredirect_port_init(struct engine_node *node OVS_UNUSED,
                                         struct engine_arg *args OVS_UNUSED)
{
    struct ovn_unpaired_port_binding_map *map = xmalloc(sizeof *map);
    ovn_unpaired_port_binding_map_init(map, &cr_callbacks);
    return map;
}


enum engine_node_state
en_port_binding_chassisredirect_port_run(struct engine_node *node, void *data)
{
    const struct ovn_synced_logical_router_map *lr_map =
        engine_get_input_data("datapath_synced_logical_router", node);
    const struct ovn_synced_logical_switch_map *ls_map =
        engine_get_input_data("datapath_synced_logical_switch", node);

    struct ovn_unpaired_port_binding_map *map = data;

    ovn_unpaired_port_binding_map_destroy(map);
    ovn_unpaired_port_binding_map_init(map, &cr_callbacks);

    struct shash ports = SHASH_INITIALIZER(&ports);
    const struct ovn_synced_logical_router *lr;
    struct hmapx all_rdgps = HMAPX_INITIALIZER(&all_rdgps);
    HMAP_FOR_EACH (lr, hmap_node, &lr_map->synced_routers) {
        if (smap_get(&lr->nb->options, "chassis")) {
            /* If the logical router has the chassis option set,
             * then we ignore any ports that have gateway_chassis
             * or ha_chassis_group options set.
             */
            continue;
        }
        struct router_dgps *rdgps = router_dgps_alloc(lr);
        hmapx_add(&all_rdgps, rdgps);
        const struct nbrec_logical_router_port *nbrp;
        for (size_t i = 0; i < lr->nb->n_ports; i++) {
            nbrp = lr->nb->ports[i];
            if (nbrp->ha_chassis_group || nbrp->n_gateway_chassis) {
                vector_push(&rdgps->dgps, &nbrp);
                shash_add(&ports, nbrp->name,
                          port_router_dgps_alloc(nbrp, rdgps));
            }
        }
    }

    struct hmapx all_localnets = HMAPX_INITIALIZER(&all_localnets);
    const struct ovn_synced_logical_switch *ls;
    HMAP_FOR_EACH (ls, hmap_node, &ls_map->synced_switches) {
        struct switch_localnets *localnets = xmalloc(sizeof *localnets);
        *localnets = (struct switch_localnets) {
            .ls = ls,
        };
        hmapx_add(&all_localnets, localnets);
        for (size_t i = 0; i < ls->nb->n_ports; i++) {
            const struct nbrec_logical_switch_port *nbsp = ls->nb->ports[i];
            if (!strcmp(nbsp->type, "localnet")) {
                localnets->n_localnet_ports++;
            }
        }
    }

    /* All logical router DGPs need corresponding chassisredirect ports
     * made
     */
    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH (hmapx_node, &all_rdgps) {
        struct router_dgps *rdgps = hmapx_node->data;
        struct ovn_unpaired_port_binding *upb;
        const struct nbrec_logical_router_port *nbrp;
        VECTOR_FOR_EACH (&rdgps->dgps, nbrp) {
            struct chassisredirect_port *crp =
                chassisredirect_router_port_alloc(nbrp);
            upb = ovn_unpaired_port_binding_alloc(0, crp->name,
                                                  PB_CHASSISREDIRECT_PORT,
                                                  crp, rdgps->lr->sb);
            shash_add(&map->ports, crp->name, upb);
        }
    }

    /* Logical switch ports that are peered with DGPs need chassisredirect
     * ports created if
     * 1. The DGP it is paired with is the only one on its router, and
     * 2. There are no localnet ports on the switch
     */
    HMAPX_FOR_EACH (hmapx_node, &all_localnets) {
        struct switch_localnets *localnets = hmapx_node->data;
        if (localnets->n_localnet_ports > 0) {
            continue;
        }
        for (size_t i = 0; i < localnets->ls->nb->n_ports; i++) {
            const struct nbrec_logical_switch_port *nbsp =
                localnets->ls->nb->ports[i];
            if (strcmp(nbsp->type, "router")) {
                continue;
            }
            const char *peer_name = smap_get(&nbsp->options, "router-port");
            if (!peer_name) {
                continue;
            }
            struct port_router_dgps *prdgps = shash_find_data(&ports,
                                                              peer_name);
            if (!prdgps) {
                continue;
            }
            if (vector_len(&prdgps->r->dgps) > 1) {
                continue;
            }
            struct ovn_unpaired_port_binding *upb;
            struct chassisredirect_port *crp =
                chassisredirect_switch_port_alloc(nbsp);
            upb = ovn_unpaired_port_binding_alloc(0, crp->name,
                                                  PB_CHASSISREDIRECT_PORT,
                                                  crp, localnets->ls->sb);
            shash_add(&map->ports, crp->name, upb);
        }
    }

    HMAPX_FOR_EACH (hmapx_node, &all_rdgps) {
        router_dgps_free(hmapx_node->data);
    }
    hmapx_destroy(&all_rdgps);
    shash_destroy_free_data(&ports);
    HMAPX_FOR_EACH (hmapx_node, &all_localnets) {
        free(hmapx_node->data);
    }
    hmapx_destroy(&all_localnets);

    return EN_UPDATED;
}

void
en_port_binding_chassisredirect_port_cleanup(void *data)
{
    struct ovn_unpaired_port_binding_map *map = data;
    ovn_unpaired_port_binding_map_destroy(map);
}


static void
ovn_paired_chassisredirect_port_map_init(
    struct ovn_paired_chassisredirect_port_map *map)
{
    *map = (struct ovn_paired_chassisredirect_port_map) {
        .paired_chassisredirect_ports =
            SHASH_INITIALIZER(&map->paired_chassisredirect_ports),
    };
}

static void
ovn_paired_chassisredirect_port_map_destroy(
    struct ovn_paired_chassisredirect_port_map *map)
{
    shash_destroy_free_data(&map->paired_chassisredirect_ports);
}

void *
en_port_binding_paired_chassisredirect_port_init(
    struct engine_node *node OVS_UNUSED, struct engine_arg *args OVS_UNUSED)
{
    struct ovn_paired_chassisredirect_port_map *map = xmalloc(sizeof *map);
    ovn_paired_chassisredirect_port_map_init(map);
    return map;
}

enum engine_node_state
en_port_binding_paired_chassisredirect_port_run(struct engine_node *node,
                                                void *data)
{
    const struct ovn_paired_port_bindings *pbs =
        engine_get_input_data("port_binding_pair", node);
    struct ovn_paired_chassisredirect_port_map *map = data;

    ovn_paired_chassisredirect_port_map_destroy(map);
    ovn_paired_chassisredirect_port_map_init(map);

    struct ovn_paired_port_binding *port;
    LIST_FOR_EACH (port, list_node, &pbs->paired_pbs) {
        if (port->type != PB_CHASSISREDIRECT_PORT) {
            continue;
        }

        const struct chassisredirect_port *cr_port = port->cookie;
        struct ovn_paired_chassisredirect_port *paired_cr_port;
        paired_cr_port = xmalloc(sizeof *paired_cr_port);
        *paired_cr_port = (struct ovn_paired_chassisredirect_port) {
            .name = cr_port->name,
            .sb = port->sb_pb,
            .dp_type = cr_port->dp_type,
        };
        if (paired_cr_port->dp_type == DP_SWITCH) {
            paired_cr_port->primary_nbsp = cr_port->nbsp;
        } else {
            paired_cr_port->primary_nbrp = cr_port->nbrp;
        }
        shash_add(&map->paired_chassisredirect_ports, cr_port->name,
                  paired_cr_port);
    }

    return EN_UPDATED;
}

void
en_port_binding_paired_chassisredirect_port_cleanup(void *data)
{
    struct ovn_paired_chassisredirect_port_map *map = data;

    ovn_paired_chassisredirect_port_map_destroy(map);
}
