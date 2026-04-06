/*
 * Copyright (c) 2026, Red Hat, Inc.
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

#include "datapath-sync.h"
#include "en-port-binding-service.h"
#include "en-datapath-nat-service.h"
#include "inc-proc-eng.h"
#include "ovn-sb-idl.h"
#include "ovn-nb-idl.h"
#include "northd.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_port_binding_service);

/* Used for managing tunnel keys for service ports */
struct service_datapath {
    struct hmap_node hmap_node;
    const struct ovn_synced_datapath *sdp;
    struct hmap port_tnlids;
    uint32_t port_key_hint;
};

struct service_port {
    const char *name;
    /* The associated northbound Service Port. This will be NULL
     * if the service_port is representing a switch or router port
     */
    const struct nbrec_service_port *nb;
    /* The datapath that the service port is attached to. This will
     * be NULL if the service_port is representing a switch or
     * router port
     */
    struct service_datapath *service;
    /* The UUID to use for the SB Port_Binding. */
    struct uuid sb_uuid;
    /* The SB port binding representing this service port. */
    const struct sbrec_port_binding *sb;
    uint32_t tunnel_key;
};

static void
service_port_destroy(struct service_port *sp, bool delete_sb)
{
    if (sp->sb && delete_sb) {
        sbrec_port_binding_delete(sp->sb);
    }
    free(sp);
}

static void
destroy_service_ports(struct shash *ports, bool delete_sb)
{
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, ports) {
        struct service_port *sp = node->data;
        shash_delete(ports, node);
        service_port_destroy(sp, delete_sb);
    }
    shash_destroy(ports);
}

static void
destroy_sync_data(struct service_ports *ports)
{
    destroy_service_ports(&ports->all_service_ports, false);
    struct service_datapath *service_dp;
    HMAP_FOR_EACH_POP (service_dp, hmap_node, &ports->all_service_dps) {
        ovn_destroy_tnlids(&service_dp->port_tnlids);
        free(service_dp);
    }
    hmap_destroy(&ports->all_service_dps);
}

static void
init_service_ports(struct service_ports *ports)
{
    shash_init(&ports->all_service_ports);
    hmap_init(&ports->all_service_dps);
}

void *
en_port_binding_service_init(struct engine_node *node OVS_UNUSED,
                             struct engine_arg *arg OVS_UNUSED)
{
    struct service_ports *ports = xmalloc(sizeof *ports);
    init_service_ports(ports);
    return ports;
}

/* There's no such thing as multicast tunnel keys for services,
 * but we'll still cap the tunnel key at 32767 just so there
 * isn't confusion regarding the allocated tunnel keys.
 */
#define MAX_SERVICE_PORT_TNLID 32767

static bool
allocate_tunnel_key(struct service_port *sp)
{
    if (sp->tunnel_key) {
        return true;
    }

    sp->tunnel_key = ovn_allocate_tnlid(&sp->service->port_tnlids,
                                        "service_port", 1,
                                        MAX_SERVICE_PORT_TNLID,
                                        &sp->service->port_key_hint);
    if (!sp->tunnel_key) {
        return false;
    }
    return true;
}

static bool
sync_port(struct ovsdb_idl_txn *ovnsb_idl_txn, struct service_port *sp)
{
    if (!sp->sb) {
        ovs_assert(!sp->tunnel_key);
        sp->sb = sbrec_port_binding_insert_persist_uuid(ovnsb_idl_txn,
                                                        &sp->sb_uuid);
        if (!allocate_tunnel_key(sp)) {
            return false;
        }
    } else {
        /* We already added the tunnel key earlier */
        ovs_assert(sp->tunnel_key);
    }
    sbrec_port_binding_set_datapath(sp->sb, sp->service->sdp->sb_dp);
    sbrec_port_binding_set_logical_port(sp->sb, sp->name);
    sbrec_port_binding_set_type(sp->sb, "service");
    sbrec_port_binding_set_tunnel_key(sp->sb, sp->tunnel_key);

    struct smap options = SMAP_INITIALIZER(&options);
    smap_clone(&options, &sp->sb->options);
    if (sp->nb->complement && sp->nb->complement[0]) {
        smap_add(&options, "service_complement_port", sp->nb->complement);
    }
    if (sp->nb->peer && sp->nb->peer[0]) {
        smap_add(&options, "service_peer_port", sp->nb->peer);
    }
    sbrec_port_binding_set_options(sp->sb, &options);
    smap_destroy(&options);
    return true;
}

static bool validate_and_set_complement(struct ovsdb_idl_txn *ovnsb_idl_txn,
                                        struct shash *candidates,
                                        struct shash *ports,
                                        struct shash_node *port_node);

static bool
validate_and_set_peer(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      struct shash *candidates, struct shash *ports,
                      struct shash_node *port_node)
{
    struct service_port *peer = NULL;
    struct service_port *port = port_node->data;
    if (!port->nb->peer || !port->nb->peer[0]) {
        /* We've reached the end of the chain */
        goto end;
    }
    struct shash_node *peer_node = shash_find(candidates, port->nb->peer);
    if (!peer_node) {
        return false;
    }
    peer = peer_node->data;
    if (!peer->nb->peer || !peer->nb->peer[0] ||
        strcmp(peer->nb->peer, port->name)) {
        return false;
    }
    if (!validate_and_set_complement(ovnsb_idl_txn, candidates, ports,
                                     peer_node)) {
        return false;
    }

end:
    if (!sync_port(ovnsb_idl_txn, port)) {
        return false;
    }
    shash_delete(candidates, port_node);
    shash_add(ports, port->name, port);
    return true;
}

static bool
validate_and_set_complement(struct ovsdb_idl_txn *ovnsb_idl_txn,
                            struct shash *candidates, struct shash *ports,
                            struct shash_node *port_node)
{
    struct service_port *port = port_node->data;
    if (!port->nb->complement || !port->nb->complement[0]) {
        return false;
    }
    struct shash_node *complement_node = shash_find(candidates,
                                                    port->nb->complement);
    if (!complement_node) {
        return false;
    }
    struct service_port *complement = complement_node->data;
    if (port->service != complement->service ||
        strcmp(complement->nb->complement, port->name)) {
        return false;
    }
    if (!validate_and_set_peer(ovnsb_idl_txn, candidates, ports,
                               complement_node)) {
        return false;
    }
    if (!sync_port(ovnsb_idl_txn, port)) {
        return false;
    }

    shash_delete(candidates, port_node);
    shash_add(ports, port->name, port);
    return true;
}

static void
validate_chain(struct ovsdb_idl_txn *ovnsb_idl_txn, struct shash *candidates,
               struct shash *ports, const struct sbrec_port_binding *op_sb,
               const struct smap *op_nb_options)
{
    struct smap options;
    smap_clone(&options, &op_sb->options);
    smap_remove(&options, "service_peer_port");

    const char *peer_port_name = smap_get(op_nb_options, "service_peer_port");
    if (!peer_port_name || !peer_port_name[0]) {
        goto end;
    }
    struct shash_node *port_node = shash_find(candidates, peer_port_name);
    if (!port_node) {
        goto end;
    }
    struct service_port *sp = port_node->data;
    if (!validate_and_set_complement(ovnsb_idl_txn, candidates, ports, port_node)) {
        goto end;
    }

    /* We also need to be sure the SB Port_Binding for the switch/router port
     * has the first Service_Port in the chain marked as a peer.
     */
    ovs_assert(sp->sb);
    smap_add(&options, "service_peer_port", peer_port_name);

end:
    sbrec_port_binding_set_options(op_sb, &options);
    smap_destroy(&options);
}

enum engine_node_state
en_port_binding_service_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct sbrec_port_binding_table *pb_table =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    const struct ovn_synced_nat_service_map *synced_nats =
        engine_get_input_data("datapath_synced_nat_service", node);
    const struct engine_context *eng_ctx = engine_get_context();

    struct service_ports *ports = data;
    destroy_sync_data(ports);
    init_service_ports(ports);

    /* Start by building service ports based on SB port bindings.
     */
    struct shash sb_service_ports = SHASH_INITIALIZER(&sb_service_ports);
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (pb, pb_table) {
        if (port_binding_is_northd(pb)) {
            continue;
        }
        struct service_port *sp = xmalloc(sizeof *sp);
        /* We only need a barebones service port here. We will
         * fill it out with more detail later if necessary.
         */
        *sp = (struct service_port) {
            .name = pb->logical_port,
            .sb_uuid = pb->header_.uuid,
            .sb = pb,
            .tunnel_key = pb->tunnel_key,
        };
        shash_add(&sb_service_ports, sp->name, sp);
    }

    /* Now add northbound service ports to the candidates. */
    struct shash candidates = SHASH_INITIALIZER(&candidates);
    const struct ovn_synced_nat_service *nat_service;
    HMAP_FOR_EACH (nat_service, hmap_node, &synced_nats->synced_nats) {
        if (!nat_service->nb->n_ports) {
            continue;
        }
        struct service_datapath *service_dp = xmalloc(sizeof *service_dp);
        *service_dp = (struct service_datapath) {
            .sdp = nat_service->sdp,
            .port_tnlids = HMAP_INITIALIZER(&service_dp->port_tnlids),
        };
        hmap_insert(&ports->all_service_dps, &service_dp->hmap_node,
                    uuid_hash(&nat_service->nb->header_.uuid));
        for (size_t i = 0; i < nat_service->nb->n_ports; i++) {
            const struct nbrec_service_port *nb_port =
                nat_service->nb->ports[i];
            struct service_port *svc_port =
                shash_find_and_delete(&sb_service_ports, nb_port->name);
            if (!svc_port) {
                svc_port = xmalloc(sizeof *svc_port);
                *svc_port = (struct service_port) {
                    .name = nb_port->name,
                    .service = service_dp,
                    .nb = nb_port,
                    .sb_uuid = uuid_random(),
                };
            } else {
                svc_port->service = service_dp;
                svc_port->nb = nb_port;

                /* Add the existing tunnel key so we don't get any
                 * collisions later when we allocate new ones.
                 */
                ovs_assert(svc_port->tunnel_key);
                ovn_add_tnlid(&svc_port->service->port_tnlids,
                              svc_port->tunnel_key);
                if (svc_port->tunnel_key > svc_port->service->port_key_hint) {
                    svc_port->service->port_key_hint = svc_port->tunnel_key;
                }
            }
            shash_add(&candidates, nb_port->name, svc_port);
        }
    }
    
    /* Follow the chain of service ports from the switch and router ports.
     * The recursive functions ensure that the service ports are only synced
     * to the SB DB if the entire chain is valid.
     */
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, &northd_data->ls_ports) {
        validate_chain(eng_ctx->ovnsb_idl_txn, &candidates,
                       &ports->all_service_ports, op->sb,
                       &op->nbsp->options);
    }
    /* Do the same for router ports */
    HMAP_FOR_EACH (op, key_node, &northd_data->lr_ports) {
        validate_chain(eng_ctx->ovnsb_idl_txn, &candidates,
                       &ports->all_service_ports, op->sb,
                       &op->nbrp->options);
    }

    /* Any ports that remain in sb_service_ports have no northbound matches and
     * should be removed from the SB DB.
     */
    destroy_service_ports(&sb_service_ports, true);
    /* Anything remaining in candidates either form invalid chains or are
     * disconnected from any switch or router ports.
     */
    destroy_service_ports(&candidates, true);

    return EN_UPDATED;
}

void
en_port_binding_service_clear_tracked_data(void *data OVS_UNUSED)
{
}

void
en_port_binding_service_cleanup(void *data OVS_UNUSED)
{
    struct service_ports *ports = data;
    destroy_sync_data(ports);
}
