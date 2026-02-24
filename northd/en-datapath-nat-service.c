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
#include "en-datapath-nat-service.h"
#include "ovn-nb-idl.h"
#include "en-datapath-sync.h"

void *
en_datapath_nat_service_init(struct engine_node *node OVS_UNUSED,
                             struct engine_arg *args OVS_UNUSED)
{
    struct ovn_unsynced_datapath_map *map = xmalloc(sizeof *map);
    ovn_unsynced_datapath_map_init(map, DP_NAT_SERVICE);
    return map;
}

enum engine_input_handler_result
datapath_nat_service_handler(struct engine_node *node OVS_UNUSED,
                             void *data OVS_UNUSED)
{
    const struct nbrec_nat_service_table *nb_ns_table =
        EN_OVSDB_GET(engine_get_input("NB_nat_service", node));

    struct ovn_unsynced_datapath_map *map = data;

    struct ovn_unsynced_datapath *udp;
    const struct nbrec_nat_service *ns;
    NBREC_NAT_SERVICE_TABLE_FOR_EACH_TRACKED (ns, nb_ns_table) {
        /* If the NAT service is added and removed within the same
         * transaction, then this is a no-op
         */
        if (nbrec_nat_service_is_new(ns) &&
            nbrec_nat_service_is_deleted(ns)) {
            continue;
        }
        udp = ovn_unsynced_datapath_find(map, &ns->header_.uuid);

        if (nbrec_nat_service_is_deleted(ns) && !udp) {
            return EN_UNHANDLED;
        }

        if (nbrec_nat_service_is_new(ns) && udp) {
            return EN_UNHANDLED;
        }

        if (udp) {
            if (nbrec_nat_service_is_deleted(ns)) {
                hmap_remove(&map->dps, &udp->hmap_node);
                hmapx_add(&map->deleted, udp);
            } else {
                hmapx_add(&map->updated, udp);
            }
        } else {
            udp = ovn_unsynced_datapath_alloc(ns->name, DP_NAT_SERVICE, 0,
                                              &ns->header_);
            hmap_insert(&map->dps, &udp->hmap_node,
                        uuid_hash(&ns->header_.uuid));
            hmapx_add(&map->new, udp);
        }
    }

    if (!(hmapx_is_empty(&map->new) && hmapx_is_empty(&map->updated) &&
        hmapx_is_empty(&map->deleted))) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}

enum engine_node_state
en_datapath_nat_service_run(struct engine_node *node, void *data)
{
    const struct nbrec_nat_service_table *nb_ns_table =
        EN_OVSDB_GET(engine_get_input("NB_nat_service", node));

    struct ovn_unsynced_datapath_map *map = data;

    ovn_unsynced_datapath_map_destroy(map);
    ovn_unsynced_datapath_map_init(map, DP_NAT_SERVICE);

    const struct nbrec_nat_service *ns;
    NBREC_NAT_SERVICE_TABLE_FOR_EACH (ns, nb_ns_table) {
        struct ovn_unsynced_datapath  *udp =
            ovn_unsynced_datapath_alloc(ns->name, DP_NAT_SERVICE,
                                        0, &ns->header_);
        hmap_insert(&map->dps, &udp->hmap_node, uuid_hash(&ns->header_.uuid));
    }
    return EN_UNCHANGED;
}

void
en_datapath_nat_service_cleanup(void *data)
{
    struct ovn_unsynced_datapath_map *map = data;
    ovn_unsynced_datapath_map_destroy(map);
}

void
en_datapath_nat_service_clear_tracked_data(void *data OVS_UNUSED)
{
    ovn_unsynced_datapath_map_clear_tracked_data(data);
}

struct ovn_synced_nat_service *
ovn_synced_nat_service_find(const struct ovn_synced_nat_service_map *map,
                               const struct uuid *nb_uuid)
{
    struct ovn_synced_nat_service *ns;
    HMAP_FOR_EACH_WITH_HASH (ns, hmap_node, uuid_hash(nb_uuid),
                             &map->synced_nats) {
        if (uuid_equals(&ns->nb->header_.uuid, nb_uuid)) {
            return ns;
        }
    }

    return NULL;
}

static void
synced_nat_service_map_init(
    struct ovn_synced_nat_service_map *nat_map)
{
    *nat_map = (struct ovn_synced_nat_service_map) {
        .synced_nats = HMAP_INITIALIZER(&nat_map->synced_nats),
        .new = HMAPX_INITIALIZER(&nat_map->new),
        .updated = HMAPX_INITIALIZER(&nat_map->updated),
        .deleted = HMAPX_INITIALIZER(&nat_map->deleted),
    };
}

static void
synced_nat_service_map_destroy(
    struct ovn_synced_nat_service_map *nat_map)
{
    hmapx_destroy(&nat_map->new);
    hmapx_destroy(&nat_map->updated);

    struct hmapx_node *node;
    struct ovn_synced_nat_service *ns;
    HMAPX_FOR_EACH_SAFE (node, &nat_map->deleted) {
        ns = node->data;
        free(ns);
        hmapx_delete(&nat_map->deleted, node);
    }
    hmapx_destroy(&nat_map->deleted);
    HMAP_FOR_EACH_POP (ns, hmap_node, &nat_map->synced_nats) {
        free(ns);
    }
    hmap_destroy(&nat_map->synced_nats);
}
void *
en_datapath_synced_nat_service_init(struct engine_node *node OVS_UNUSED,
                                    struct engine_arg *args OVS_UNUSED)
{
    struct ovn_synced_nat_service_map *nat_map;
    nat_map = xmalloc(sizeof *nat_map);
    synced_nat_service_map_init(nat_map);

    return nat_map;
}

static struct ovn_synced_nat_service *
synced_nat_service_alloc(const struct ovn_synced_datapath *sdp)
{
    struct ovn_synced_nat_service *ns = xmalloc(sizeof *ns);
    *ns = (struct ovn_synced_nat_service) {
        .nb = CONTAINER_OF(sdp->nb_row, struct nbrec_nat_service,
                           header_),
        .sdp = sdp,
    };
    return ns;
}

enum engine_node_state
en_datapath_synced_nat_service_run(struct engine_node *node, void *data)
{
    const struct all_synced_datapaths *all_dps =
        engine_get_input_data("datapath_sync", node);
    const struct ovn_synced_datapaths *dps =
        &all_dps->synced_dps[DP_NAT_SERVICE];
    struct ovn_synced_nat_service_map *nat_map = data;

    synced_nat_service_map_destroy(nat_map);
    synced_nat_service_map_init(nat_map);

    struct ovn_synced_datapath *sdp;
    HMAP_FOR_EACH (sdp, hmap_node, &dps->synced_dps) {
        struct ovn_synced_nat_service *ns =
            synced_nat_service_alloc(sdp);
        hmap_insert(&nat_map->synced_nats, &ns->hmap_node,
                    uuid_hash(&ns->nb->header_.uuid));
    }

    return EN_UPDATED;
}

void
en_datapath_synced_nat_service_clear_tracked_data(void *data)
{
    struct ovn_synced_nat_service_map *nat_map = data;

    hmapx_clear(&nat_map->new);
    hmapx_clear(&nat_map->updated);

    struct hmapx_node *node;
    HMAPX_FOR_EACH_SAFE (node, &nat_map->deleted) {
        struct ovn_synced_nat_service *ns = node->data;
        free(ns);
        hmapx_delete(&nat_map->deleted, node);
    }
}

enum engine_input_handler_result
en_datapath_synced_nat_service_datapath_sync_handler(
        struct engine_node *node, void *data)
{
    const struct all_synced_datapaths *all_dps =
        engine_get_input_data("datapath_sync", node);
    const struct ovn_synced_datapaths *dps =
        &all_dps->synced_dps[DP_NAT_SERVICE];
    struct ovn_synced_nat_service_map *nat_map = data;

    if (!all_dps->has_tracked_data) {
        return EN_UNHANDLED;
    }

    struct hmapx_node *hmapx_node;
    struct ovn_synced_datapath *sdp;
    struct ovn_synced_nat_service *ns;
    HMAPX_FOR_EACH (hmapx_node, &dps->new) {
        sdp = hmapx_node->data;
        ns = synced_nat_service_alloc(sdp);
        hmap_insert(&nat_map->synced_nats, &ns->hmap_node,
                    uuid_hash(&ns->nb->header_.uuid));
        hmapx_add(&nat_map->new, ns);
    }

    HMAPX_FOR_EACH (hmapx_node, &dps->deleted) {
        sdp = hmapx_node->data;
        ns = ovn_synced_nat_service_find(nat_map, &sdp->nb_row->uuid);
        if (!ns) {
            return EN_UNHANDLED;
        }
        hmap_remove(&nat_map->synced_nats, &ns->hmap_node);
        hmapx_add(&nat_map->deleted, ns);
    }

    HMAPX_FOR_EACH (hmapx_node, &dps->updated) {
        sdp = hmapx_node->data;
        ns = ovn_synced_nat_service_find(nat_map, &sdp->nb_row->uuid);
        if (!ns) {
            return EN_UNHANDLED;
        }
        ns->nb = CONTAINER_OF(sdp->nb_row, struct nbrec_nat_service,
                               header_);
        ns->sdp = sdp;
        hmapx_add(&nat_map->updated, ns);
    }

    if (hmapx_is_empty(&nat_map->new) &&
        hmapx_is_empty(&nat_map->updated) &&
        hmapx_is_empty(&nat_map->deleted)) {
        return EN_HANDLED_UNCHANGED;
    }

    return EN_HANDLED_UPDATED;
}

void
en_datapath_synced_nat_service_cleanup(void *data)
{
    struct ovn_synced_nat_service_map *nat_map = data;
    synced_nat_service_map_destroy(nat_map);
}

