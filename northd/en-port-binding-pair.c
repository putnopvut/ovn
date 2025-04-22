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

#include "en-port-binding-pair.h"
#include "en-global-config.h"
#include "port-binding-pair.h"
#include "ovn-sb-idl.h"
#include "mcast-group-index.h"
#include "vec.h"

#include "simap.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(port_binding_pair);

void *
en_port_binding_pair_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *args OVS_UNUSED)
{
    struct ovn_paired_port_bindings *paired_port_bindings
        = xmalloc(sizeof *paired_port_bindings);
    ovs_list_init(&paired_port_bindings->paired_pbs);
    hmap_init(&paired_port_bindings->tunnel_key_maps);

    return paired_port_bindings;
}

static struct ovn_unpaired_port_binding *
find_unpaired_port_binding(const struct ovn_unpaired_port_binding_map **maps,
                           const struct sbrec_port_binding *sb_pb)
{
    const struct ovn_unpaired_port_binding_map *map;

    for (size_t i = 0; i < PB_MAX; i++) {
        map = maps[i];
        struct ovn_unpaired_port_binding *upb;
        upb = shash_find_data(&map->ports, sb_pb->logical_port);
        if (upb && map->cb->sb_is_valid(sb_pb, upb)) {
            return upb;
        }
    }

    return NULL;
}

struct tunnel_key_map {
    struct hmap_node hmap_node;
    uint32_t datapath_tunnel_key;
    struct hmap port_tunnel_keys;
};

static struct tunnel_key_map *
find_tunnel_key_map(uint32_t datapath_tunnel_key,
                    const struct hmap *tunnel_key_maps)
{
    uint32_t hash = hash_int(datapath_tunnel_key, 0);
    struct tunnel_key_map *key_map;
    HMAP_FOR_EACH_WITH_HASH (key_map, hmap_node, hash, tunnel_key_maps) {
        if (key_map->datapath_tunnel_key == datapath_tunnel_key) {
            return key_map;
        }
    }
    return NULL;
}

static struct tunnel_key_map *
alloc_tunnel_key_map(uint32_t datapath_tunnel_key,
                     struct hmap *tunnel_key_maps)
{
    uint32_t hash = hash_int(datapath_tunnel_key, 0);
    struct tunnel_key_map *key_map;

    key_map = xmalloc(sizeof *key_map);
    *key_map = (struct tunnel_key_map) {
        .datapath_tunnel_key = datapath_tunnel_key,
        .port_tunnel_keys = HMAP_INITIALIZER(&key_map->port_tunnel_keys),
    };
    hmap_insert(tunnel_key_maps, &key_map->hmap_node, hash);

    return key_map;
}

static struct tunnel_key_map *
find_or_alloc_tunnel_key_map(const struct sbrec_datapath_binding *sb_dp,
                             struct hmap *tunnel_key_maps)
{
    struct tunnel_key_map *key_map = find_tunnel_key_map(sb_dp->tunnel_key,
                                                         tunnel_key_maps);
    if (!key_map) {
        key_map = alloc_tunnel_key_map(sb_dp->tunnel_key, tunnel_key_maps);
    }
    return key_map;
}

static void
tunnel_key_maps_destroy(struct hmap *tunnel_key_maps)
{
    struct tunnel_key_map *key_map;
    HMAP_FOR_EACH_POP (key_map, hmap_node, tunnel_key_maps) {
        ovn_destroy_tnlids(&key_map->port_tunnel_keys);
        free(key_map);
    }
    hmap_destroy(tunnel_key_maps);
}

struct candidate_spb {
    struct ovn_paired_port_binding *spb;
    uint32_t requested_tunnel_key;
    uint32_t existing_tunnel_key;
    struct tunnel_key_map *tunnel_key_map;
    bool tunnel_key_assigned;
};

static void
reset_port_binding_pair_data(
    struct ovn_paired_port_bindings *paired_port_bindings)
{
    /* Free the old paired port_bindings */
    struct ovn_paired_port_binding *spb;
    LIST_FOR_EACH_POP (spb, list_node, &paired_port_bindings->paired_pbs) {
        free(spb);
    }
    tunnel_key_maps_destroy(&paired_port_bindings->tunnel_key_maps);

    hmap_init(&paired_port_bindings->tunnel_key_maps);
    ovs_list_init(&paired_port_bindings->paired_pbs);
}

static struct ovn_paired_port_binding *
ovn_paired_port_binding_alloc(const struct sbrec_port_binding *sb_pb,
                              const struct ovn_unpaired_port_binding *upb)
{
    struct ovn_paired_port_binding *spb;
    spb = xmalloc(sizeof *spb);
    *spb = (struct ovn_paired_port_binding) {
        .sb_pb = sb_pb,
        .cookie = upb->cookie,
        .type = upb->type,
    };
    sbrec_port_binding_set_external_ids(sb_pb, &upb->external_ids);
    sbrec_port_binding_set_logical_port(sb_pb, upb->name);

    return spb;
}

static void
get_candidate_pbs_from_sb(
    const struct sbrec_port_binding_table *sb_pb_table,
    const struct ovn_unpaired_port_binding_map **input_maps,
    struct hmap *tunnel_key_maps, struct vector *candidate_spbs,
    struct simap *visited)
{
    const struct sbrec_port_binding *sb_pb;
    const struct ovn_unpaired_port_binding *upb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_SAFE (sb_pb, sb_pb_table) {
        upb = find_unpaired_port_binding(input_maps, sb_pb);
        if (!upb) {
            sbrec_port_binding_delete(sb_pb);
            continue;
        }

        if (!uuid_equals(&upb->sb_dp->header_.uuid,
            &sb_pb->datapath->header_.uuid)) {
            /* A matching unpaired port was found for this port binding, but it
             * has moved to a different datapath. Delete the old SB port
             * binding so that a new one will be created later when we traverse
             * unpaired port bindings later.
             */
            sbrec_port_binding_delete(sb_pb);
            continue;
        }

        if (!simap_put(visited, sb_pb->logical_port, upb->type)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(
                &rl, "deleting port_binding "UUID_FMT" with "
                "duplicate name %s",
                UUID_ARGS(&sb_pb->header_.uuid), sb_pb->logical_port);
            sbrec_port_binding_delete(sb_pb);
            continue;
        }
        struct candidate_spb candidate = {
            .spb = ovn_paired_port_binding_alloc(sb_pb, upb),
            .requested_tunnel_key = upb->requested_tunnel_key,
            .existing_tunnel_key = sb_pb->tunnel_key,
            .tunnel_key_map =
                find_or_alloc_tunnel_key_map(upb->sb_dp, tunnel_key_maps),
        };
        vector_push(candidate_spbs, &candidate);
    }
}

static void
get_candidate_pbs_from_nb(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    const struct ovn_unpaired_port_binding_map **input_maps,
    struct hmap *tunnel_key_maps,
    struct vector *candidate_spbs,
    struct simap *visited)
{
    for (size_t i = 0; i < PB_MAX; i++) {
        const struct ovn_unpaired_port_binding_map *map = input_maps[i];
        struct shash_node *shash_node;
        SHASH_FOR_EACH (shash_node, &map->ports) {
            const struct ovn_unpaired_port_binding *upb = shash_node->data;
            struct simap_node *visited_node = simap_find(visited, upb->name);
            if (visited_node) {
                if (upb->type != visited_node->data) {
                    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5,
                                                                            1);
                    VLOG_WARN_RL(&rl, "duplicate logical port %s", upb->name);
                }
                continue;
            } else {
                /* Add the port to "visited" to help with detection of
                 * duplicated port names across different types of ports.
                 */
                simap_put(visited, upb->name, upb->type);
            }
            const struct sbrec_port_binding *sb_pb;
            sb_pb = sbrec_port_binding_insert(ovnsb_idl_txn);
            struct candidate_spb candidate = {
                .spb = ovn_paired_port_binding_alloc(sb_pb, upb),
                .requested_tunnel_key = upb->requested_tunnel_key,
                .existing_tunnel_key = sb_pb->tunnel_key,
                .tunnel_key_map =
                    find_or_alloc_tunnel_key_map(upb->sb_dp, tunnel_key_maps),
            };
            vector_push(candidate_spbs, &candidate);
        }
    }
}

static void
pair_requested_tunnel_keys(struct vector *candidate_spbs,
                           struct ovs_list *paired_pbs,
                           bool vxlan_mode)
{
    struct candidate_spb *candidate;
    VECTOR_FOR_EACH_PTR (candidate_spbs, candidate) {
        if (!candidate->requested_tunnel_key) {
            continue;
        }
        if (vxlan_mode &&
            candidate->requested_tunnel_key >= OVN_VXLAN_MIN_MULTICAST) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Tunnel key %"PRIu32" for port %s"
                         " is incompatible with VXLAN",
                         candidate->requested_tunnel_key,
                         candidate->spb->sb_pb->logical_port);
            continue;
        }

        if (!ovn_add_tnlid(&candidate->tunnel_key_map->port_tunnel_keys,
                          candidate->requested_tunnel_key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical port_binding %s requests same "
                         "tunnel key %"PRIu32" as another logical "
                         "port_binding on the same datapath",
                         candidate->spb->sb_pb->logical_port,
                         candidate->requested_tunnel_key);
            continue;
        }
        sbrec_port_binding_set_tunnel_key(candidate->spb->sb_pb,
                                          candidate->requested_tunnel_key);
        candidate->tunnel_key_assigned = true;
        ovs_list_push_back(paired_pbs, &candidate->spb->list_node);
    }
}

static void
pair_existing_tunnel_keys(struct vector *candidate_spbs,
                          struct ovs_list *paired_pbs)
{
    struct candidate_spb *candidate;
    VECTOR_FOR_EACH_PTR (candidate_spbs, candidate) {
        if (!candidate->existing_tunnel_key ||
            candidate->tunnel_key_assigned) {
            continue;
        }
        /* Existing southbound pb. If this key is available,
         * reuse it.
         */
        if (ovn_add_tnlid(&candidate->tunnel_key_map->port_tunnel_keys,
                          candidate->existing_tunnel_key)) {
            candidate->tunnel_key_assigned = true;
            ovs_list_push_back(paired_pbs, &candidate->spb->list_node);
        }
    }
}

static void
pair_new_tunnel_keys(struct vector *candidate_spbs,
                     struct ovs_list *paired_pbs,
                     uint32_t max_pb_tunnel_id)
{
    uint32_t hint = 0;
    struct candidate_spb *candidate;
    VECTOR_FOR_EACH_PTR (candidate_spbs, candidate) {
        if (candidate->tunnel_key_assigned) {
            continue;
        }
        uint32_t tunnel_key =
            ovn_allocate_tnlid(&candidate->tunnel_key_map->port_tunnel_keys,
                               "port", 1, max_pb_tunnel_id,
                               &hint);
        if (!tunnel_key) {
            continue;
        }
        sbrec_port_binding_set_tunnel_key(candidate->spb->sb_pb,
                                              tunnel_key);
        candidate->tunnel_key_assigned = true;
        ovs_list_push_back(paired_pbs, &candidate->spb->list_node);
    }
}

static void
free_unpaired_candidates(struct vector *candidate_spbs)
{
    struct candidate_spb *candidate;
    VECTOR_FOR_EACH_PTR (candidate_spbs, candidate) {
        if (candidate->tunnel_key_assigned) {
            continue;
        }
        sbrec_port_binding_delete(candidate->spb->sb_pb);
        free(candidate->spb);
    }
}

static void
cleanup_stale_fdb_entries(const struct sbrec_fdb_table *sbrec_fdb_table,
                          struct hmap *tunnel_key_maps)
{
    const struct sbrec_fdb *fdb_e;
    SBREC_FDB_TABLE_FOR_EACH_SAFE (fdb_e, sbrec_fdb_table) {
        bool delete = true;
        struct tunnel_key_map *map = find_tunnel_key_map(fdb_e->dp_key,
                                                         tunnel_key_maps);
        if (map &&
            ovn_tnlid_present(&map->port_tunnel_keys, fdb_e->port_key)) {
            delete = false;
        }

        if (delete) {
            sbrec_fdb_delete(fdb_e);
        }
    }
}

enum engine_node_state
en_port_binding_pair_run(struct engine_node *node , void *data)
{
    const struct sbrec_port_binding_table *sb_pb_table =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    const struct sbrec_fdb_table *sb_fdb_table =
        EN_OVSDB_GET(engine_get_input("SB_fdb", node));
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    const struct ovn_unpaired_port_binding_map *lsp_map =
        engine_get_input_data("port_binding_logical_switch_port", node);
    const struct ovn_unpaired_port_binding_map *lrp_map =
        engine_get_input_data("port_binding_logical_router_port", node);
    const struct ovn_unpaired_port_binding_map *crp_map =
        engine_get_input_data("port_binding_chassisredirect_port", node);
    const struct ovn_unpaired_port_binding_map *mp_map =
        engine_get_input_data("port_binding_mirror", node);

    const struct ovn_unpaired_port_binding_map *input_maps[PB_MAX];

    input_maps[PB_SWITCH_PORT] = lsp_map;
    input_maps[PB_ROUTER_PORT] = lrp_map;
    input_maps[PB_CHASSISREDIRECT_PORT] = crp_map;
    input_maps[PB_MIRROR_PORT] = mp_map;

    size_t num_ports = 0;
    for (size_t i = 0; i < PB_MAX; i++) {
        ovs_assert(input_maps[i]);
        num_ports += shash_count(&input_maps[i]->ports);
    }

    struct ovn_paired_port_bindings *paired_port_bindings = data;
    reset_port_binding_pair_data(paired_port_bindings);

    struct simap visited = SIMAP_INITIALIZER(&visited);
    struct vector candidate_spbs =
        VECTOR_CAPACITY_INITIALIZER(struct candidate_spb, num_ports);
    get_candidate_pbs_from_sb(sb_pb_table, input_maps,
                              &paired_port_bindings->tunnel_key_maps,
                              &candidate_spbs, &visited);

    const struct engine_context *eng_ctx = engine_get_context();
    get_candidate_pbs_from_nb(eng_ctx->ovnsb_idl_txn, input_maps,
                              &paired_port_bindings->tunnel_key_maps,
                              &candidate_spbs, &visited);

    simap_destroy(&visited);

    pair_requested_tunnel_keys(&candidate_spbs,
                               &paired_port_bindings->paired_pbs,
                               global_config->vxlan_mode);
    pair_existing_tunnel_keys(&candidate_spbs,
                              &paired_port_bindings->paired_pbs);
    pair_new_tunnel_keys(&candidate_spbs, &paired_port_bindings->paired_pbs,
                         global_config->max_pb_tunnel_id);

    cleanup_stale_fdb_entries(sb_fdb_table,
                              &paired_port_bindings->tunnel_key_maps);

    free_unpaired_candidates(&candidate_spbs);
    vector_destroy(&candidate_spbs);

    return EN_UPDATED;
}

void
en_port_binding_pair_cleanup(void *data)
{
    struct ovn_paired_port_bindings *paired_port_bindings = data;
    struct ovn_paired_port_binding *spb;

    LIST_FOR_EACH_POP (spb, list_node, &paired_port_bindings->paired_pbs) {
        free(spb);
    }
    tunnel_key_maps_destroy(&paired_port_bindings->tunnel_key_maps);
}

enum engine_input_handler_result
port_binding_fdb_change_handler(struct engine_node *node, void *data)
{
    struct ovn_paired_port_bindings *paired_port_bindings = data;
    const struct sbrec_fdb_table *sbrec_fdb_table =
        EN_OVSDB_GET(engine_get_input("SB_fdb", node));

    /* check if changed rows are stale and delete them */
    const struct sbrec_fdb *fdb_e, *fdb_prev_del = NULL;
    SBREC_FDB_TABLE_FOR_EACH_TRACKED (fdb_e, sbrec_fdb_table) {
        if (sbrec_fdb_is_deleted(fdb_e)) {
            continue;
        }

        if (fdb_prev_del) {
            sbrec_fdb_delete(fdb_prev_del);
        }

        fdb_prev_del = fdb_e;
        struct tunnel_key_map *tunnel_key_map =
            find_tunnel_key_map(fdb_e->dp_key,
                                &paired_port_bindings->tunnel_key_maps);
        if (tunnel_key_map &&
            ovn_tnlid_present(&tunnel_key_map->port_tunnel_keys,
                              fdb_e->port_key)) {
            fdb_prev_del = NULL;
        }
    }

    if (fdb_prev_del) {
        sbrec_fdb_delete(fdb_prev_del);
    }

    return EN_HANDLED_UNCHANGED;
}
