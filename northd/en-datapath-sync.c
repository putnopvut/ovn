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

#include "uuidset.h"

#include "en-datapath-sync.h"
#include "en-global-config.h"
#include "datapath_sync.h"
#include "ovn-sb-idl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(datapath_sync);

void *
en_datapath_sync_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *args OVS_UNUSED)
{
    struct ovn_synced_datapaths *synced_datapaths
        = xzalloc(sizeof *synced_datapaths);
    ovs_list_init(&synced_datapaths->synced_dps);

    return synced_datapaths;
}

static struct ovn_unsynced_datapath *
find_unsynced_datapath(const struct ovn_unsynced_datapath_map **maps,
                       size_t n_maps,
                       const struct sbrec_datapath_binding *sb_dp,
                       const char **map_key)
{
    struct uuid key;
    const struct ovn_unsynced_datapath_map *map;
    bool found_map = false;
    *map_key = NULL;
    for (size_t i = 0; i < n_maps; i++) {
        map = maps[i];
        if (smap_get_uuid(&sb_dp->external_ids, map->sb_key_name, &key)) {
            found_map = true;
            break;
        }
    }

    if (!found_map) {
        return NULL;
    }
    ovs_assert(map);
    *map_key = map->sb_key_name;

    uint32_t hash = uuid_hash(&key);
    struct ovn_unsynced_datapath *dp;
    HMAP_FOR_EACH_WITH_HASH (dp, hmap_node, hash, &map->dps) {
        if (uuid_equals(&key, &dp->nb_row->uuid)) {
            return dp;
        }
    }

    return NULL;
}

struct candidate_sdp {
    struct ovs_list list_node;
    struct ovn_synced_datapath *sdp;
    uint32_t requested_tunnel_key;
    uint32_t existing_tunnel_key;
};

static struct candidate_sdp *
candidate_sdp_alloc(const struct ovn_unsynced_datapath *udp,
                    const struct sbrec_datapath_binding *sb_dp)
{
    struct ovn_synced_datapath *sdp;
    sdp = xzalloc(sizeof *sdp);
    sdp->sb_dp = sb_dp;
    sdp->nb_row = udp->nb_row;
    sbrec_datapath_binding_set_external_ids(sb_dp, &udp->external_ids);

    struct candidate_sdp *candidate;
    candidate = xzalloc(sizeof *candidate);
    candidate->sdp = sdp;
    candidate->requested_tunnel_key = udp->requested_tunnel_key;
    candidate->existing_tunnel_key = sdp->sb_dp->tunnel_key;

    return candidate;
}

static void
reset_synced_datapaths(struct ovn_synced_datapaths *synced_datapaths)
{
    struct ovn_synced_datapath *sdp;
    LIST_FOR_EACH_POP (sdp, list_node, &synced_datapaths->synced_dps) {
        free(sdp);
    }
    ovs_list_init(&synced_datapaths->synced_dps);
}

static void
create_synced_datapath_candidates_from_sb(
    const struct sbrec_datapath_binding_table *sb_dp_table,
    struct uuidset *visited,
    const struct ovn_unsynced_datapath_map **input_maps,
    size_t n_input_maps,
    struct ovs_list *candidate_sdps)
{
    const struct sbrec_datapath_binding *sb_dp;
    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_SAFE (sb_dp, sb_dp_table) {
        const char *map_key;
        struct ovn_unsynced_datapath *udp;
        udp = find_unsynced_datapath(input_maps, n_input_maps, sb_dp,
                                     &map_key);
        if (!udp) {
            sbrec_datapath_binding_delete(sb_dp);
            continue;
        }

        if (uuidset_find(visited, &udp->nb_row->uuid)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(
                &rl, "deleting Datapath_Binding "UUID_FMT" with "
                "duplicate external-ids:%s "UUID_FMT,
                UUID_ARGS(&sb_dp->header_.uuid), map_key,
                UUID_ARGS(&udp->nb_row->uuid));
            sbrec_datapath_binding_delete(sb_dp);
            continue;
        }

        struct candidate_sdp *candidate;
        candidate = candidate_sdp_alloc(udp, sb_dp);
        ovs_list_push_back(candidate_sdps, &candidate->list_node);
        uuidset_insert(visited, &udp->nb_row->uuid);
    }
}

static void
create_synced_datapath_candidates_from_nb(
    const struct ovn_unsynced_datapath_map **input_maps,
    size_t n_input_maps,
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct uuidset *visited,
    struct ovs_list *candidate_sdps)
{
    for (size_t i = 0; i < n_input_maps; i++) {
        const struct ovn_unsynced_datapath_map *map = input_maps[i];
        struct ovn_unsynced_datapath *udp;
        HMAP_FOR_EACH (udp, hmap_node, &map->dps) {
            if (uuidset_find(visited, &udp->nb_row->uuid)) {
                continue;
            }
            struct sbrec_datapath_binding *sb_dp;
            sb_dp = sbrec_datapath_binding_insert(ovnsb_idl_txn);
            struct candidate_sdp *candidate;
            candidate = candidate_sdp_alloc(udp, sb_dp);
            ovs_list_push_back(candidate_sdps, &candidate->list_node);
        }
    }
}

static void
assign_requested_tunnel_keys(struct ovs_list *candidate_sdps,
                             struct hmap *dp_tnlids,
                             struct ovn_synced_datapaths *synced_datapaths)
{
    struct candidate_sdp *candidate;
    LIST_FOR_EACH_SAFE (candidate, list_node, candidate_sdps) {
        if (!candidate->requested_tunnel_key) {
            continue;
        }
        if (ovn_add_tnlid(dp_tnlids, candidate->requested_tunnel_key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical datapath "UUID_FMT" requests same "
                         "tunnel key %"PRIu32" as another logical datapath",
                         UUID_ARGS(&candidate->sdp->nb_row->uuid),
                         candidate->requested_tunnel_key);
        }
        sbrec_datapath_binding_set_tunnel_key(candidate->sdp->sb_dp,
                                              candidate->requested_tunnel_key);
        ovs_list_remove(&candidate->list_node);
        ovs_list_push_back(&synced_datapaths->synced_dps,
                           &candidate->sdp->list_node);
        free(candidate);
    }
}

static void
assign_existing_tunnel_keys(struct ovs_list *candidate_sdps,
                            struct hmap *dp_tnlids,
                            struct ovn_synced_datapaths *synced_datapaths)
{
    struct candidate_sdp *candidate;
    LIST_FOR_EACH_SAFE (candidate, list_node, candidate_sdps) {
        if (!candidate->existing_tunnel_key) {
            continue;
        }
        /* Existing southbound DP. If this key is available,
         * reuse it.
         */
        if (ovn_add_tnlid(dp_tnlids, candidate->existing_tunnel_key)) {
            ovs_list_remove(&candidate->list_node);
            ovs_list_push_back(&synced_datapaths->synced_dps,
                               &candidate->sdp->list_node);
            free(candidate);
        }
    }
}

static void
allocate_tunnel_keys(struct ovs_list *candidate_sdps,
                     struct hmap *dp_tnlids,
                     uint32_t max_dp_tunnel_id,
                     struct ovn_synced_datapaths *synced_datapaths)
{
    uint32_t hint = 0;
    struct candidate_sdp *candidate;
    LIST_FOR_EACH_SAFE (candidate, list_node, candidate_sdps) {
        uint32_t tunnel_key =
            ovn_allocate_tnlid(dp_tnlids, "datapath", OVN_MIN_DP_KEY_LOCAL,
                               max_dp_tunnel_id, &hint);
        if (!tunnel_key) {
            continue;
        }
        sbrec_datapath_binding_set_tunnel_key(candidate->sdp->sb_dp,
                                              tunnel_key);
        ovs_list_remove(&candidate->list_node);
        ovs_list_push_back(&synced_datapaths->synced_dps,
                           &candidate->sdp->list_node);
        free(candidate);
    }
}

static void
delete_candidates(struct ovs_list *candidate_sdps)
{
    struct candidate_sdp *candidate;
    LIST_FOR_EACH_POP (candidate, list_node, candidate_sdps) {
        sbrec_datapath_binding_delete(candidate->sdp->sb_dp);
        free(candidate->sdp);
        free(candidate);
    }
}

void
en_datapath_sync_run(struct engine_node *node , void *data)
{
    const struct sbrec_datapath_binding_table *sb_dp_table =
        EN_OVSDB_GET(engine_get_input("SB_datapath_binding", node));
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    /* The inputs are:
     * * Some number of input maps.
     * * Southbound Datapath Binding table.
     * * Global config data.
     *
     * Therefore, the number of inputs - 2 is the number of input
     * maps from the datapath-specific nodes.
     */
    size_t n_input_maps = node->n_inputs - 2;
    const struct ovn_unsynced_datapath_map **input_maps =
        xmalloc(n_input_maps * sizeof *input_maps);
    struct ovn_synced_datapaths *synced_datapaths = data;

    for (size_t i = 0; i < n_input_maps; i++) {
        input_maps[i] = engine_get_data(node->inputs[i].node);
    }

    reset_synced_datapaths(synced_datapaths);

    struct uuidset visited = UUIDSET_INITIALIZER(&visited);
    struct ovs_list candidate_sdps = OVS_LIST_INITIALIZER(&candidate_sdps);
    create_synced_datapath_candidates_from_sb(sb_dp_table, &visited,
                                              input_maps, n_input_maps,
                                              &candidate_sdps);

    const struct engine_context *eng_ctx = engine_get_context();
    create_synced_datapath_candidates_from_nb(input_maps, n_input_maps,
                                              eng_ctx->ovnsb_idl_txn, &visited,
                                              &candidate_sdps);
    uuidset_destroy(&visited);

    struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
    assign_requested_tunnel_keys(&candidate_sdps, &dp_tnlids,
                                 synced_datapaths);
    assign_existing_tunnel_keys(&candidate_sdps, &dp_tnlids, synced_datapaths);
    allocate_tunnel_keys(&candidate_sdps, &dp_tnlids,
                         global_config->max_dp_tunnel_id, synced_datapaths);

    /* Any remaining candidates could not be synced due to tunnel key
     * issues and need to be deleted.
     */
    delete_candidates(&candidate_sdps);

    ovn_destroy_tnlids(&dp_tnlids);
    free(input_maps);

    engine_set_node_state(node, EN_UPDATED);
}

void en_datapath_sync_cleanup(void *data)
{
    struct ovn_synced_datapaths *synced_datapaths = data;
    struct ovn_synced_datapath *sdp;

    LIST_FOR_EACH_POP (sdp, list_node, &synced_datapaths->synced_dps) {
        free(sdp);
    }
}
