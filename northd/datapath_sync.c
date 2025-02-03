/* Copyright (c) 2025, Red Hat, Inc.
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

#include "datapath_sync.h"

struct ovn_unsynced_datapath *
ovn_unsynced_datapath_alloc(const char *name, uint32_t requested_tunnel_key,
                            const struct ovsdb_idl_row *nb_row)
{
    struct ovn_unsynced_datapath *dp = xzalloc(sizeof *dp);
    dp->name = xstrdup(name);
    dp->requested_tunnel_key = requested_tunnel_key;
    dp->nb_row = nb_row;
    smap_init(&dp->external_ids);

    return dp;
}

void
ovn_unsynced_datapath_destroy(struct ovn_unsynced_datapath *dp)
{
    free(dp->name);
    smap_destroy(&dp->external_ids);
}

void
ovn_unsynced_datapath_map_init(struct ovn_unsynced_datapath_map *map,
                               const char *sb_key_name)
{
    hmap_init(&map->dps);
    map->sb_key_name = sb_key_name;
}

void
ovn_unsynced_datapath_map_destroy(struct ovn_unsynced_datapath_map *map)
{
    struct ovn_unsynced_datapath *dp;
    HMAP_FOR_EACH_POP (dp, hmap_node, &map->dps) {
        ovn_unsynced_datapath_destroy(dp);
        free(dp);
    }
    hmap_destroy(&map->dps);
}
