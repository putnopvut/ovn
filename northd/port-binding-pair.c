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

#include "port-binding-pair.h"

struct ovn_unpaired_port_binding *
ovn_unpaired_port_binding_alloc(uint32_t requested_tunnel_key,
                                const char *name,
                                enum ovn_port_type type,
                                void *cookie,
                                const struct sbrec_datapath_binding *sb_dp)
{
    struct ovn_unpaired_port_binding *pb = xmalloc(sizeof *pb);
    *pb = (struct ovn_unpaired_port_binding) {
        .requested_tunnel_key = requested_tunnel_key,
        .name = name,
        .type = type,
        .cookie = cookie,
        .sb_dp = sb_dp,
        .external_ids = SMAP_INITIALIZER(&pb->external_ids),
    };
    return pb;
}

void
ovn_unpaired_port_binding_destroy(struct ovn_unpaired_port_binding *pb)
{
    smap_destroy(&pb->external_ids);
}

bool
default_sb_is_valid(const struct sbrec_port_binding *sb_pb OVS_UNUSED,
                    const struct ovn_unpaired_port_binding *upb OVS_UNUSED)
{
    return true;
}

void
ovn_unpaired_port_binding_map_init(
    struct ovn_unpaired_port_binding_map *map,
    const struct ovn_unpaired_port_binding_map_callbacks *cb)
{
    *map = (struct ovn_unpaired_port_binding_map) {
        .cb = cb,
        .ports = SHASH_INITIALIZER(&map->ports),
    };
}

void
ovn_unpaired_port_binding_map_destroy(
    struct ovn_unpaired_port_binding_map *map)
{
    struct ovn_unpaired_port_binding *pb;
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &map->ports) {
        pb = node->data;
        map->cb->free_cookie(pb->cookie);
        shash_delete(&map->ports, node);
        ovn_unpaired_port_binding_destroy(pb);
        free(pb);
    }
    shash_destroy(&map->ports);
}
