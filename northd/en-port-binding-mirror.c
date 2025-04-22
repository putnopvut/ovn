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
#include "ovn-util.h"
#include "lib/inc-proc-eng.h"
#include "ovn-nb-idl.h"
#include "en-datapath-logical-switch.h"
#include "en-port-binding-mirror.h"
#include "port-binding-pair.h"
#include "northd.h"
#include "openvswitch/vlog.h"

#define MIRROR_PORT_TYPE "mirror"

VLOG_DEFINE_THIS_MODULE(en_port_binding_mirror);

struct mirror_port {
    char *name;
    const char *sink;
    const struct nbrec_logical_switch_port *nbsp;
};

static struct mirror_port *
mirror_port_alloc(const struct sbrec_datapath_binding *sb, const char *sink,
                  const struct nbrec_logical_switch_port *nbsp)
{
    struct mirror_port *mp = xmalloc(sizeof *mp);
    *mp = (struct mirror_port) {
        .name = ovn_mirror_port_name(ovn_datapath_name(sb), sink),
        .sink = sink,
        .nbsp = nbsp,
    };
    return mp;
}

static void
mirror_port_cookie_free(void *cookie)
{
    struct mirror_port *mp = cookie;
    free(mp->name);
    free(mp);
}

static struct ovn_unpaired_port_binding_map_callbacks mirror_port_callbacks = {
    .sb_is_valid = default_sb_is_valid,
    .free_cookie = mirror_port_cookie_free,
};

void *
en_port_binding_mirror_init(struct engine_node *node OVS_UNUSED,
                            struct engine_arg *arg OVS_UNUSED)
{
    struct ovn_unpaired_port_binding_map *map = xmalloc(sizeof *map);
    ovn_unpaired_port_binding_map_init(map, &mirror_port_callbacks);
    return map;
}

enum engine_node_state
en_port_binding_mirror_run(struct engine_node *node, void *data)
{
    const struct ovn_synced_logical_switch_map *ls_map =
        engine_get_input_data("datapath_synced_logical_switch", node);
    struct ovn_unpaired_port_binding_map *map = data;

    ovn_unpaired_port_binding_map_destroy(map);
    ovn_unpaired_port_binding_map_init(map, &mirror_port_callbacks);

    /* Typically, we'd use an ovsdb_idl_index to search for a specific record
     * based on a column value. However, we currently are not monitoring
     * the Logical_Switch_Port table at all in ovn-northd. Introducing
     * this monitoring is likely more computationally intensive than
     * making an on-the-fly sset of logical switch port names.
     */
    struct sset all_switch_ports = SSET_INITIALIZER(&all_switch_ports);
    const struct ovn_synced_logical_switch *ls;
    HMAP_FOR_EACH (ls, hmap_node, &ls_map->synced_switches) {
        for (size_t i = 0; i < ls->nb->n_ports; i++) {
            sset_add(&all_switch_ports, ls->nb->ports[i]->name);
        }
    }

    HMAP_FOR_EACH (ls, hmap_node, &ls_map->synced_switches) {
        for (size_t i = 0; i < ls->nb->n_ports; i++) {
            const struct nbrec_logical_switch_port *nbsp = ls->nb->ports[i];
            for (size_t j = 0; j < nbsp->n_mirror_rules; j++) {
                struct nbrec_mirror *nb_mirror = nbsp->mirror_rules[j];
                if (strcmp(nb_mirror->type, "lport")) {
                    continue;
                }
                if (!sset_find(&all_switch_ports, nb_mirror->sink)) {
                    continue;
                }
                struct mirror_port *mp = mirror_port_alloc(ls->sb,
                                                           nb_mirror->sink,
                                                           nbsp);
                struct ovn_unpaired_port_binding *upb;
                upb = ovn_unpaired_port_binding_alloc(0, mp->name,
                                                      PB_MIRROR_PORT, mp,
                                                      ls->sb);
                shash_add(&map->ports, mp->name, upb);
            }
        }
    }
    sset_destroy(&all_switch_ports);

    return EN_UPDATED;
}

void
en_port_binding_mirror_cleanup(void *data)
{
    struct ovn_unpaired_port_binding_map *map = data;
    ovn_unpaired_port_binding_map_destroy(map);
}

static void
ovn_paired_mirror_map_init(
    struct ovn_paired_mirror_map *map)
{
    *map = (struct ovn_paired_mirror_map) {
        .paired_mirror_ports = SHASH_INITIALIZER(&map->paired_mirror_ports),
    };
}

static void
ovn_paired_mirror_map_destroy(
    struct ovn_paired_mirror_map *map)
{
    shash_destroy_free_data(&map->paired_mirror_ports);
}

void *
en_port_binding_paired_mirror_init(struct engine_node *node OVS_UNUSED,
                                   struct engine_arg *arg OVS_UNUSED)
{
    struct ovn_paired_mirror_map *map = xmalloc(sizeof *map);
    ovn_paired_mirror_map_init(map);
    return map;
}

enum engine_node_state
en_port_binding_paired_mirror_run(struct engine_node *node,
                                  void *data)
{
    const struct ovn_paired_port_bindings *pbs =
        engine_get_input_data("port_binding_pair", node);
    struct ovn_paired_mirror_map *map = data;

    ovn_paired_mirror_map_destroy(map);
    ovn_paired_mirror_map_init(map);

    struct ovn_paired_port_binding *port;
    LIST_FOR_EACH (port, list_node, &pbs->paired_pbs) {
        if (port->type != PB_MIRROR_PORT) {
            continue;
        }
        const struct mirror_port *mp = port->cookie;
        struct ovn_paired_mirror *opm = xmalloc(sizeof *opm);
        *opm = (struct ovn_paired_mirror) {
            .name = mp->name,
            .sink = mp->sink,
            .sb = port->sb_pb,
            .nbsp = mp->nbsp,
        };
        shash_add(&map->paired_mirror_ports, opm->name, opm);
    }

    return EN_UPDATED;
}

void
en_port_binding_paired_mirror_cleanup(void *data)
{
    struct ovn_paired_mirror_map *map = data;

    ovn_paired_mirror_map_destroy(map);
}

