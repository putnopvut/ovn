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

#ifndef EN_PORT_BINDING_LOGICAL_SWITCH_PORT_H
#define EN_PORT_BINDING_LOGICAL_SWITCH_PORT_H

#include "lib/inc-proc-eng.h"
#include "openvswitch/shash.h"


void *en_port_binding_logical_switch_port_init(struct engine_node *,
                                           struct engine_arg *);

enum engine_node_state en_port_binding_logical_switch_port_run(
    struct engine_node *, void *data);
void en_port_binding_logical_switch_port_cleanup(void *data);

struct ovn_paired_logical_switch_port {
    const struct nbrec_logical_switch_port *nb;
    const struct sbrec_port_binding *sb;
    const struct ovn_synced_logical_switch *sw;
};

struct ovn_paired_logical_switch_port_map {
    struct shash paired_switch_ports;
};

void *en_port_binding_paired_logical_switch_port_init(struct engine_node *,
                                                      struct engine_arg *);

enum engine_node_state en_port_binding_paired_logical_switch_port_run(
    struct engine_node *, void *data);
void en_port_binding_paired_logical_switch_port_cleanup(void *data);

#endif /* EN_PORT_BINDING_LOGICAL_SWITCH_PORT_H */
