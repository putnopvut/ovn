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

#ifndef EN_PORT_BINDING_MIRROR_H
#define EN_PORT_BINDING_MIRROR_H

#include "lib/inc-proc-eng.h"
#include "openvswitch/shash.h"

void *en_port_binding_mirror_init(struct engine_node *,
                                  struct engine_arg *);

enum engine_node_state en_port_binding_mirror_run(struct engine_node *,
                                                  void *data);
void en_port_binding_mirror_cleanup(void *data);

struct ovn_paired_mirror {
    const char *name;
    const char *sink;
    const struct nbrec_logical_switch_port *nbsp;
    const struct sbrec_port_binding *sb;
};

struct ovn_paired_mirror_map {
    struct shash paired_mirror_ports;
};

void *en_port_binding_paired_mirror_init(struct engine_node *,
                                         struct engine_arg *);

enum engine_node_state en_port_binding_paired_mirror_run(struct engine_node *,
                                                         void *data);
void en_port_binding_paired_mirror_cleanup(void *data);

#endif /* EN_PORT_BINDING_MIRROR_H */
