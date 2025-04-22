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

#ifndef EN_PORT_BINDING_PAIR_H
#define EN_PORT_BINDING_PAIR_H

#include "inc-proc-eng.h"

void *en_port_binding_pair_init(struct engine_node *node,
                            struct engine_arg *args);
enum engine_node_state en_port_binding_pair_run(struct engine_node *node,
                                                void *data);
void en_port_binding_pair_cleanup(void *data);

enum engine_input_handler_result
port_binding_fdb_change_handler(struct engine_node *, void *data);

#endif /* EN_PORT_BINDING_PAIR_H */
