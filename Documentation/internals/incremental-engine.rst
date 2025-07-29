..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in OVN documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

=================================
How to use the Incremental Engine
=================================

Overview
--------
This document's intended audience is contributors to OVN's code.

When writing OVN code, developers will inevitably find themselves needing to
interface with the incremental engine code. The incremental engine code is
complex and has many nuances. This guide will discuss the incremental engine,
how to use it, and also give some ideas for future improvements to the engine
that might make it slightly easier to use.

Basics
------
The incremental engine is defined in the ``lib/`` directory of ovn, in the
``inc-proc-eng.h`` and ``inc-proc-eng.c`` files.

An incremental engine consists of incremental nodes. The job of an incremental
node is to compute a set of data that can then be used by other incremental
nodes. An incremental node whose data is used directly by another incremental
node is referred to as an "input node".

ovn-northd and ovn-controller each make use of a single incremental engine.
During initialization of the application, the engine is initialized by linking
the nodes together in a directed graph. The incremental engine then performs a
topological sort of the directed graph in order to sort the nodes into an
array. When an iteration of the OVN application main loop is executed, the
nodes of the array are iterated over in order, attempting to calculate each
node's data. Based on the state of each node, and that node's inputs, the node
may do one of two things:

* compute: In this scenario, the node is able to apply changes calculated by
  input nodes and update its own data in place. However, if circumstances do
  not allow for in-place input, then the node will fall back to its other
  possibility, which is:
* recompute: In this scenario, the node clears any of its current data and
  recalculates it from scratch based on the data from input nodes.

The goal of the incremental engine is to hit the "compute" scenario more often
than the "recompute" scenario, since in-place updates of data are less
CPU-intense than recalculating all of the engine node's data.

While both ovn-northd and ovn-controller use the incremental engine, their
usage patterns are different. ovn-northd's main job is to convert data from the
northbound database into data for the southbound database. As a result,
ovn-northd's code is written almost 100% in terms of the incremental engine.
ovn-controller, on the other hand, uses the incremental engine to calculate
some runtime data. Then the bulk of the ovn-controller code uses the data
calculated by the incremental engine to act on the data as necessary. When
working in ovn-controller, it is important to note whether the code is
operating within the incremental engine or after the incremental engine has
run.

Declaring an Engine Node
------------------------
Engine nodes are structs of type ``struct engine_node``. Each engine node
consists of its own data, and a series of callbacks. The three required
callbacks are:

* ``init()``: This function is called once during incremental engine
  initialization. This function is used to allocate the engine node's data, and
  if possible initialize the data. It is likely that when this data is
  recomputed, the data will need to be reinitialized, but it should never need
  to be reallocated.
* ``cleanup()``: This function is called once when the application shuts down.
  This function is responsible for freeing any engine node data. However, it
  should not actually free the ``node->data`` pointer itself, since this is
  handled by the incremental engine internals.
* ``run()``: This function is called when the engine node recomputes. A typical
  ``run()`` callback will start by clearing the engine node's data and
  reinitializing it. The ``run()`` callback will then use the engine node's
  input node data to compute its own data, saving it in the ``node->data``.

There are also three optional callbacks:

* ``is_valid()``: When an engine node retrieves data from an input node, the
  incremental engine needs to determine if the data from the input node is
  valid. By default, as long as the data in the input node is not stale (we
  will go over engine states later in the document), then the data is
  considered valid. The ``is_valid()`` callback provides engine nodes with the
  ability to override this default behavior. For instance, the data may be
  valid even if the input node is stale.
* ``clear_tracked_data()``: This will be covered when we discuss input
  handlers.
* ``get_compute_failure_info()``: This will be covered when we discuss input
  handlers.

To declare a new engine node, use the ``ENGINE_NODE()`` macro. You can find
examples of ``ENGINE_NODE()`` in ovn-northd in ``northd/inc-proc-northd.c`` and
in ovn-controller in ``controller/ovn-controller.c``. For the rest of this
documentat, we will be dealing with a hypothetical engine node called "foo". We
can declare foo with the following: ::

    ENGINE_NODE(foo);

Under the hood, this will create a ``struct engine_node en_foo``. The
``init()``, ``run()``, and ``cleanup()`` callbacks will be set to the functions
``en_foo_init()``, ``en_foo_run()``, and ``en_foo_cleanup()`` respectively. It
is then up to the developer to declare and define these functions in whichever
file is the best fit.

If the ``is_valid()``, ``clear_tracked_data()``, or
``get_compute_failure_info()`` callbacks are desired, then special arguments
can be passed to the ``ENGINE_NODE()`` declaration. These can be mixed and
matched as desired. Here are some examples of valid ``ENGINE_NODE()``
declarations. ::

    ENGINE_NODE(foo, CLEAR_TRACKED_DATA);
    ENGINE_NODE(foo, IS_VALID);
    ENGINE_NODE(foo, COMPUTE_FAIL_INFO);
    ENGINE_NODE(foo, IS_VALID, CLEAR_TRACKED_DATA);
    ENGINE_NODE(foo, CLEAR_TRACKED_DATA, IS_VALID);

If ``CLEAR_TRACKED_DATA`` is passed as an argument, then the
``clear_tracked_data()`` callback will be set to the function
``en_foo_clear_tracked_data()``. If ``IS_VALID`` is passed as an argument, then
the ``is_valid()`` callback will be set to the function ``en_foo_is_valid()``.
And finally, if ``COMPUTE_FAIL_INFO`` is passed as an argument, then the
``get_compute_failure_info()`` callback will be set to
``en_foo_get_compute_failure_info()``.

Database Engine Nodes
---------------------
In addition to standard ``ENGINE_NODE()`` declarations, there are special
declarations that can be used for engine nodes that represent data from Open
vSwitch database (OVSDB) tables. We will refer to these as "DB nodes" from here
on. The ``ENGINDE_NODE_NB()`` macro declares a DB node for a table in the
northbound database. The name of the resulting struct is prefixed with "nb"
similarly to how the ``ENGINE_NODE()`` macro prefixes the struct and engine
node callbacks with "en". So for example, ``ENGINE_NODE_NB(logical_switch)``
would create an engine node structure called ``struct engine_node
nb_logical_switch;``.  ``ENGINE_NODE_SB()`` does the same, except it makes a DB
node whose struct name is prefixed with "sb". The ``ENGINE_FUNC_NB()`` macro
defines the callbacks used by a northbound DB node and ``ENGINE_FUNC_SB()`` does
the same but for southbound db nodes.

Linking Engine Nodes
--------------------
Once an engine node has been declared, it then needs to be linked with the
other nodes in the incremental engine. The ``engine_node_add_input()`` function
is used for this purpose. The first argument of this function is the node which
needs an input added. The second argument of this function is the node which
will act as an input node. The final argument is an input handler function. We
will go into detail about input handler functions in a later section.

Let's take the following example: ::

    engine_add_input(en_foo, en_bar, foo_bar_handler);
    engine_add_input(en_foo, en_baz, NULL);
    engine_add_input(en_foo, en_wub, engine_noop_handler);

In this case, the "foo" engine node takes the "bar," "baz," and "wub" engine
nodes as input.

Engine Node States
------------------
Engine node states are important when determining how an engine node will
behave during any particular engine run.

When an engine run begins, all nodes in the engine are marked as ``EN_STALE``,
meaning the data in the node is invalid. As each engine node is visited, a new
state is determined for that node. The most common states that a node might
change to are:

* ``EN_UNCHANGED``: The engine node's data did not change as a result of this
  engine run.
* ``EN_UPDATED``: The engine node's data has changed as a result of this engine
  run.

Another state, ``EN_CANCELED``, exists as well, but it is a special state that
is only applicable to the engine node internals. Writers of engine nodes do not
need to concern themselves with this state.

When determining if an engine node needs to compute, the incremental engine
code examines the states of all input nodes to the engine node. If all input
nodes are ``EN_UNCHANGED``, then there is no need for the engine node to have
to do anything. If any of the input nodes are ``EN_UPDATED``, then the engine
node needs to compute its data based on the changes to the input node.

Writing Engine Node Callbacks
-----------------------------

``init()``
~~~~~~~~~~
``init()`` handlers have one job: allocate the engine node's data on the heap
and initialize whatever can be. Since the ``init()`` callback is called at
program startup, it does not have any input content to use for initialization.
Therefore, you cannot, for instance, attempt to initialize the node with all of
the data from a particular database table.

``cleanup()``
~~~~~~~~~~~~~
``cleanup()`` handlers are responsible for freeing all engine data. This
callback is called once at program shutdown. Like with ``init()`` it is called
outside the context of an engine run, so you cannot use any engine node inputs
to try to clean up the engine data.

One important note is that the ``cleanup()`` function should *not* free the
``node->data`` directly. This is done by the incremental engine, and doing so
in the ``cleanup()`` callback will result in a double free and crash of OVN.

``run()``
~~~~~~~~~
The ``run()`` callback has essentially two jobs:
 # Recompute all engine node data from scratch using data from input nodes.
 # Determine if the data in this node has changed.

For the first job, input node data can be retrieved using the
``engine_get_input_data()`` function. If the input node is a DB node, then the
database table can be retrieved using ``EN_OVSDB_GET(engine_get_input())``. It
is the responsibility of the ``run()`` handler to clear out any data that might
be present in the ``node->data`` from previous engine runs. It is common for
``run()`` callbacks to start by destroying their data, then reinitializing their
data, and then using the input node data to recompute the engine node data.

In the vast majority of cases, that second part results in ``EN_UPDATED`` being
returned as the node state. The big exception to this is DB nodes. DB nodes can
view the OVSDB IDL tracked database information and determine that the OVSDB
table has not had any changes to its records and return ``EN_UNCHANGED`` as a
result.

``is_valid()``
~~~~~~~~~~~~~~
The vast majority of engine nodes do not need to define this function. This is
mostly useful for engine nodes in ovn-controller, since their data may be
requested by the main ovn-controller code after an engine run has completed. In
this case, the engine node might be ``EN_STALE`` since the engine node never
ran. However, the data that is stored in that node could still be valid even
though the incremental engine did not run. In that case, defining an
``is_valid()`` callback to allow the data to be retrieved in this case is
useful.

Input Node Handlers
-------------------
Input node handlers are the foundation on which in-place incremental processing
of data can be performed. If we refer to previous code in this document, we did
the following: ::

    engine_add_input(en_foo, en_bar, foo_bar_handler);
    engine_add_input(en_foo, en_baz, NULL);
    engine_add_input(en_foo, en_wub, engine_noop_handler);

Back then, we glossed over the third parameter, but now we will talk in more
detail about it. The third parameter is an input handler function. The goal of
the input handler function is to take the data from the specified input node
and determine if the engine node's data can be handled in place incrementally.
An input handler can return one of three values:

* ``EN_HANDLED_UNCHANGED``: The data from the input node was able to be
  handled and did not result in a change in the engine node's data.
* ``EN_HANDLED_UPDATED``: The data from the input node was able to be handled
  and it resulted in a change to the engine node's data.
* ``EN_UNHANDLED``: A change in the input data could not be handled in-place,
  and so we need to fall back to the engine node's ``run()`` callback in order
  to recompute the engine node's data.

When are input handlers called? Because of the topological sort, the
``en_bar``, ``en_baz``, and ``en_wub`` engine nodes will be run before the
``en_foo`` node is run. This means that each of these input nodes will have a
state associated with them, most likely one of ``EN_UNCHANGED`` or
``EN_UPDATED``. Eventually, the incremental engine will reach the ``en_foo``
node for evaluation. At that point, the incremental engine will look at the
input nodes in the order that they were defined. In this case, the engine
first looks at ``en_bar``. If the ``en_bar`` engine node's state is
``EN_UPDATED``, then the incremental engine will call the ``foo_bar_handler()``
function in order for ``en_foo`` to update its data based on ``en_bar``'s
changes. If ``foo_bar_handler()`` returns anything other than ``EN_UNHANDLED``,
then the incremental engine will move to the next input node. However, if
``foo_bar_handler()`` returns ``EN_UNHANDLED``, then the incremental engine
will skip evaluating the other input nodes and immediately fall back to the
``run()`` callback of ``en_foo()``.

In the case that an input handler results in ``EN_UNHANDLED`` being returned,
the incremental engine will call into the input node's
``get_compute_failure_info()`` callback if it is defined. This gives the input
node the ability to print information about the input node's data. This can be
useful in debugging situations when trying to determine what data might be
responsible for causing an engine node to recompute.

Note that the ``en_baz`` input node to ``en_foo`` has a ``NULL`` input handler
function. This is an indication that ``en_foo`` can never incrementally handle
changes from the ``en_baz`` input node. If ``en_baz`` is ever in the
``EN_UPDATED`` state, then ``en_foo`` will fall back to its ``run()`` callback
to recompute its data. However, if ``en_baz`` remains ``EN_UNCHANGED``, then it
is possible for ``en_foo`` to still incrementally process changes from other
changed nodes.

Note also that the ``en_wub`` input node to ``en_foo`` has a special
``engine_noop_handler`` input handler. The ``engine_noop_handler`` is a
predefined function that always returns ``EN_UNCHANGED``. This is useful in the
case where an engine node needs the input node's data, but the input node's
data will never actually result in a change to the engine node's data.

Tracked Data
~~~~~~~~~~~~
In order to incrementally process data, most engine nodes will need to be able
to determine what data from an input node has changed since the previous engine
run. Input nodes can make this easier by indicating what of its data is new,
updated, or deleted. This way, the engine node can iterate through these
collections in the input handler and make a determination of how to handle each
of these new, updated, or deleted objects.

Unlike the core data of an incremental engine node, tracked data is only valid
during the current engine run. An object is only "new" for that particular
engine run. In the next run, the object will either be updated, deleted, or
unchanged. Similarly, deleted objects can only be kept around for the current
engine run. After that, they need to be cleaned up.

The incremental engine has a special callback to deal with the management of
tracked data called ``clear_tracked_data()``. Input nodes that provide tracked
data can define this callback in order to reset the state of tracked data, and
free any objects that no longer need to be tracked.

The ``clear_tracked_data()`` callback is called in three situations.
* The ``clear_tracked_data()`` function is called just before the ``cleanup()``
callback as a means of ensuring all data is freed before the program shuts
down.
* When an engine run begins, all nodes have their ``clear_tracked_data()``
callback called. This ensures that tracked data that was calculated during
the previous engine run is freed so that new tracked data can be calculated
during this engine run.
* When an input handler returns ``EN_UNHANDLED``, then the engine node's
``clear_tracked_data()`` is called before calling the ``run()`` callback.
This ensures that the engine node does not erroneously provide partial
tracked data to any other engine nodes that use it as an input node.

Guidelines
----------
The following are good practices to follow when developing incremental engine
code. These are not hard and fast rules, but they should be followed whenever
possible.

Data Ownwership And Const Input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Data that belongs to an engine node should only be modified or freed by the
engine node that owns the data. As such, it is a good idea to always try to
declare input node data as ``const``.

Avoid Side Effects
~~~~~~~~~~~~~~~~~~
Engine nodes should do their best only to update their own data. When engine
nodes also change global data, it is difficult to reason about how the engine
nodes fit together.

Isolate Input Handler Effects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Engine nodes can have multiple input nodes and as such can have multiple input
handlers. Engine nodes should strive to only update data affected by the
particular input node in its respective input handler.

Define a ``get_compute_failure_info()`` Handler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Do everyone a favor and increase the debuggability of the incremental engine by
definining this callback. It could save someone a ton of time at some point by
pinpointing exact reasons why engine nodes are having to recompute.

Keep Engine Nodes Small
~~~~~~~~~~~~~~~~~~~~~~~
It's much easier to have consistent incremental processing when engine nodes
are responsible for a small set of data. If an incremental engine has to handle
too much data, then it is more likely that changes in input nodes will cause
recomputes.

Provide Tracked Data
~~~~~~~~~~~~~~~~~~~~
When writing an engine node, always try to provide tracked data. Without
tracked data, engine nodes that use your node as input are unlikely to be able
to incrementally process changes from your engine node. When one node in the
chain has to recompute, it usually leads to many more nodes having to recompute
as a result.

Future Improvements
-------------------
The incremental engine is an evolving library, and as such, it can be improved
from its current state. Below are some ideas for improving the incremental
engine.

Formal Separation of Core and Tracked Data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Engine nodes currently store all of their data in a ``data`` pointer. This
includes both the core data of the node as well as its tracked data. Writers
of engine nodes need to examine input nodes in detail to try to determine what
part of the input node is core and what part is tracked. A future improvement
to the incremental engine would be to separate these two types of data into the
``data`` pointer and a ``tracked_data`` pointer. Then, engine nodes could
differentiate between the two easily through ``engine_get_input_data()`` and
``engine_get_input_tracked_data()`` calls.

Automatic clearing of core data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A common idiom in engine node ``run()`` callbacks is to free all data, then
reinitialize all data, then recompute all data. Those first two steps are so
common that they should probably be taken care of by the incremental engine
itself. This would simplify ``run()`` handlers to only focus on recomputation
of the data. The incremental engine provides a ``clear_tracked_data()``
callback, so it would not be that strange to provide a ``clear_data()``
callback as well.
