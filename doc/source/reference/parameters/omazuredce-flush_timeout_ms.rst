.. _param-omazuredce-flush_timeout_ms:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.flush_timeout_ms:
=======
.. _omazuredce.parameter.input.flush_timeout_ms:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.flush_timeout_ms:
=======
.. _omazuredce.parameter.action.flush_timeout_ms:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce flush_timeout_ms parameter.
   :keywords: rsyslog, omazuredce, flush_timeout_ms, azure, batching

flush_timeout_ms
================

.. index::
   single: omazuredce; flush_timeout_ms
   single: flush_timeout_ms

.. summary-start

Controls how long a partially filled batch may stay idle before it is flushed.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: flush_timeout_ms
<<<<<<< HEAD
<<<<<<< HEAD
:Scope: action
=======
:Scope: input
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
:Scope: input
=======
:Scope: action
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)
:Type: non-negative integer
:Default: 1000
:Required?: no
:Introduced: Not specified

Description
-----------
When ``flush_timeout_ms`` is greater than ``0``, a worker thread checks for
idle batches and flushes them after the configured number of milliseconds.

When it is set to ``0``, the timer-based flush is disabled and batches are sent
only when they fill up or when the current action queue transaction ends.

<<<<<<< HEAD
<<<<<<< HEAD
Action usage
------------
.. _omazuredce.parameter.action.flush_timeout_ms-usage:
=======
Input usage
-----------
.. _omazuredce.parameter.input.flush_timeout_ms-usage:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Input usage
-----------
.. _omazuredce.parameter.input.flush_timeout_ms-usage:
=======
Action usage
------------
.. _omazuredce.parameter.action.flush_timeout_ms-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   action(type="omazuredce" flush_timeout_ms="2000" ...)

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
