.. _param-omazuredce-table_name:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.table_name:
=======
.. _omazuredce.parameter.input.table_name:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.table_name:
=======
.. _omazuredce.parameter.action.table_name:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce table_name parameter.
   :keywords: rsyslog, omazuredce, table_name, azure, stream

table_name
==========

.. index::
   single: omazuredce; table_name
   single: table_name

.. summary-start

Sets the stream or table name appended to the Azure ingestion request path.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: table_name
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
:Type: string
:Default: none
:Required?: yes
:Introduced: Not specified

Description
-----------
``table_name`` is appended below ``/streams/`` in the final request URL. The
configured value must match a stream accepted by the target Data Collection
Rule.

<<<<<<< HEAD
<<<<<<< HEAD
Action usage
------------
.. _omazuredce.parameter.action.table_name-usage:
=======
Input usage
-----------
.. _omazuredce.parameter.input.table_name-usage:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Input usage
-----------
.. _omazuredce.parameter.input.table_name-usage:
=======
Action usage
------------
.. _omazuredce.parameter.action.table_name-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   action(type="omazuredce" table_name="Custom-MyTable_CL" ...)

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
