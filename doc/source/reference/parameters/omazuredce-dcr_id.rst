.. _param-omazuredce-dcr_id:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.dcr_id:
=======
.. _omazuredce.parameter.input.dcr_id:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.dcr_id:
=======
.. _omazuredce.parameter.action.dcr_id:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce dcr_id parameter.
   :keywords: rsyslog, omazuredce, dcr_id, azure, logs ingestion

dcr_id
======

.. index::
   single: omazuredce; dcr_id
   single: dcr_id

.. summary-start

<<<<<<< HEAD
<<<<<<< HEAD
Specifies the Azure Data Collection Rule immutable ID used in the ingestion URL.
=======
Specifies the Azure Data Collection Rule identifier used in the ingestion URL.
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Specifies the Azure Data Collection Rule identifier used in the ingestion URL.
=======
Specifies the Azure Data Collection Rule immutable ID used in the ingestion URL.
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: dcr_id
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
``dcr_id`` identifies the Data Collection Rule that receives the uploaded log
records. The value is inserted into the request path under
``dataCollectionRules/<dcr_id>``.

<<<<<<< HEAD
<<<<<<< HEAD
Action usage
------------
.. _omazuredce.parameter.action.dcr_id-usage:
=======
Input usage
-----------
.. _omazuredce.parameter.input.dcr_id-usage:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Input usage
-----------
.. _omazuredce.parameter.input.dcr_id-usage:
=======
Action usage
------------
.. _omazuredce.parameter.action.dcr_id-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   action(type="omazuredce" dcr_id="<dcr-id>" ...)

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
