.. _param-omazuredce-dce_url:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.dce_url:
=======
.. _omazuredce.parameter.input.dce_url:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.dce_url:
=======
.. _omazuredce.parameter.action.dce_url:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce dce_url parameter.
   :keywords: rsyslog, omazuredce, dce_url, azure, logs ingestion

dce_url
=======

.. index::
   single: omazuredce; dce_url
   single: dce_url

.. summary-start

Defines the Azure Data Collection Endpoint base URL used for batch submission.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: dce_url
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
``dce_url`` is the base HTTPS endpoint for the Azure Logs Ingestion API. The
module appends the DCR and stream path segments to this URL when constructing
requests.

Both forms with and without a trailing slash are accepted.

<<<<<<< HEAD
<<<<<<< HEAD
Action usage
------------
.. _omazuredce.parameter.action.dce_url-usage:
=======
Input usage
-----------
.. _omazuredce.parameter.input.dce_url-usage:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Input usage
-----------
.. _omazuredce.parameter.input.dce_url-usage:
=======
Action usage
------------
.. _omazuredce.parameter.action.dce_url-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   action(
      type="omazuredce"
      dce_url="https://<dce-name>.<region>.ingest.monitor.azure.com"
      ...
   )

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
