.. _param-omazuredce-client_secret:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.client_secret:
=======
.. _omazuredce.parameter.input.client_secret:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.client_secret:
=======
.. _omazuredce.parameter.action.client_secret:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce client_secret parameter.
   :keywords: rsyslog, omazuredce, client_secret, azure, entra

client_secret
=============

.. index::
   single: omazuredce; client_secret
   single: client_secret

.. summary-start

Supplies the client secret paired with ``client_id`` for OAuth token requests.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: client_secret
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
``client_secret`` provides the shared secret used by Microsoft Entra client
credentials authentication. Treat this value as sensitive and avoid storing
real production secrets in example configurations or version control.

<<<<<<< HEAD
<<<<<<< HEAD
Action usage
------------
.. _omazuredce.parameter.action.client_secret-usage:
=======
Input usage
-----------
.. _omazuredce.parameter.input.client_secret-usage:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Input usage
-----------
.. _omazuredce.parameter.input.client_secret-usage:
=======
Action usage
------------
.. _omazuredce.parameter.action.client_secret-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   action(type="omazuredce" client_secret="<client-secret>" ...)

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
