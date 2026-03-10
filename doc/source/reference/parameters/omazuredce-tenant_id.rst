.. _param-omazuredce-tenant_id:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.tenant_id:
=======
.. _omazuredce.parameter.input.tenant_id:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.tenant_id:
=======
.. _omazuredce.parameter.action.tenant_id:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce tenant_id parameter.
   :keywords: rsyslog, omazuredce, tenant_id, azure, entra

tenant_id
=========

.. index::
   single: omazuredce; tenant_id
   single: tenant_id

.. summary-start

Sets the Microsoft Entra tenant used when requesting OAuth access tokens.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: tenant_id
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
``tenant_id`` identifies the Microsoft Entra tenant that issues the token for
the configured application credentials.

<<<<<<< HEAD
<<<<<<< HEAD
Action usage
------------
.. _omazuredce.parameter.action.tenant_id-usage:
=======
Input usage
-----------
.. _omazuredce.parameter.input.tenant_id-usage:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
Input usage
-----------
.. _omazuredce.parameter.input.tenant_id-usage:
=======
Action usage
------------
.. _omazuredce.parameter.action.tenant_id-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   action(type="omazuredce" tenant_id="<tenant-id>" ...)

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
