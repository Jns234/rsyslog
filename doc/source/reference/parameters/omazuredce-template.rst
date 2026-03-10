.. _param-omazuredce-template:
<<<<<<< HEAD
<<<<<<< HEAD
.. _omazuredce.parameter.action.template:
=======
.. _omazuredce.parameter.input.template:
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
.. _omazuredce.parameter.input.template:
=======
.. _omazuredce.parameter.action.template:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. meta::
   :description: Reference for the omazuredce template parameter.
   :keywords: rsyslog, omazuredce, template, azure

template
========

.. index::
   single: omazuredce; template
   single: template

.. summary-start

Selects the rsyslog template used to render each message before it is added to
the Azure ingestion batch.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omazuredce`.

:Name: template
<<<<<<< HEAD
<<<<<<< HEAD
:Scope: action
:Type: word
:Default: action=StdJSONFmt
=======
:Scope: input
:Type: word
:Default: input=RSYSLOG_FileFormat
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
:Scope: input
:Type: word
:Default: input=RSYSLOG_FileFormat
=======
:Scope: action
:Type: word
:Default: action=StdJSONFmt
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)
:Required?: no
:Introduced: Not specified

Description
-----------
The selected template must render exactly one valid JSON object per message.
``omazuredce`` parses the rendered text and merges it into the batch payload.
<<<<<<< HEAD
<<<<<<< HEAD
If this parameter is omitted, the module uses the built-in ``StdJSONFmt``
template, which already renders one JSON object per message.

Action usage
------------
.. _omazuredce.parameter.action.template-usage:
=======
=======
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

Although the module currently defaults to ``RSYSLOG_FileFormat``, that default
does not produce a JSON object and is therefore not suitable for normal use.
Set ``template`` explicitly.

Input usage
-----------
.. _omazuredce.parameter.input.template-usage:
<<<<<<< HEAD
>>>>>>> d611f7117 (Add azure Monitor API ingestion module)
=======
=======
If this parameter is omitted, the module uses the built-in ``StdJSONFmt``
template, which already renders one JSON object per message.

Action usage
------------
.. _omazuredce.parameter.action.template-usage:
>>>>>>> 5508f1427 (Add azure Monitor API ingestion module)
>>>>>>> d938bc052 (Add azure Monitor API ingestion module)

.. code-block:: rsyslog

   template(name="tplAzureDce" type="list" option.jsonf="on") {
      property(outname="TimeGenerated" name="timereported" dateFormat="rfc3339" format="jsonf")
      property(outname="Host" name="hostname" format="jsonf")
      property(outname="Message" name="msg" format="jsonf")
   }

   action(type="omazuredce" template="tplAzureDce" ...)

See also
--------
See also :doc:`../../configuration/modules/omazuredce`.
