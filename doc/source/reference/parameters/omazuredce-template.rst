.. _param-omazuredce-template:
.. _omazuredce.parameter.input.template:

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
:Scope: input
:Type: word
:Default: input=RSYSLOG_FileFormat
:Required?: no
:Introduced: Not specified

Description
-----------
The selected template must render exactly one valid JSON object per message.
``omazuredce`` parses the rendered text and merges it into the batch payload.

Although the module currently defaults to ``RSYSLOG_FileFormat``, that default
does not produce a JSON object and is therefore not suitable for normal use.
Set ``template`` explicitly.

Input usage
-----------
.. _omazuredce.parameter.input.template-usage:

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
