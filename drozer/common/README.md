Mercury: the Heavy Metal that Poisoned the Droid
================================================

Mercury is a security assessment framework for the Android. It allows you to dynamically interact with the IPC endpoints exported by an application installed on a device.

Mercury is open source software, maintained by MWR InfoSecurity, and can be downloaded
from:

    mwr.to/mercury

Mercury provides similar functionality to a number of static analysis tools, such as aapt, but offers far more flexibility by allowing you to interact with these endpoints from the context of an unprivileged application running on the same device. The Android sandbox is designed to restrict the access of an unprivileged application to other applications, and the underlying device, without requesting appropriate permissions. You will be surprised how much access you actually have...


Installing
----------

See INSTALLING.


License
-------

Mercury is released under the MWR Code License v1. See LICENSE for full details.


This Repository
---------------

This repository contains Mercury components that are shared between the Agent and the Server/Console.

In particular:

* protobuf.proto
This file contains the Protocol Buffer description for the Mercury protocol. The file is parsed using the `protoc` command to generate the required libraries for each platform in use.
