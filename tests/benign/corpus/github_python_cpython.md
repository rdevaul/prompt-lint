This is Python version 3.15.0 alpha 6
=====================================

.. image:: https://github.com/python/cpython/actions/workflows/build.yml/badge.svg?branch=main&event=push
   :alt: CPython build status on GitHub Actions
   :target: https://github.com/python/cpython/actions

.. image:: https://dev.azure.com/python/cpython/_apis/build/status/Azure%20Pipelines%20CI?branchName=main
   :alt: CPython build status on Azure DevOps
   :target: https://dev.azure.com/python/cpython/_build/latest?definitionId=4&branchName=main

.. image:: https://img.shields.io/badge/discourse-join_chat-brightgreen.svg
   :alt: Python Discourse chat
   :target: https://discuss.python.org/


Copyright © 2001 Python Software Foundation.  All rights reserved.

See the end of this file for further copyright and license information.

.. contents::

General Information
-------------------

- Website: https://www.python.org
- Source code: https://github.com/python/cpython
- Issue tracker: https://github.com/python/cpython/issues
- Documentation: https://docs.python.org
- Developer's Guide: https://devguide.python.org/

Contributing to CPython
-----------------------

For more complete instructions on contributing to CPython development,
see the `Developer Guide`_.

.. _Developer Guide: https://devguide.python.org/

Using Python
------------

Installable Python kits, and information about using Python, are available at
`python.org`_.

.. _python.org: https://www.python.org/

Build Instructions
------------------

On Unix, Linux, BSD, macOS, and Cygwin::

    ./configure
    make
    make test
    sudo make install

This will install Python as ``python3``.

You can pass many options to the configure script; run ``./configure --help``
to find out more.  On macOS case-insensitive file systems and on Cygwin,
the executable is called ``python.exe``; elsewhere it's just ``python``.

Building a complete Python installation requires the use of various
additional third-party libraries, depending on your build platform and
configure options.  Not all standard library modules are buildable or
usable on all platforms.  Refer to the
`Install dependencies <https://devguide.python.org/getting-started/setup-building.html#build-dependencies>`_
section of the `Developer Guide`_ for current detailed information on
dependencies for various Linux distributions and macOS.

On macOS, there are additional configure and build options related
to macOS framework and universal builds.  Refer to `Mac/README.rst
<https://github.com/python/cpython/blob/main/Mac/README.rst>`_.

On Windows, see `PCbuild/readme.txt
<https://github.com/python/cpython/blob/main/PCbuild/readme.txt>`_.

To build Windows installer, see `Tools/msi/README.txt
<https://github.com/python/cpython/blob/main/Tools/msi/README.txt>`_.

If you wish, you can create a subdirectory and invoke configure from there.
For example::

    mkdir debug
    cd debug
    ../configure --with-pydebug
    make
    make test

(This will fail if you *als