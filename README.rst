minion-zap-plugin
=================

This is a plugin for Minion that executes the OWASP Zed Attack Proxy (ZAP) 
penetration testing tool. This tool is designed to find vulnerabilities in web
applications. 

Interested in learning more about ZAP? See `zaproxy <https://github.com/zaproxy/zaproxy>`_.

Requirements
------------

Minion is well-supported on most Linux distro (Ubuntu, Fedora, etc).

* Python 2.7
* virtualenv
* ZAP weekly build (07-22 or above)
* ZAP python client 0.6

We recommend the weekly build from 07-22 and python client to be 0.6. You can find
other weekly releases by visiting zaproxy on Google code, but this README will 
assume you use the weekly built on 07-22.

ZAP installation
----------------

First, you must have ZAP setup on your system. Assume you are under ``/home/username``, you can
get the latest weekly or stable release of ZAP from http://sourceforge.net/projects/zaproxy/files/.

Download and extract the compressed file. For the purpose of this documentation, we will rename
the extracted folder to the name "zap", so that it resides at ``/home/username/zap".

The plugin looks for ZAP's ``zap.sh`` script either on the system ``PATH`` or in a directory specified
in either ``~/.minion/zap-plugin.json`` or ``/etc/minion/zap-plugin.json``. It is generally easier
to use the configuration file than to change the system `PATH` so that is what we recommend.

The ``zap-plugin.json`` config file should look as follows:

.. code:: json

    {
        "zap-path": "/home/username/zap/"
    }

You can put the ZAP directory anywhere, as long as the user executing the plugins has the
right permissions to read and execute the ``zap.sh`` script.


Plugin installation
-------------------

Assume you have minion installed, you can clone this plugin and do ``python setup.py``::

    $ git clone https://github.com/mozilla/minion-zap-plugin
    $ cd minion-zap-plugin
    $ python setup.py install

If you are developing minion and zap, you should run ``python setup.py develop`` using an
appropriate python environment (using a virtualenv or the global python interpreter).

Finally, you **must** restart minion-backend and all backend queue workers. Now go to your
minion administration interface on the browser, go to plugins, you should see zap plugin
installed.


Options
-------

ZAP is usually used as a proxy tool doing automated testing driven by browser testing plugin
such as selenium, and therefore some features are less appropriate for headless mode. Minion
runs zap as headless, and therefore we can only expose a subset of ZAP's power. Here is a complete
JSON configuration document you can put as a Minion zap plan:

.. code:: python

    [
        {
            "configuration": {
                "auth": {
                    "type": "basic/session",
                    "username": "username",
                    "password": "password",
                    "realm": "Restricted Area",
                    "hostname": "example.org",
                    "port": "https",
                    "sessions": [
                        {
                            "token": "token_name1",
                            "value": "wp_342423423"
                        },
                        {
                            "token": "token_name2",
                            "value": "wp_111111"
                        }
                    ]
                },
                "excludes": {
                    "spider": [
                        "http://localhost:1234/path1",
                        "http://localhost:1234/path2"
                    ],
                    "scanner": [
                        "http://localhost:1234/path1",
                        "http://localhost:1234/path2"
                    ]
                },
                "policies": {
                    "40012": "0"
                },
                "scan": true
            },
            "description": "Run the ZAP Spider and Scanner",
            "plugin_name": "minion.plugins.zap.ZAPPlugin"
        }
    ]


authentication
~~~~~~~~~~~~~~

This plugin can test websites that can be authenticated via basic auth or session/cookie auth.
You either specify ``basic`` or ``session`` as the type of the authentication method.

+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|   key    |                                                                                                         meaning                                                                                                          |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sessions | A list of session token name and value pair: ``{"token": "", "value": ""}``                                                                                                                                              |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| username | The username to authenticate (basic auth only)                                                                                                                                                                           |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| password | The password to authenticate (basic auth only)                                                                                                                                                                           |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| realm    | A string specifying the semantic of the protected area (basic auth only, optional)                                                                                                                                       |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| hostname | The hostname of the authentication to get through (basic auth only, optional)                                                                                                                                            |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| port     | The port of the authentication to get through (basic auth only, optional). By default minion will try to figure out the port using standard scheme-port matching. If you use non-standard port you need to specify this. |
+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

exclusions
----------

You can exclude certain URL from ZAP's scanner or spider. This is done by specify a list of url to 
the corresponding feature in the ``excludes`` attribute.

+---------+--------------------------------------------------------------------------------+
|   key   |                                    meaning                                     |
+---------+--------------------------------------------------------------------------------+
| spider  | A list of url to exclude from the spider: ["http://localhost:1234/path1", ...] |
| scanner | A list of url to exclude from the scanner.                                     |
+---------+--------------------------------------------------------------------------------+

Due to `bug #749 <http://code.google.com/p/zaproxy/issues/detail?id=749&start=200>`_ you might
need to exclude the same set of urls to achieve the same spider, scanner exclusion effect.

scan
----

By default, we will execute active scanning. You can turn this behavior off by specifying
``scan: false`` in the JSON attack plan.

policies
--------

ZAP allows you to turn on or off some scan policies. This is useful to speed up a scan
if you are only interested in a particular subset of issues. 

You specify ``policies`` and the value is a list of ``["policy_id": "0/1"]``, where
``0`` is off and ``1`` is on. The policy id is hard code in ZAP and we have extracted
this list in ``minion-zap-plugin/minion/plugins/reference.py``. See 
`reference.py <https://github.com/mozilla/minion-zap-plugin/blob/master/minion/plugins/reference.py>`_.

In the example JSON above, ``40012`` corresponds to "Cross site scripting (Reflected)".


