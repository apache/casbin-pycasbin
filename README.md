PyCasbin
====

[![build](https://github.com/apache/casbin-pycasbin/actions/workflows/build.yml/badge.svg)](https://github.com/apache/casbin-pycasbin/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/apache/casbin-pycasbin/badge.svg)](https://coveralls.io/github/apache/casbin-pycasbin)
[![Version](https://img.shields.io/pypi/v/pycasbin.svg)](https://pypi.org/project/pycasbin/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/pycasbin.svg)](https://pypi.org/project/pycasbin/)
[![Pyversions](https://img.shields.io/pypi/pyversions/pycasbin.svg)](https://pypi.org/project/pycasbin/)
[![Download](https://static.pepy.tech/badge/pycasbin)](https://pypi.org/project/pycasbin/)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

**News**: 🔥 How to use it with `Django` ? Try [Django Authorization](https://github.com/officialpycasbin/django-authorization), an authorization library for `Django` framework.

**News**: Async is now supported by Pycasbin >= 1.23.0!

**News**: still worry about how to write the correct Casbin policy? ``Casbin online editor`` is coming to help! Try it at: http://casbin.org/editor/

Casbin is a powerful and efficient open-source access control library for Python projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

| [![golang](https://casbin.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/img/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin) |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| [Casbin](https://github.com/casbin/casbin)                                             | [jCasbin](https://github.com/casbin/jcasbin)                                        | [node-Casbin](https://github.com/casbin/node-casbin)                                        | [PHP-Casbin](https://github.com/php-casbin/php-casbin)                                   |
| production-ready                                                                       | production-ready                                                                    | production-ready                                                                            | production-ready                                                                         |

| [![python](https://casbin.org/img/langs/python.png)](https://github.com/apache/casbin-pycasbin) | [![dotnet](https://casbin.org/img/langs/dotnet.png)](https://github.com/casbin-net/Casbin.NET) | [![c++](https://casbin.org/img/langs/cpp.png)](https://github.com/casbin/casbin-cpp) | [![rust](https://casbin.org/img/langs/rust.png)](https://github.com/casbin/casbin-rs) |
|------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| [PyCasbin](https://github.com/apache/casbin-pycasbin)                                           | [Casbin.NET](https://github.com/casbin-net/Casbin.NET)                                         | [Casbin-CPP](https://github.com/casbin/casbin-cpp)                                   | [Casbin-RS](https://github.com/casbin/casbin-rs)                                      |
| production-ready                                                                         | production-ready                                                                               | beta-test                                                                            | production-ready                                                                      |

## Table of contents

- [Supported models](#supported-models)
- [How it works?](#how-it-works)
- [Features](#features)
- [Installation](#installation)
- [Documentation](#documentation)
- [Online editor](#online-editor)
- [Tutorials](#tutorials)
- [Get started](#get-started)
- [Policy management](#policy-management)
- [Policy persistence](#policy-persistence)
- [Role manager](#role-manager)
- [Async Enforcer](#async-enforcer)
- [Benchmarks](#benchmarks)
- [Logging](#logging)
- [Examples](#examples)
- [Middlewares](#middlewares)
- [Our adopters](#our-adopters)

## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
3. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like ``write-article``, ``read-log``. It doesn't control the access to a specific article or log.
4. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
5. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
6. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
7. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like ``resource.Owner`` can be used to get the attribute for a resource.
8. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like ``/res/*``, ``/res/:id`` and HTTP methods like ``GET``, ``POST``, ``PUT``, ``DELETE``.
9. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
10. **Priority**: the policy rules can be prioritized like firewall rules.

## How it works?

In Casbin, an access control model is abstracted into a CONF file based on the **PERM metamodel (Policy, Effect, Request, Matchers)**. So switching or upgrading the authorization mechanism for a project is just as simple as modifying a configuration. You can customize your own access control model by combining the available models. For example, you can get RBAC roles and ABAC attributes together inside one model and share one set of policy rules.

The most basic and simplest model in Casbin is ACL. ACL's model CONF is:

```ini
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act

```

An example policy for ACL model is like:

```
p, alice, data1, read
p, bob, data2, write
```

It means:

- alice can read data1
- bob can write data2

We also support multi-line mode by appending '\\'  in the end:  

```ini
# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj \ 
  && r.act == p.act
```

Further more, if you are using ABAC,  you can try operator `in` like following in Casbin **golang** edition (jCasbin and Node-Casbin are not supported yet):

```ini
# Matchers
[matchers]
m = r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3')
```

But you **SHOULD** make sure that the length of the array is **MORE** than **1**, otherwise there will cause it to panic.

For more operators, you may take a look at [govaluate](https://github.com/Knetic/govaluate)

## Features

What Casbin does:

1. enforce the policy in the classic ``{subject, object, action}`` form or a customized form as you defined, both allow and deny authorizations are supported.
2. handle the storage of the access control model and its policy.
3. manage the role-user mappings and role-role mappings (aka role hierarchy in RBAC).
4. support built-in superuser like ``root`` or ``administrator``. A superuser can do anything without explict permissions.
5. multiple built-in operators to support the rule matching. For example, ``keyMatch`` can map a resource key ``/foo/bar`` to the pattern ``/foo*``.

What Casbin does NOT do:

1. authentication (aka verify ``username`` and ``password`` when a user logs in)
2. manage the list of users or roles. I believe it's more convenient for the project itself to manage these entities. Users usually have their passwords, and Casbin is not designed as a password container. However, Casbin stores the user-role mapping for the RBAC scenario. 

## Installation

```
pip install pycasbin
```

## Documentation

https://casbin.org/docs/overview

## Online editor

You can also use the online editor (http://casbin.org/editor/) to write your Casbin model and policy in your web browser. It provides functionality such as ``syntax highlighting`` and ``code completion``, just like an IDE for a programming language.

## Tutorials

https://casbin.org/docs/tutorials

## Get started

1. New a Casbin enforcer with a model file and a policy file:

```python
import casbin
e = casbin.Enforcer("path/to/model.conf", "path/to/policy.csv")
```

Note: you can also initialize an enforcer with policy in DB instead of file, see [Policy persistence](#policy-persistence) section for details.

2. Add an enforcement hook into your code right before the access happens:

```python
sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass
```

3. Besides the static policy file, Casbin also provides API for permission management at run-time. For example, You can get all the roles assigned to a user as below:

```python
roles = e.get_roles_for_user("alice")
```

See [Policy management APIs](#policy-management) for more usage.

4. Please refer to the ``tests`` files for more usage.

## Policy management

Casbin provides two sets of APIs to manage permissions:

- [Management API](https://github.com/casbin/casbin/blob/master/management_api.go): the primitive API that provides full support for Casbin policy management. See [here](https://github.com/casbin/casbin/blob/master/management_api_test.go) for examples.
- [RBAC API](https://github.com/casbin/casbin/blob/master/rbac_api.go): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code. See [here](https://github.com/casbin/casbin/blob/master/rbac_api_test.go) for examples.

We also provide a web-based UI for model management and policy management:

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy persistence

https://casbin.org/docs/adapters

## Role manager

https://casbin.org/docs/role-managers

## Async Enforcer

If your code use `async` / `await` and is heavily dependent on I/O operations, you can adopt Async Enforcer!

1. Create an async engine and new a Casbin AsyncEnforcer with a model file and an async Pycasbin adapter (AsyncAdapter subclass):

```python
import asyncio
import os

import casbin
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from casbin_async_sqlalchemy_adapter import Adapter, CasbinRule


async def get_enforcer():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    adapter = Adapter(engine)
    await adapter.create_table()

    async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as s:
        s.add(CasbinRule(ptype="p", v0="alice", v1="data1", v2="read"))
        s.add(CasbinRule(ptype="p", v0="bob", v1="data2", v2="write"))
        s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read"))
        s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write"))
        s.add(CasbinRule(ptype="g", v0="alice", v1="data2_admin"))
        await s.commit()

    e = casbin.AsyncEnforcer("path/to/model.conf", adapter)
    await e.load_policy()
    return e
```

Note: you can see all supported adapters in [Adapters | Casbin](https://casbin.org/docs/adapters).

Built-in async adapters are available in `casbin.persist.adapters.asyncio`.

2. Add an enforcement hook into your code right before the access happens:

```python
async def main():
    e = await get_enforcer()
    if e.enforce("alice", "data1", "read"):
        print("alice can read data1")
    else:
        print("alice can not read data1")
```

3. Run the code:

```python
asyncio.run(main())
```

4. Please refer to the ``tests`` files for more usage.

## Benchmarks

https://casbin.org/docs/benchmark

## Logging

pycasbin leverages the default Python logging mechanism. The pycasbin package makes a call to `logging.getLogger()` to set the logger. No special logging configuration is needed other than initializing the logger in the parent application. If no logging is initialized within the parent application, you will not see any log messages from pycasbin. At the same time, When you enable log in pycasbin, you can specify the logging configuration through the parameter `logging_config`. If no configuration is specified, it will use the [default log configuration](https://github.com/apache/casbin-pycasbin/blob/c33cabfa0ac65cd09cf812a65e71794d64cb5132/casbin/util/log.py#L6C1-L6C1). For other pycasbin extensions, you can refer to the [Django logging docs](https://docs.djangoproject.com/en/4.2/topics/logging/) if you are a Django user. For other Python users, you should refer to the [Python logging docs](https://docs.python.org/3/library/logging.config.html) to configure the logger.

## Examples

| Model                     | Model file                                                                                                                       | Policy file                                                                                                                      |
|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| ACL                       | [basic_model.conf](https://github.com/casbin/casbin/blob/master/examples/basic_model.conf)                                       | [basic_policy.csv](https://github.com/casbin/casbin/blob/master/examples/basic_policy.csv)                                       |
| ACL with superuser        | [basic_model_with_root.conf](https://github.com/casbin/casbin/blob/master/examples/basic_with_root_model.conf)                   | [basic_policy.csv](https://github.com/casbin/casbin/blob/master/examples/basic_policy.csv)                                       |
| ACL without users         | [basic_model_without_users.conf](https://github.com/casbin/casbin/blob/master/examples/basic_without_users_model.conf)           | [basic_policy_without_users.csv](https://github.com/casbin/casbin/blob/master/examples/basic_without_users_policy.csv)           |
| ACL without resources     | [basic_model_without_resources.conf](https://github.com/casbin/casbin/blob/master/examples/basic_without_resources_model.conf)   | [basic_policy_without_resources.csv](https://github.com/casbin/casbin/blob/master/examples/basic_without_resources_policy.csv)   |
| RBAC                      | [rbac_model.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_model.conf)                                         | [rbac_policy.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_policy.csv)                                         |
| RBAC with resource roles  | [rbac_model_with_resource_roles.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_with_resource_roles_model.conf) | [rbac_policy_with_resource_roles.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_with_resource_roles_policy.csv) |
| RBAC with domains/tenants | [rbac_model_with_domains.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_with_domains_model.conf)               | [rbac_policy_with_domains.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_with_domains_policy.csv)               |
| ABAC                      | [abac_model.conf](https://github.com/casbin/casbin/blob/master/examples/abac_model.conf)                                         | N/A                                                                                                                              |
| RESTful                   | [keymatch_model.conf](https://github.com/casbin/casbin/blob/master/examples/keymatch_model.conf)                                 | [keymatch_policy.csv](https://github.com/casbin/casbin/blob/master/examples/keymatch_policy.csv)                                 |
| Deny-override             | [rbac_model_with_deny.conf](https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_model.conf)                     | [rbac_policy_with_deny.csv](https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_policy.csv)                     |
| Priority                  | [priority_model.conf](https://github.com/casbin/casbin/blob/master/examples/priority_model.conf)                                 | [priority_policy.csv](https://github.com/casbin/casbin/blob/master/examples/priority_policy.csv)                                 |

## Middlewares

Authz middlewares for web frameworks: https://casbin.org/docs/middlewares

## Our adopters

https://casbin.org/docs/adopters

## Contributors

This project exists thanks to all the people who contribute. 
<a href="https://github.com/apache/casbin-pycasbin/graphs/contributors"><img src="https://opencollective.com/pycasbin/contributors.svg?width=890&button=false" /></a>

## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=apache/casbin-pycasbin&type=Date)](https://star-history.dera.page/#apache/casbin-pycasbin&Date)

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.

- https://github.com/apache/casbin-pycasbin/issues
- https://discord.gg/S5UjpzGZjN
