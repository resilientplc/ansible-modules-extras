#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to manage mssql databases
# (c) 2016, Resilient PLC
# Outline and parts are reused from Vedit Firat Arig <firatarig@gmail.com>'s mssql_db
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: mssql_user
short_description: Manage users in MSSQL databases
description:
   - Manage users in MSSQL databases
version_added: "2.3"
options:
  db:
    description:
      - name of the database to work with users in
    required: true
    default: null
    aliases: [ name ]
  login_user:
    description:
      - The username used to authenticate with
    required: false
    default: null
  login_password:
    description:
      - The password used to authenticate with
    required: false
    default: null
  login_host:
    description:
      - Host running the database
    required: True
  login_port:
    description:
      - Port of the MSSQL server.
    required: false
    default: 1433
  user_login:
    description:
      - Name of the user to add or remove
    required: true
  state:
    description:
      - Whether the user should exist in the database
    required: false
    default: present
    choices: [ "present", "absent"]

notes:
   - Requires the pymssql Python package on the remote host. For Ubuntu, this
     is as easy as pip install pymssql (See M(pip).)
requirements:
   - python >= 2.7
   - pymssql
author: J Peck
'''

EXAMPLES = '''
# Create a new user 'bob' with role db_owner in database with name 'jackdata'
- mssql_user: db=jackdata user_login=bob user_role=db_owner state=present
'''

RETURN  = '''
#
'''

try:
    import pymssql
except ImportError:
    mssql_found = False
else:
    mssql_found = True


def user_add(cursor, name, db):
    cursor.execute("USE [%s]" % db)
    cursor.execute("CREATE USER [%s] FOR LOGIN [%s]" % (name, name))


def user_remove(cursor, name, db):
    cursor.execute("USE [%s]" % db)
    cursor.execute("DROP USER [%s]" % name)


def add_user_to_role(cursor, name, role, db):
    cursor.execute("USE [%s]" % db)
    cursor.execute("ALTER ROLE [%s] ADD MEMBER [%s]" % (role, name))


def add_login_to_user(cursor, name, db):
    cursor.execute("USE [%s]" % db)
    cursor.execute("ALTER USER [%s] WITH LOGIN=[%s]" % (name, name))


def user_exists(cursor, name, db):
    cursor.execute("SELECT * FROM [%s].sys.database_principals "
                   "WHERE name = '%s' "
                   "AND (type='S' or type = 'U')" % (db, name))
    return bool(cursor.rowcount)


def user_exists_with_role(cursor, name, role, db):
    cursor.execute("SELECT roles.name role_name, users.name user_name "
                   "FROM   [%s].sys.database_principals roles, "
                   "       [%s].sys.database_principals users, "
                   "       [%s].sys.database_role_members members "
                   "WHERE  members.member_principal_id = users.principal_id "
                   "AND    members.role_principal_id = roles.principal_id "
                   "AND    users.name = '%s' "
                   "AND    roles.name = '%s' "
                   "AND    roles.type = 'R' "
                   "AND    (users.type='S' or users.type = 'U')" % (db, db, db, name, role))
    return bool(cursor.rowcount)


def user_exists_with_login(cursor, name, db):
    cursor.execute("SELECT dp.type_desc, dp.SID, dp.name AS user_name "
                   "FROM [%s].sys.database_principals AS dp "
                   "        JOIN sys.server_principals AS sp "
                   "ON dp.SID = sp.SID "
                   "WHERE authentication_type_desc = 'INSTANCE' "
                   "AND   dp.name = '%s'" % (db, name))
    return bool(cursor.rowcount)


def execute_if_not_check_mode(function, check_mode):
    if not check_mode:
        function()


def user_main(cursor, name, role, db, state, check_mode):
    changed = False

    if state == "present":
        if not user_exists(cursor, name, db):
            execute_if_not_check_mode(lambda: user_add(cursor, name, db), check_mode)
            changed = True

        if role and not user_exists_with_role(cursor, name, role, db):
            execute_if_not_check_mode(lambda: add_user_to_role(cursor, name, role, db), check_mode)
            changed = True

        if not user_exists_with_login(cursor, name, db):
            execute_if_not_check_mode(lambda: add_login_to_user(cursor, name, db), check_mode)
            changed = True
    else:
        if user_exists(cursor, name, db):
            execute_if_not_check_mode(lambda: user_remove(cursor, name, db), check_mode)
            changed = True

    return changed


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True, aliases=['db']),
            login_user=dict(default=''),
            login_password=dict(default=''),
            login_host=dict(required=True),
            login_port=dict(default='1433'),
            user_login=dict(required=True),
            user_role=dict(default=None),
            state=dict(
                default='present', choices=['present', 'absent'])
        ),
        supports_check_mode=True
    )

    if not mssql_found:
        module.fail_json(msg="pymssql python module is required")

    db = module.params['name']
    state = module.params['state']

    name = module.params['user_login']
    role = module.params['user_role']

    conn, cursor = MsSqlConnectionFactory.create_connection(module)

    changed = user_main(cursor, name, role, db, state, module.check_mode)

    module.exit_json(changed=changed, db=db)


class MsSqlConnectionFactory:

    @staticmethod
    def create_connection(module):
        if not mssql_found:
            module.fail_json(msg="pymssql python module is required")
        login_user = module.params['login_user']
        login_password = module.params['login_password']
        login_host = module.params['login_host']
        login_port = module.params['login_port']
        login_querystring = login_host
        if login_port != "1433":
            login_querystring = "%s:%s" % (login_host, login_port)
        if login_user != "" and login_password == "":
            module.fail_json(msg="when supplying login_user arguments login_password must be provided")
        try:
            conn = pymssql.connect(user=login_user, password=login_password, host=login_querystring, database='master')
            cursor = conn.cursor()
        except Exception as e:
            if "Unknown database" in str(e):
                errno, errstr = e.args
                module.fail_json(msg="ERROR: %s %s" % (errno, errstr))
            else:
                module.fail_json(
                    msg="unable to connect, check login_user and login_password are correct, or alternatively check your @sysconfdir@/freetds.conf / ${HOME}/.freetds.conf")
        conn.autocommit(True)
        return conn, cursor


# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
