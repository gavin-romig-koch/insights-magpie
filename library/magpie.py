#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: magpie
short_description: Gathers extended facts about remote hosts
options:
    None
description:
     - This module gathers extended facts for the Magpie system.
author:
    - "Gavin Romig-Koch"
'''

EXAMPLES = """
# Gather extended facts
# ansible all -m magpie

"""

def ansible_main():
    module = AnsibleModule(
        argument_spec = dict(
        ),
        supports_check_mode = True,
    )


    result = dict(ansible_facts=dict(gavin_facts=dict(first="gavin", last="romig-koch")))
    
    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.facts import *

if __name__ == '__main__':
    ansible_main()

