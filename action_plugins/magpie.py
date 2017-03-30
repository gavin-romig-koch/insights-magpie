# (c) 2015, Ansible Inc,
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.action import ActionBase
   
class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):

        self._supports_check_mode = True
        self._supports_async      = False

        result = super(ActionModule, self).run(tmp, task_vars)

        if result.get('skipped', False):
            return result

        result.update(self._execute_module(module_name="magpie", module_args=self._task.args, task_vars=task_vars))

        result['ansible_facts']['gavin_action_facts'] = dict(theman=dict(first='galen',last='koch'))
        return result

