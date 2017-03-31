insights-magpie
===============

What if we could use Ansible modules to do data collection for Insights?

Requirements
------------

The controller machine must have tar installed.


Role Variables
--------------

The magpie action plugin needs BASICAUTH (username/password) for the Red Hat Portal (Red Hat Insights
uses the same credentials as Red Hat Portal). These must be defined for the magpie action plugin
to work.

redhat_portal_username 
redhat_portal_password

Once the magpie action plugin runs it will define the fact:

insights_upload_results


Dependencies
------------

None yet.

Example Playbook
----------------

    - hosts: servers
      roles:
         - { role: gavin-romig-koch.insights-magpie }

License
-------

BSD

Author Information
------------------

Gavin Romig-Koch, based largely on insights-client by 
