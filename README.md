insights-magpie
===============

What if we could use Ansible modules to collect data for Red Hat Insights?

Requirements
------------

The controller machine must have 'tar' installed.


Role Variables
--------------

The magpie action plugin needs BASICAUTH (username/password) for the Red Hat Portal (Red Hat Insights
uses the same credentials as Red Hat Portal). These must be defined for the magpie action plugin
to work.

* redhat_portal_username 
* redhat_portal_password

Once the magpie action plugin runs it will define the fact:

* insights_upload_results


Example Playbook
----------------

  In magpie_example.yml:
  
    ```yaml
    - hosts: all
      roles:
         - { role: gavin-romig-koch.insights-magpie }
      tasks:
         - debug: msg="{{ insights_upload_results.reports }}"
    ```
    
  In portal_creds.yml: (where XXXX and YYYYY are replaced with Red Hat Portal credentials)

    ```yaml
    redhat_portal_username: XXXXXX
    redhat_portal_password: YYYYYY
    ```
    
  Then this will collect Insights data from 'myhost.example.com', submit that data to 
  Red Hat Insights saving the results in the fact insights_upload_results, and then print out 
  those results.

    ```bash
    ansible-playbook --limit myhost.example.com --extra-vars @portal_creds.yml magpie_example.yml
    ```
    
License
-------

BSD

Author Information
------------------

The Ansible module and action plugin were written by Gavin Romig-Koch, based largely on the original insights-client by Richard Brantley, Jeremy Crafts, and Dan Varga.
