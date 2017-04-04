insights-magpie
===============

What if we could use Ansible modules to collect data for Red Hat Insights?

This role contains an module and an action plugin pair that work together to collect Insights data from a system,
submit that data to Red Hat Insights, and present the results as Ansible facts that can be used and displayed by
later tasks in the playbook.   

The module runs on the target machines collecting the data that Insights needs to do its analysis, returning
that data to the control machine as Ansible facts.

The action plugin runs on the control machine.  It captures the facts returned by the module, submits them to
the Red Hat Insights service for analysis, and then presents that analysis back to the running playbook as 
another Ansible fact.

If you know what Insights is, and would like to try out this role, but need some help with Ansible, [try here](https://github.com/gavin-romig-koch/insights-magpie/wiki/Just-Enough-about-Ansible-to-Use-insights-magpie).

Requirements
------------

The Ansible controll machine must have 'tar' installed.   

The target machines must already be registered with the Red Hat Insights service.  Currently the easiest 
(perhaps only) way to do this is to install the Insights Collector (redhat-access-insights/insights-client)
on the target machine(s) and register those machines.  Target machines that are already registered with
Red Hat Insights do not need to be re-registered.  The magpie module collects up the Insights system/machine
id stored on the machine when it is registered, and then the insights action plugin uses that system/machine id
when submitting the collected data to the Insights service.  No part of this Ansible role makes any use of the
Insights Collector program itself.  In theory one could uninstall the Insights Collector, but (I think) RPM
renames the needed system/machine id file.  This requirement will be removed as quickly as possible.

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

  In insights-magpie-example.yml:

    - hosts: all
      roles:
         - { role: gavin-romig-koch.insights-magpie }
      tasks:
         - debug: msg="{{ insights_upload_results.reports }}"
    
    
  In redhat-portal-creds.yml: (where XXXX and YYYYY are replaced with Red Hat Portal credentials)

    redhat_portal_username: XXXXXX
    redhat_portal_password: YYYYYY
    
  Then this will collect Insights data from 'myhost.example.com', submit that data to 
  Red Hat Insights saving the results in the fact insights_upload_results, and then print out 
  those results.

    ansible-playbook --limit myhost.example.com --extra-vars @redhat-portal-creds.yml insights-magpie-example.yml
 
    
License
-------

BSD

Author Information
------------------

The Ansible module and action plugin were written by Gavin Romig-Koch, based largely on the original redhat-access-insights/insights-client by Richard Brantley, Jeremy Crafts, and Dan Varga.
