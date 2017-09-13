# audit

This plugin is to be used to track transactions in the Cacti database, when they were made, by what IP address and by what login account.  This can be used to determine the root cause of issues created by users of the Cacti system.

## Purpose

This plugin allows Cacti Administrators to log user change activity

## Features

* Log all $_POST activities to the Cacti Server that can change the contents of the system.
* Captures CLI commands and who ran them
	
## Installation

Install just like any other plugin, just throw it in the plugin directory, and Install and Enabled from the Plugin Management Interface.  Make sure the plugin directory is named 'admin' and not 'plugin_admin'.

Once this is done, you have to goto Configuration -> Settings -> Misc and define data retention	and turn on auditing.
    
## Possible Bugs?
   
If you figure out this problem, see the Cacti forums!

## Future Changes
    
Got any ideas or complaints, please log an issue on GitHub.

## Changelog

--- 1.0 ---
* feature: Added Spanish Translation
* Initial Release

