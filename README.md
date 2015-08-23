# munin-plugins

Custom Munin Node Plugins for cPanel monitoring

There are several Munin Plugins here which were developed in the hardening for a specific server but can easily be adapted to other enviornments

These munin plugins were run on a Hostgator VPS with cPanel 11.50

Some of these monitors were written as basic shell scripts for simplicity, others were written in c for performance


processes/

  processes_oom			Monitors /var/log/messages for OOM kills and distinguishes specific processes of interest

apache/

  apache_vh_accesses		Monitors apache access via domlogs, must replace 'website' with domain, duplicate for additional sites

  apache_qos_logs.c		Single cource c based monitor to scan mod_qos log various block conditions
				See blog post for mod_qos rules it matches: http://nerd.janklier.com/manage-traffic-by-qos
				Copy of current pre_virtualhost_global.conf in this repository as well
				mod_qos was run with a custom log file stored at /usr/local/apache/logs/qsaudit_log
				Custom log file is configured via include post_virtualhost_global.conf and corresponding conf files 
				for each virtual host

  apache_qos_stats.c		Single source c based monitor to track queue length avg/max and request latency avg/max
				Same configuration dependencies as apache_qos_logs.c
	

				Compile single source c based monitors with

				gcc -o apache_qos_logs apache_qos_logs.c
				gcc -o apache_qos_stats apache_qos_stats.c

				The create symbolic links for these monitors in /etc/munin/plugins and configure appropriately

