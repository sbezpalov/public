Passive monitoring of Proxmox Mail Gateway 8.1.

Add the following to /etc/zabbix/zabbix_agentd.conf:

```
 UserParameter=mail.queuesize,/usr/sbin/postqueue -p | tail -n 1 | awk '{ if ($5 == "") print "0"; else print $5; }'
 UserParameter=postfix.status,systemctl is-active postfix | grep -q "active" && echo 1 || echo 0
 UserParameter=pmg.cpu.usage,top -b -n 1 | grep "Cpu(s)" | awk '{print $2 + $4}'
 UserParameter=pmg.mem.usage,free | grep Mem | awk '{print $3/$2 * 100.0}'
 UserParameter=pmg.disk.usage,df / | tail -1 | awk '{print $5}' | sed 's/%//'
```
