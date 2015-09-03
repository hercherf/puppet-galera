# == Class: galera::firewall
#
# === Parameters
#
# [*source*]
# (optional) The firewall source addresses to unblock
# Defaults to undef
#
class galera::firewall (
  $source = undef,
) {

  $galera_ports = [$galera::mysql_port, $galera::wsrep_group_comm_port, $galera::wsrep_state_transfer_port, $galera::wsrep_inc_state_transfer_port]
  if $source {
    $source.each |$ip| {
      firewall { "4567 galera accept tcp from ${ip}":
        before => Anchor['mysql::server::start'],
        proto  => 'tcp',
        port   => $galera_ports,
        action => accept,
        source => $ip,
      }
      firewall { "4567 galera accept udp from ${ip}":
        before => Anchor['mysql::server::start'],
        proto  => 'udp',
        port   =>  $galera::wsrep_group_comm_port,
        action => accept,
        source => $ip,
      }
    }
  }
  else {
    firewall { '4567 galera accept tcp':
      before => Anchor['mysql::server::start'],
      proto  => 'tcp',
      port   => $galera_ports,
      action => accept,
      source => $source,
    }
    firewall { "4567 galera accept udp from ${ip}":
      before => Anchor['mysql::server::start'],
      proto  => 'udp',
      port   =>  $galera::wsrep_group_comm_port,
      action => accept,
      source => $ip,
    }
  }
}
