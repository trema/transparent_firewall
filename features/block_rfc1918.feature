Feature: Block RFC1918 packets
  Background:
    Given I set the environment variables to:
      | variable         | value |
      | TREMA_LOG_DIR    | .     |
      | TREMA_PID_DIR    | .     |
      | TREMA_SOCKET_DIR | .     |

  @sudo
  Scenario: block_rfc1918.rb blocks packets with private source/destination address
    Given a file named "transparent_firewall.conf" with:
      """
      vswitch('firewall') { datapath_id '0xabc' }

      vhost('host1') { ip '192.168.0.1' }
      vhost('host2') { ip '192.168.0.2' }

      link 'firewall', 'host1'
      link 'firewall', 'host2'
      """
    And I successfully run `trema run ../../lib/block_rfc1918.rb -c transparent_firewall.conf -d`
    And I run `sleep 8`
    When I run `trema send_packets --source host1 --dest host2`
    And I run `trema show_stats host2`
    Then the output should not contain "Packets received"

  @sudo
  Scenario: block_rfc1918.rb does not block packets with global source/destination address
    Given a file named "transparent_firewall.conf" with:
      """
      vswitch('firewall') { datapath_id '0xabc' }

      vhost('host1') { ip '1.1.1.1' }
      vhost('host2') { ip '2.2.2.2' }

      link 'firewall', 'host1'
      link 'firewall', 'host2'
      """
    And I run `trema run ../../lib/block_rfc1918.rb -c transparent_firewall.conf -d`
    And I run `sleep 8`
    When I run `trema send_packets --source host1 --dest host2`
    And I run `trema show_stats host2`
    Then the output should contain "Packets received"
