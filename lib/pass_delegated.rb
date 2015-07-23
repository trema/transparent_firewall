# A sample transparent firewall, see README.md for more information.
class PassDelegated < Trema::Controller
  PORT = {
    outside: 1,
    inside: 2,
    inspect: 3
  }.freeze

  PRIORITY = {
    bypass: 65_000,
    prefix: 64_000,
    inspect: 1000,
    non_ipv4: 900
  }.freeze

  PREFIX_FILES = %w(afrinic apnic arin lacnic ripencc).map do |each|
    File.join __dir__, '..', "aggregated-delegated-#{each}.txt"
  end

  def start(_args)
    @prefixes = PREFIX_FILES.reduce([]) do |result, each|
      data = IO.readlines(each).map(&:chomp)
      logger.info "#{each}: #{data.size} prefix(es)"
      result + data
    end
  end

  def switch_ready(dpid)
    return if @dpid
    @dpid = dpid
    logger.info "#{@dpid.to_hex}: connected"
    start_loading
  end

  def switch_disconnected(dpid)
    return if @dpid != dpid
    logger.info "#{@dpid.to_hex}: disconnected"
    @dpid = nil
  end

  def barrier_reply(dpid, _message)
    return if dpid != @dpid
    finish_loading
  end

  private

  def start_loading
    @loading_started = Time.now
    install_preamble_and_bypass
    install_prefixes
    install_postamble
    send_message @dpid, Barrier::Request.new
  end

  # All flows in place, safe to remove bypass.
  def finish_loading
    send_flow_mod_delete(@dpid,
                         strict: true,
                         priority: PRIORITY[:bypass],
                         match: Match.new(in_port: PORT[:outside]))
    logger.info "#{@dpid.to_hex}: bypass OFF"
    logger.info(format('%s: loading finished in %.2f second(s)',
                       @dpid.to_hex, Time.now - @loading_started))
  end

  def install_preamble_and_bypass
    send_flow_mod_add(@dpid,
                      priority: PRIORITY[:bypass],
                      match: Match.new(in_port: PORT[:inside]),
                      actions: SendOutPort.new(PORT[:outside]))
    send_flow_mod_add(@dpid,
                      priority: PRIORITY[:bypass],
                      match: Match.new(in_port: PORT[:outside]),
                      actions: SendOutPort.new(PORT[:inside]))
  end

  def install_prefixes
    logger.info "#{@dpid.to_hex}: loading started"
    @prefixes.each do |each|
      send_flow_mod_add(
        @dpid,
        priority: PRIORITY[:prefix],
        match: Match.new(in_port: PORT[:outside],
                         ether_type: 0x0800,
                         ip_source_address: IPv4Address.new(each)),
        actions: SendOutPort.new(PORT[:inside]))
    end
  end

  # Deny any other IPv4 and permit non-IPv4 traffic.
  def install_postamble
    send_flow_mod_add(@dpid,
                      priority: PRIORITY[:inspect],
                      match: Match.new(in_port: PORT[:outside],
                                       ether_type: 0x0800),
                      actions: SendOutPort.new(PORT[:inspect]))
    send_flow_mod_add(@dpid,
                      priority: PRIORITY[:non_ipv4],
                      match: Match.new(in_port: PORT[:outside]),
                      actions: SendOutPort.new(PORT[:inside]))
  end
end
