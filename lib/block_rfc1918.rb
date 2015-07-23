# A sample transparent firewall
class BlockRFC1918 < Trema::Controller
  PORT = {
    outside: 1,
    inside: 2,
    inspect: 3
  }.freeze

  PREFIX = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].map do |each|
    Pio::IPv4Address.new each
  end

  def switch_ready(dpid)
    if @dpid
      logger.info "#{dpid.to_hex}: ignored"
      return
    end
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
    logger.info "#{@dpid.to_hex}: loading finished"
  end

  private

  def start_loading
    PREFIX.each do |each|
      block_prefix_on_port prefix: each, port: :inside, priority: 5000
      block_prefix_on_port prefix: each, port: :outside, priority: 4000
    end
    install_postamble 1500
    send_message @dpid, Barrier::Request.new
  end

  # rubocop:disable MethodLength
  def block_prefix_on_port(prefix:, port:, priority:)
    send_flow_mod_add(
      @dpid,
      priority: priority + 100,
      match: Match.new(in_port: PORT[port],
                       ether_type: 0x0800,
                       source_ip_address: prefix),
      actions: SendOutPort.new(PORT[:inspect]))
    send_flow_mod_add(
      @dpid,
      priority: priority,
      match: Match.new(in_port: PORT[port],
                       ether_type: 0x0800,
                       destination_ip_address: prefix),
      actions: SendOutPort.new(PORT[:inspect]))
  end
  # rubocop:enable MethodLength

  def install_postamble(priority)
    send_flow_mod_add(
      @dpid,
      priority: priority + 100,
      match: Match.new(in_port: PORT[:inside]),
      actions: SendOutPort.new(PORT[:outside]))
    send_flow_mod_add(
      @dpid,
      priority: priority,
      match: Match.new(in_port: PORT[:outside]),
      actions: SendOutPort.new(PORT[:inside]))
  end
end
