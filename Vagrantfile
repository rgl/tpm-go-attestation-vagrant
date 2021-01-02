# to make sure the nodes are created in order, we
# have to force a --no-parallel execution.
ENV['VAGRANT_NO_PARALLEL'] = 'yes'

require 'ipaddr'

number_of_client_nodes  = 2
first_server_node_ip    = '10.11.0.101'
first_client_node_ip    = '10.11.0.201'

server_node_ip_address  = IPAddr.new first_server_node_ip
client_node_ip_address  = IPAddr.new first_client_node_ip
client_base_addresses   = (0...number_of_client_nodes).map do |n|
  "http://#{IPAddr.new(client_node_ip_address.to_i+n, client_node_ip_address.family)}:9000"
end

Vagrant.configure('2') do |config|
  config.vm.box = 'ubuntu-20.04-uefi-amd64'

  config.vm.provider :libvirt do |lv, config|
    lv.memory = 1024
    lv.cpus = 2
    lv.cpu_mode = 'host-passthrough'
    lv.nested = false
    lv.keymap = 'pt'
    config.vm.synced_folder '.', '/vagrant', type: 'nfs'
  end

  config.vm.define 'server' do |config|
    config.vm.hostname = 'server.example.test'
    config.vm.network :private_network, ip: server_node_ip_address.to_s, libvirt__forward_mode: 'none', libvirt__dhcp_enabled: false
    config.vm.provision :hosts, :sync_hosts => true, :add_localhost_hostnames => false
    config.vm.provision :file, source: '/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem', destination: '~/swtpm-localca-rootca-cert.pem'
    config.vm.provision :file, source: '/var/lib/swtpm-localca/issuercert.pem', destination: '~/swtpm-localca-cert.pem'
    config.vm.provision :shell, path: 'provision-base.sh'
    config.vm.provision :shell, path: 'provision-docker.sh'
    config.vm.provision :shell, path: 'provision-server.sh'
    config.vm.provision :shell, inline: "cd /vagrant/server && ./run.sh '#{server_node_ip_address}' '#{client_base_addresses.join(',')}'"
  end

  (1..number_of_client_nodes).each do |n|
    name = "client#{n}"
    fqdn = "#{name}.example.test"
    ip_address = client_node_ip_address.to_s; client_node_ip_address = client_node_ip_address.succ
    config.vm.define name do |config|
      config.vm.provider :libvirt do |lv, config|
        lv.tpm_model = 'tpm-crb'
        lv.tpm_type = 'emulator'
        lv.tpm_version = '2.0'
      end
      config.vm.hostname = fqdn
      config.vm.network :private_network, ip: ip_address, libvirt__forward_mode: 'none', libvirt__dhcp_enabled: false
      config.vm.provision :hosts, :sync_hosts => true, :add_localhost_hostnames => false
      config.vm.provision :file, source: '/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem', destination: '~/swtpm-localca-rootca-cert.pem'
      config.vm.provision :file, source: '/var/lib/swtpm-localca/issuercert.pem', destination: '~/swtpm-localca-cert.pem'
      config.vm.provision :shell, path: 'provision-base.sh'
      config.vm.provision :shell, path: 'provision-docker.sh'
      config.vm.provision :shell, path: 'provision-client.sh'
      config.vm.provision :shell, inline: "cd /vagrant/client && ./run.sh '#{server_node_ip_address}' '#{ip_address}'"
    end
  end
end
