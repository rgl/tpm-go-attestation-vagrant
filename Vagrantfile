# to make sure the nodes are created in order, we
# have to force a --no-parallel execution.
ENV['VAGRANT_NO_PARALLEL'] = 'yes'

require 'ipaddr'

CONFIG_SERVER_IP_ADDRESS       = '10.11.0.101'
CONFIG_FIRST_CLIENT_IP_ADDRESS = '10.11.0.201'
CONFIG_CLIENTS = [
  'ubuntu',
  'windows',
].map.with_index do |os, n|
  ip_address = IPAddr.new((IPAddr.new CONFIG_FIRST_CLIENT_IP_ADDRESS).to_i + n, Socket::AF_INET).to_s
  [os, ip_address]
end

Vagrant.configure('2') do |config|
  config.vm.provider :libvirt do |lv, config|
    lv.memory = 1024
    lv.cpus = 2
    lv.cpu_mode = 'host-passthrough'
    lv.nested = false
    lv.keymap = 'pt'
    config.vm.synced_folder '.', '/vagrant', type: 'nfs'
  end

  config.vm.define 'server' do |config|
    config.vm.box = 'ubuntu-20.04-uefi-amd64'
    config.vm.hostname = 'server.example.test'
    config.vm.network :private_network, ip: CONFIG_SERVER_IP_ADDRESS, libvirt__forward_mode: 'none', libvirt__dhcp_enabled: false
    config.vm.provision :hosts, :sync_hosts => true, :add_localhost_hostnames => false
    config.vm.provision :file, source: '/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem', destination: '~/swtpm-localca-rootca-cert.pem'
    config.vm.provision :file, source: '/var/lib/swtpm-localca/issuercert.pem', destination: '~/swtpm-localca-cert.pem'
    config.vm.provision :shell, path: 'provision-base.sh'
    config.vm.provision :shell, path: 'provision-docker.sh'
    config.vm.provision :shell, path: 'provision-server.sh'
    config.vm.provision :shell, inline: "cd /vagrant/server && ./run.sh '#{CONFIG_SERVER_IP_ADDRESS}' '#{CONFIG_CLIENTS.map{|(_, ip_address)|"http://#{ip_address}:9000"}.join(',')}'"
  end

  CONFIG_CLIENTS.each_with_index do |(os, ip_address), n|
    name = "client#{n}"
    fqdn = "#{name}.example.test"
    case os
    when 'ubuntu'
      config.vm.define name do |config|
        config.vm.box = 'ubuntu-20.04-uefi-amd64'
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
        config.vm.provision :shell, inline: "cd /vagrant/client && ./run.sh '#{CONFIG_SERVER_IP_ADDRESS}' '#{ip_address}'"
      end
    when 'windows'
      config.vm.define name do |config|
        config.vm.box = 'windows-2022-uefi-amd64'
        config.vm.provider :libvirt do |lv, config|
          lv.memory = 2*1024
          lv.tpm_model = 'tpm-crb'
          lv.tpm_type = 'emulator'
          lv.tpm_version = '2.0'
          config.vm.synced_folder '.', '/vagrant', type: 'smb', smb_username: ENV['USER'], smb_password: ENV['VAGRANT_SMB_PASSWORD']
        end
        config.vm.hostname = name
        config.vm.network :private_network, ip: ip_address, libvirt__forward_mode: 'none', libvirt__dhcp_enabled: false
        config.vm.provision :hosts, :sync_hosts => true, :add_localhost_hostnames => false
        config.vm.provision :file, source: '/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem', destination: '~/swtpm-localca-rootca-cert.pem'
        config.vm.provision :file, source: '/var/lib/swtpm-localca/issuercert.pem', destination: '~/swtpm-localca-cert.pem'
        config.vm.provision :shell, path: 'windows/ps.ps1', args: 'provision-chocolatey.ps1'
        config.vm.provision :shell, path: 'windows/ps.ps1', args: 'provision-base.ps1'
        config.vm.provision :shell, path: 'windows/ps.ps1', args: 'provision-client.ps1'
        config.vm.provision :shell, path: 'windows/ps.ps1', args: ['../client/run.ps1', CONFIG_SERVER_IP_ADDRESS, ip_address]
      end
    else
      raise "unknown client os #{os}"
    end
  end
end
