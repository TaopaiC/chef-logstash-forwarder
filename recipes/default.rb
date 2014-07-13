include_recipe "runit"

if node["logstash-forwarder"]["ssl_ca_certificate_path"].empty? && !node['logstash-forwarder']['ssl_data_bag_name']
  Chef::Application.fatal!("You must have the CA certificate installed which signed the server's certificate")
end

host_hash = ""
node["logstash-forwarder"]["hosts"].each do |host| 
  host_hash = host_hash + "\"#{host}:#{node["logstash-forwarder"]["port"]}\","
end
host_hash = host_hash[0...-1]

file_list = "  \"files\": ["
node["logstash-forwarder"]["files"].each do |type, files| 
  if !files.empty?
    file_list = file_list + "\n    {\n"
    file_list = file_list + "      \"paths\": #{files},\n"
    file_list = file_list + "      \"fields\": { \"type\": \"#{type}\" }\n"
    file_list = file_list + "    },"
  end
end
file_list = file_list[0...-1]
file_list = file_list + "\n  ]"

group node["logstash-forwarder"]["group"] do
  system true
end

user node["logstash-forwarder"]["user"] do
  system true
  group node["logstash-forwarder"]["group"]
end

case node["platform_family"]
when "debian"
  cookbook_file "#{Chef::Config[:file_cache_path]}/logstash-forwarder_amd64.deb" do
    source "logstash-forwarder_#{node["logstash-forwarder"]["version"]}_amd64.deb"
  end

  package "logstash-forwarder" do
    source "#{Chef::Config[:file_cache_path]}/logstash-forwarder_amd64.deb"
    provider Chef::Provider::Package::Dpkg
    action :install
  end
when "rhel"
  cookbook_file "#{Chef::Config[:file_cache_path]}/logstash-forwarder_x86_64.rpm" do
    source "logstash-forwarder-#{node["logstash-forwarder"]["version"]}.x86_64.rpm"
  end

  package "logstash-forwarder" do
    source "#{Chef::Config[:file_cache_path]}/logstash-forwarder_x86_64.rpm"
    provider Chef::Provider::Package::Rpm
    action :install
  end
end

if node['logstash-forwarder']['ssl_data_bag_name']
  directory "#{node["logstash-forwarder"]["dir"]}/ssl" do
    mode "0750"
    owner node["logstash-forwarder"]["user"]
    group node["logstash-forwarder"]["group"]
    recursive true
  end

  file "#{node['logstash-forwarder']['dir']}/ssl/ssl-cert-logstash-forwarder.crt" do
    owner node['logstash-forwarder']['user']
    group node['logstash-forwarder']['group']
    content data_bag_item('logstash-forwarder', node['logstash-forwarder']['ssl_data_bag_name'])['ssl_certificate']
    action :create
  end.run_action(:create)

  file "#{node['logstash-forwarder']['dir']}/ssl/ssl-cert-logstash-forwarder.key" do
    owner node['logstash-forwarder']['user']
    group node['logstash-forwarder']['group']
    content data_bag_item('logstash-forwarder', node['logstash-forwarder']['ssl_data_bag_name'])['ssl_key']
    action :create
  end

  ruby_block "ssl-certificate-setup" do
    block do
      node.set["logstash-forwarder"]["ssl_key_path"]                  = "#{node["logstash-forwarder"]["dir"]}/ssl/ssl-cert-logstash-forwarder.key"
      node.set["logstash-forwarder"]["ssl_certificate_path"]          = "#{node["logstash-forwarder"]["dir"]}/ssl/ssl-cert-logstash-forwarder.crt"
      node.set["logstash-forwarder"]["ssl_ca_certificate_path"]       = "#{node["logstash-forwarder"]["dir"]}/ssl/ssl-cert-logstash-forwarder.crt"
    end
    action :nothing
  end.run_action(:create)
end

directory node["logstash-forwarder"]["log_dir"] do
  mode "0755"
  owner node["logstash-forwarder"]["user"]
  group node["logstash-forwarder"]["group"]
  recursive true
end

template node["logstash-forwarder"]["config_file"] do
  mode "0644"
  source "logstash-forwarder.settings.conf.erb"
  variables(
    :hosts               => host_hash,
    :files               => file_list,
    :timeout             => node["logstash-forwarder"]["timeout"],
    :ssl_certificate     => node["logstash-forwarder"]["ssl_certificate_path"],
    :ssl_ca_certificate  => node["logstash-forwarder"]["ssl_ca_certificate_path"],
    :ssl_key             => node["logstash-forwarder"]["ssl_key_path"],
    :files_to_watch      => node["logstash-forwarder"]["files_to_watch"]
  )
  notifies :restart, "service[logstash-forwarder]"
end

runit_service 'logstash-forwarder' do
  owner node["logstash-forwarder"]["user"]
  group node["logstash-forwarder"]["group"]
  options(
    :dir              => node["logstash-forwarder"]["dir"],
    :config_file      => node["logstash-forwarder"]["config_file"]
  )
end

service "logstash-forwarder" do
  action :start
end
