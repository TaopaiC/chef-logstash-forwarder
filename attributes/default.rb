default["logstash-forwarder"]["version"]                    = "0.3.1"
default["logstash-forwarder"]["user"]                       = "logstash-forwarder"
default["logstash-forwarder"]["group"]                      = "logstash-forwarder"
default["logstash-forwarder"]["dir"]                        = "/opt/logstash-forwarder"
default["logstash-forwarder"]["log_dir"]                    = "#{node["logstash-forwarder"]["dir"]}/log"
default["logstash-forwarder"]["hosts"]                       = nil
default["logstash-forwarder"]["port"]                       = "6060"
default["logstash-forwarder"]["timeout"]                    = "15"
default["logstash-forwarder"]["ssl_certificate_path"]       = ""
default["logstash-forwarder"]["ssl_key_path"]               = ""
default["logstash-forwarder"]["ssl_ca_certificate_path"]    = ""
# default["logstash-forwarder"]["files"]                      = { "syslog" => [ '/var/log/syslog' ]}
default["logstash-forwarder"]["files"]                      = nil
default["logstash-forwarder"]["logstash_role"]              = "logstash"
default["logstash-forwarder"]["logstash_fqdn"]              = ""
default["logstash-forwarder"]["config_file"]                = "#{node["logstash-forwarder"]["dir"]}/logstash-forwarder.conf"
